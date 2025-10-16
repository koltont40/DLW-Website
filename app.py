import base64
import binascii
import errno
import json
import mimetypes
import os
import re
import secrets
import shutil
import smtplib
import ssl
import string
import subprocess
import threading
import time
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from email.utils import formataddr, format_datetime, make_msgid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote_plus, urljoin

import requests

try:  # pragma: no cover - import guard for optional dependency
    import stripe
except ImportError:  # pragma: no cover - stripe is required in production
    stripe = None
    StripeError = Exception
    SignatureVerificationError = Exception
else:  # pragma: no cover - executed when stripe is installed
    StripeError = stripe.error.StripeError
    SignatureVerificationError = stripe.error.SignatureVerificationError

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
    current_app,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import BaseWSGIServer, make_server
from werkzeug.utils import secure_filename

from sqlalchemy import event, inspect, or_, text
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError, NoSuchTableError

load_dotenv()

db = SQLAlchemy()

_billing_schema_checked = False
_stripe_schema_checked = False

STRIPE_DEFAULT_CURRENCY = "usd"
STRIPE_AUTOPAY_METADATA_FLAG = "autopay"

SITE_SHELL_CACHE_KEY = "_site_shell_cache"
SITE_SHELL_CACHE_SECONDS_DEFAULT = 15.0
DASHBOARD_OVERVIEW_CACHE_KEY = "_dashboard_overview_cache"
DASHBOARD_OVERVIEW_CACHE_SECONDS_DEFAULT = 10.0

FILE_TRANSFER_SURFACES: dict[str, str] = {
    "acme-challenge": "Let's Encrypt HTTP challenge files",
    "signup-verification": "Customer signup verification uploads",
    "client-verification": "Customer verification documents",
    "support-ticket-attachments": "Support ticket photo attachments",
    "install-photo": "Technician installation photos",
    "install-signature": "Technician install acknowledgements",
    "legal-documents": "Published legal policy documents",
    "branding-assets": "Branding asset uploads",
    "theme-background": "Site background images",
    "team-member-photo": "Team member profile photos",
    "trusted-business-logo": "Trusted business logos",
    "support-partner-logo": "Operations partner logos",
}


def _allowed_file_surfaces() -> set[str]:
    allowed = current_app.config.get("ALLOWED_FILE_TRANSFER_SURFACES")
    if allowed is None:
        allowed = set(FILE_TRANSFER_SURFACES.keys())
        current_app.config["ALLOWED_FILE_TRANSFER_SURFACES"] = allowed
    return allowed


def ensure_file_surface_enabled(surface: str) -> None:
    if surface not in _allowed_file_surfaces():
        current_app.logger.warning(
            "Blocked file transfer for disabled surface '%s' on %s %s",
            surface,
            request.method,
            request.path,
        )
        abort(403)


def send_site_file(
    surface: str,
    directory: str | Path,
    filename: str,
    **send_kwargs,
):
    ensure_file_surface_enabled(surface)
    return send_from_directory(str(directory), filename, **send_kwargs)


def utcnow() -> datetime:
    return datetime.now(UTC)


def slugify_segment(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def generate_portal_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def generate_account_reference() -> str:
    return f"DLW-{secrets.token_hex(3).upper()}"


def generate_unique_slug(title: str, existing_id: int | None = None) -> str:
    base_slug = secure_filename(title.lower()).strip("-")
    if not base_slug:
        base_slug = f"post-{secrets.token_hex(4)}"

    slug = base_slug
    suffix = 2

    while True:
        query = BlogPost.query.filter_by(slug=slug)
        if existing_id is not None:
            query = query.filter(BlogPost.id != existing_id)

        if query.first() is None:
            return slug

        slug = f"{base_slug}-{suffix}"
        suffix += 1


def stripe_active(app: Flask | None = None) -> bool:
    app = app or current_app
    if app is None or stripe is None:
        return False
    return bool(app.config.get("STRIPE_SECRET_KEY"))


class UispApiError(RuntimeError):
    """Raised when the UISP API responds with an error."""


class UispApiClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = 10.0):
        self.base_url = (base_url or "").rstrip("/")
        self.token = (token or "").strip()
        self.timeout = timeout

        if not self.base_url or not self.token:
            raise UispApiError("UISP API base URL and token are required.")

    def fetch_devices(self) -> list[dict]:
        endpoint = f"{self.base_url}/nms/api/v2.1/devices"
        headers = {
            "accept": "application/json",
            "x-auth-token": self.token,
        }

        devices: list[dict] = []
        page = 1
        per_page = 200
        next_url: str | None = endpoint
        params: dict[str, object] | None = {"page": page, "perPage": per_page}

        while next_url:
            response = requests.get(
                next_url,
                headers=headers,
                params=params if params else None,
                timeout=self.timeout,
            )
            if response.status_code != 200:
                raise UispApiError(
                    f"UISP API responded with HTTP {response.status_code}: {response.text}"
                )

            try:
                payload = response.json()
            except ValueError as exc:  # pragma: no cover - defensive guard
                raise UispApiError("UISP API returned an invalid JSON payload.") from exc

            chunk: list[dict]
            pagination: dict[str, object] | None = None
            next_link: str | None = None

            if isinstance(payload, list):
                chunk = payload
                pagination = None
                next_link = None
            elif isinstance(payload, dict):
                data_field: list[dict] | None = None
                for key in ("items", "data", "devices"):
                    value = payload.get(key)
                    if isinstance(value, list):
                        data_field = value
                        break
                if data_field is None:
                    raise UispApiError("Unexpected UISP API response structure.")
                chunk = data_field

                links = payload.get("_links") or payload.get("links") or {}
                if isinstance(links, dict):
                    next_candidate = links.get("next")
                    if isinstance(next_candidate, dict):
                        next_link = next_candidate.get("href") or next_candidate.get("url")
                    elif isinstance(next_candidate, list):
                        next_link = None
                        for entry in next_candidate:
                            if isinstance(entry, dict):
                                next_link = entry.get("href") or entry.get("url")
                                if next_link:
                                    break
                            elif isinstance(entry, str) and entry:
                                next_link = entry
                                break
                    elif isinstance(next_candidate, str) and next_candidate:
                        next_link = next_candidate

                pagination = payload.get("pagination")
                if not isinstance(pagination, dict):
                    meta = payload.get("meta")
                    if isinstance(meta, dict):
                        pagination_meta = meta.get("pagination")
                        if isinstance(pagination_meta, dict):
                            pagination = pagination_meta
            else:
                raise UispApiError("Unexpected UISP API response structure.")

            devices.extend(chunk)

            next_url = None
            params = None

            if next_link:
                next_url = urljoin(self.base_url + "/", next_link)
            elif pagination:
                current_page = _coerce_int(pagination.get("page") or pagination.get("current"))
                total_pages = _coerce_int(
                    pagination.get("totalPages")
                    or pagination.get("total_pages")
                    or pagination.get("pages")
                )
                per_page_value = _coerce_int(
                    pagination.get("perPage")
                    or pagination.get("per_page")
                    or pagination.get("limit")
                )
                if per_page_value:
                    per_page = per_page_value
                if total_pages and current_page and current_page < total_pages:
                    page = current_page + 1
                    next_url = endpoint
                    params = {"page": page, "perPage": per_page}

        return devices

def _coerce_int(value: object | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value:  # NaN check
            return None
        return int(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return int(cleaned)
        except ValueError:
            try:
                return int(float(cleaned))
            except (TypeError, ValueError):
                return None
    return None


def parse_uisp_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        timestamp = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def init_stripe(app: Flask) -> None:
    if stripe is None:
        return

    secret_key = app.config.get("STRIPE_SECRET_KEY")
    if secret_key:
        stripe.api_key = secret_key
        stripe.default_http_client = stripe.http_client.RequestsClient()
    else:
        try:
            stripe.api_key = None
        except AttributeError:
            pass


def normalize_phone_number(raw: str | None) -> tuple[str | None, str | None]:
    digits = "".join(ch for ch in (raw or "") if ch.isdigit())
    if not digits:
        return None, None

    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]

    display = raw.strip() if raw else digits
    if len(digits) == 10:
        display = f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
    elif len(digits) == 7:
        display = f"{digits[:3]}-{digits[3:]}"

    href = f"tel:+1{digits}" if len(digits) >= 10 else f"tel:{digits}"
    return display, href


def normalize_hex_color(value: str) -> str:
    cleaned = (value or "").strip().lstrip("#")
    if len(cleaned) == 3:
        cleaned = "".join(ch * 2 for ch in cleaned)
    if len(cleaned) != 6 or not all(ch in string.hexdigits for ch in cleaned):
        raise ValueError("Invalid hex color")
    return f"#{cleaned.lower()}"


def derive_theme_palette(background_hex: str) -> tuple[str, str]:
    background = normalize_hex_color(background_hex)
    r = int(background[1:3], 16)
    g = int(background[3:5], 16)
    b = int(background[5:7], 16)

    brightness = (r * 299 + g * 587 + b * 114) / 1000
    if brightness >= 150:
        return "#111827", "#475569"
    return "#f5f3ff", "#b5a6d8"


def allowed_install_file(filename: str) -> bool:
    if not filename:
        return False
    return Path(filename).suffix.lower() in ALLOWED_INSTALL_EXTENSIONS


def allowed_verification_file(filename: str) -> bool:
    if not filename:
        return False
    return Path(filename).suffix.lower() in ALLOWED_VERIFICATION_EXTENSIONS


def allowed_ticket_attachment(filename: str) -> bool:
    if not filename:
        return False
    return Path(filename).suffix.lower() in ALLOWED_TICKET_ATTACHMENT_EXTENSIONS


def get_install_photo_requirements() -> list["InstallPhotoRequirement"]:
    return (
        InstallPhotoRequirement.query.order_by(
            InstallPhotoRequirement.position.asc(),
            InstallPhotoRequirement.id.asc(),
        ).all()
    )


def get_required_install_photo_categories() -> list[str]:
    requirements = get_install_photo_requirements()
    return [requirement.label for requirement in requirements]


def get_install_photo_category_choices() -> list[str]:
    categories = list(get_required_install_photo_categories())
    if OPTIONAL_INSTALL_PHOTO_CATEGORY not in categories:
        categories.append(OPTIONAL_INSTALL_PHOTO_CATEGORY)
    return categories


def resequence_install_photo_requirements(
    ordered_requirements: list["InstallPhotoRequirement"],
) -> None:
    for index, requirement in enumerate(ordered_requirements):
        requirement.position = index


def delete_client_verification_photo(app: Flask, client: "Client") -> None:
    if not client.verification_photo_filename:
        return

    base_folder = Path(app.config["CLIENT_VERIFICATION_FOLDER"])
    file_path = base_folder / client.verification_photo_filename
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass


def store_client_verification_photo(app: Flask, client: "Client", file) -> None:
    delete_client_verification_photo(app, client)

    verification_folder = (
        Path(app.config["CLIENT_VERIFICATION_FOLDER"]) / f"client_{client.id}"
    )
    verification_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    safe_name = secure_filename(file.filename)
    stored_filename = f"{timestamp}_{safe_name}" if safe_name else f"{timestamp}.bin"
    relative_path = Path(f"client_{client.id}") / stored_filename
    file.save(verification_folder / stored_filename)

    client.verification_photo_filename = str(relative_path)
    client.verification_photo_uploaded_at = utcnow()


def store_ticket_attachment(app: Flask, ticket: "SupportTicket", file) -> "SupportTicketAttachment":
    attachments_folder = (
        Path(app.config["SUPPORT_TICKET_ATTACHMENT_FOLDER"]) / f"ticket_{ticket.id}"
    )
    attachments_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    safe_name = secure_filename(file.filename)
    stored_filename = f"{timestamp}_{safe_name}" if safe_name else f"{timestamp}.bin"
    relative_path = Path(f"ticket_{ticket.id}") / stored_filename
    file.save(attachments_folder / stored_filename)

    attachment = SupportTicketAttachment(
        ticket_id=ticket.id,
        original_filename=file.filename or stored_filename,
        stored_filename=str(relative_path),
    )
    db.session.add(attachment)
    return attachment


def delete_ticket_attachment_files(app: Flask, ticket: "SupportTicket") -> None:
    base_folder = Path(app.config["SUPPORT_TICKET_ATTACHMENT_FOLDER"])
    for attachment in ticket.attachments:
        file_path = base_folder / attachment.stored_filename
        try:
            if file_path.exists():
                file_path.unlink()
        except OSError:
            pass

    ticket_folder = base_folder / f"ticket_{ticket.id}"
    try:
        if ticket_folder.exists() and not any(ticket_folder.iterdir()):
            ticket_folder.rmdir()
    except OSError:
        pass


SIGNATURE_DATA_PREFIX = "data:image/png;base64,"


def store_install_signature_image(
    app: Flask, acknowledgement: "InstallAcknowledgement", data_url: str
) -> None:
    if not data_url or not data_url.startswith(SIGNATURE_DATA_PREFIX):
        raise ValueError("Signature must be provided as a base64-encoded PNG data URL.")

    encoded = data_url.split(",", 1)[1]
    try:
        binary = base64.b64decode(encoded)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - sanity
        raise ValueError("Unable to decode signature image.") from exc

    signature_folder = (
        Path(app.config["INSTALL_SIGNATURE_FOLDER"]) / f"client_{acknowledgement.client_id}"
    )
    signature_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"{timestamp}_{secrets.token_hex(4)}.png"
    relative_path = Path(f"client_{acknowledgement.client_id}") / filename
    (signature_folder / filename).write_bytes(binary)

    acknowledgement.signature_filename = str(relative_path)


def delete_install_signature_image(app: Flask, acknowledgement: "InstallAcknowledgement") -> None:
    if not acknowledgement.signature_filename:
        return
    signature_folder = Path(app.config["INSTALL_SIGNATURE_FOLDER"])
    file_path = signature_folder / acknowledgement.signature_filename
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass


def normalize_card_number(card_number: str) -> str:
    return re.sub(r"[^0-9]", "", card_number or "")


def store_team_member_photo(app: Flask, member: "TeamMember", file) -> None:
    if not file or not file.filename:
        return

    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_TEAM_PHOTO_EXTENSIONS:
        allowed = ", ".join(sorted(ext.lstrip(".") for ext in ALLOWED_TEAM_PHOTO_EXTENSIONS))
        raise ValueError(f"Team member photos must be one of: {allowed}.")

    upload_folder = Path(app.config["TEAM_UPLOAD_FOLDER"])
    upload_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    stored_filename = f"member_{member.id}_{timestamp}{extension}"
    file_path = upload_folder / stored_filename
    file.save(file_path)

    if member.photo_filename:
        previous_path = upload_folder / member.photo_filename
        try:
            if previous_path.exists():
                previous_path.unlink()
        except OSError:
            pass

    member.photo_filename = stored_filename
    member.photo_original = file.filename or stored_filename
    member.updated_at = utcnow()


def delete_team_member_photo(app: Flask, member: "TeamMember") -> None:
    if not member.photo_filename:
        return

    upload_folder = Path(app.config["TEAM_UPLOAD_FOLDER"])
    file_path = upload_folder / member.photo_filename
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass

    member.photo_filename = None
    member.photo_original = None
    member.updated_at = utcnow()


def store_trusted_business_logo(app: Flask, business: "TrustedBusiness", file) -> None:
    if not file or not file.filename:
        return

    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_TRUSTED_LOGO_EXTENSIONS:
        allowed = ", ".join(sorted(ext.lstrip(".") for ext in ALLOWED_TRUSTED_LOGO_EXTENSIONS))
        raise ValueError(f"Trusted business logos must be one of: {allowed}.")

    upload_folder = Path(app.config["TRUSTED_BUSINESS_UPLOAD_FOLDER"])
    upload_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    stored_filename = f"business_{business.id}_{timestamp}{extension}"
    file_path = upload_folder / stored_filename
    file.save(file_path)

    if business.logo_filename:
        previous_path = upload_folder / business.logo_filename
        try:
            if previous_path.exists():
                previous_path.unlink()
        except OSError:
            pass

    business.logo_filename = stored_filename
    business.logo_original = file.filename or stored_filename
    business.updated_at = utcnow()


def delete_trusted_business_logo(app: Flask, business: "TrustedBusiness") -> None:
    if not business.logo_filename:
        return

    upload_folder = Path(app.config["TRUSTED_BUSINESS_UPLOAD_FOLDER"])
    file_path = upload_folder / business.logo_filename
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass

    business.logo_filename = None
    business.logo_original = None
    business.updated_at = utcnow()


def store_support_partner_logo(app: Flask, partner: "SupportPartner", file) -> None:
    if not file or not file.filename:
        return

    extension = Path(file.filename).suffix.lower()
    if extension not in ALLOWED_SUPPORT_PARTNER_LOGO_EXTENSIONS:
        allowed = ", ".join(
            sorted(ext.lstrip(".") for ext in ALLOWED_SUPPORT_PARTNER_LOGO_EXTENSIONS)
        )
        raise ValueError(f"Support partner logos must be one of: {allowed}.")

    upload_folder = Path(app.config["SUPPORT_PARTNER_UPLOAD_FOLDER"])
    upload_folder.mkdir(parents=True, exist_ok=True)

    timestamp = utcnow().strftime("%Y%m%d%H%M%S")
    stored_filename = f"partner_{partner.id}_{timestamp}{extension}"
    file_path = upload_folder / stored_filename
    file.save(file_path)

    if partner.logo_filename:
        previous_path = upload_folder / partner.logo_filename
        try:
            if previous_path.exists():
                previous_path.unlink()
        except OSError:
            pass

    partner.logo_filename = stored_filename
    partner.logo_original = file.filename or stored_filename
    partner.updated_at = utcnow()


def delete_support_partner_logo(app: Flask, partner: "SupportPartner") -> None:
    if not partner.logo_filename:
        return

    upload_folder = Path(app.config["SUPPORT_PARTNER_UPLOAD_FOLDER"])
    file_path = upload_folder / partner.logo_filename
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass

    partner.logo_filename = None
    partner.logo_original = None
    partner.updated_at = utcnow()


def recalculate_client_billing_state(client: "Client") -> None:
    ensure_billing_schema_once()

    outstanding = [
        invoice
        for invoice in client.invoices
        if invoice.status not in {"Paid", "Cancelled", "Refunded"}
    ]
    today = date.today()
    has_overdue = any(
        invoice.status == "Overdue"
        or (invoice.due_date is not None and invoice.due_date < today)
        for invoice in outstanding
    )
    failed_autopay = any(
        invoice.autopay_status
        and invoice.autopay_status not in {"Paid", "Manual", "Processing", "Refunded"}
        for invoice in outstanding
    )

    if has_overdue or failed_autopay:
        client.billing_status = "Delinquent"
        client.service_suspended = True
        if has_overdue:
            client.suspension_reason = "Billing hold: overdue balance"
        else:
            client.suspension_reason = "Billing hold: autopay method required"
    elif outstanding:
        client.billing_status = "Pending"
        client.service_suspended = False
        client.suspension_reason = None
    else:
        client.billing_status = "Good Standing"
        client.service_suspended = False
        client.suspension_reason = None

    client.billing_status_updated_at = utcnow()


def record_autopay_event(
    *,
    client: "Client",
    invoice: "Invoice | None",
    payment_method: "PaymentMethod | None",
    status: str,
    message: str | None,
    amount_cents: int,
    stripe_payment_intent_id: str | None = None,
    stripe_event_id: str | None = None,
) -> "AutopayEvent":
    event = AutopayEvent(
        client_id=client.id,
        invoice_id=invoice.id if invoice else None,
        payment_method_id=payment_method.id if payment_method else None,
        status=status,
        message=message,
        amount_cents=amount_cents,
        stripe_payment_intent_id=stripe_payment_intent_id,
        stripe_event_id=stripe_event_id,
    )
    db.session.add(event)
    return event


def ensure_stripe_customer(client: "Client") -> str | None:
    if not stripe_active():
        return None

    if client.stripe_customer_id:
        return client.stripe_customer_id

    metadata = {
        "client_id": str(client.id) if client.id else None,
        "account_reference": client.account_reference,
    }
    metadata = {k: v for k, v in metadata.items() if v is not None}

    customer = stripe.Customer.create(
        name=client.name,
        email=client.email,
        phone=client.phone,
        metadata=metadata,
    )
    client.stripe_customer_id = customer.id
    db.session.flush()
    return customer.id


def _stripe_card_details(payment_method: object) -> dict[str, object]:
    if not payment_method or getattr(payment_method, "type", None) != "card":
        return {}
    card = getattr(payment_method, "card", None) or {}
    billing_details = getattr(payment_method, "billing_details", None) or {}
    address = getattr(billing_details, "address", None) or {}
    return {
        "brand": getattr(card, "brand", "Card").title(),
        "last4": getattr(card, "last4", "????"),
        "exp_month": getattr(card, "exp_month", 1),
        "exp_year": getattr(card, "exp_year", datetime.now().year),
        "billing_zip": getattr(address, "postal_code", None),
        "cardholder_name": getattr(billing_details, "name", None),
    }


def sync_stripe_payment_method(
    client: "Client",
    stripe_payment_method_id: str,
    *,
    set_default: bool = False,
) -> "PaymentMethod":
    if not stripe_active():
        raise RuntimeError("Stripe is not configured")

    customer_id = ensure_stripe_customer(client)
    assert customer_id is not None

    payment_method = stripe.PaymentMethod.retrieve(stripe_payment_method_id)
    if getattr(payment_method, "customer", None) != customer_id:
        stripe.PaymentMethod.attach(stripe_payment_method_id, customer=customer_id)

    details = _stripe_card_details(payment_method)

    existing = PaymentMethod.query.filter(
        or_(
            PaymentMethod.stripe_payment_method_id == stripe_payment_method_id,
            PaymentMethod.token == stripe_payment_method_id,
        )
    ).first()

    if existing is None:
        existing = PaymentMethod(client_id=client.id)

    existing.nickname = existing.nickname or details.get("brand")
    existing.brand = details.get("brand") or existing.brand or "Card"
    existing.last4 = details.get("last4", existing.last4 or "0000")
    existing.exp_month = details.get("exp_month", existing.exp_month or 1)
    existing.exp_year = details.get("exp_year", existing.exp_year or datetime.now().year)
    existing.billing_zip = details.get("billing_zip") or existing.billing_zip
    existing.cardholder_name = details.get("cardholder_name") or existing.cardholder_name
    existing.token = stripe_payment_method_id
    existing.stripe_payment_method_id = stripe_payment_method_id

    if set_default or not client.default_payment_method():
        for other in client.payment_methods:
            other.is_default = False
        existing.is_default = True
        stripe.Customer.modify(
            customer_id,
            invoice_settings={"default_payment_method": stripe_payment_method_id},
        )
    else:
        existing.is_default = existing.is_default

    db.session.add(existing)
    db.session.flush()
    return existing


def ensure_invoice_payment_intent(
    invoice: "Invoice",
    *,
    autopay: bool,
    client: "Client",
    payment_method_id: str | None = None,
) -> "stripe.PaymentIntent | None":
    if not stripe_active():
        return None

    customer_id = ensure_stripe_customer(client)
    if customer_id is None:
        return None

    metadata = {
        "invoice_id": str(invoice.id),
        "client_id": str(client.id),
        STRIPE_AUTOPAY_METADATA_FLAG: "true" if autopay else "false",
    }

    description = f"Invoice {invoice.id} - {invoice.description}"[:220]

    if invoice.stripe_payment_intent_id:
        payment_intent = stripe.PaymentIntent.retrieve(invoice.stripe_payment_intent_id)
        if getattr(payment_intent, "status", "") in {"succeeded", "processing"}:
            return payment_intent
        if getattr(payment_intent, "status", "") == "requires_payment_method" and payment_method_id:
            stripe.PaymentIntent.modify(
                payment_intent.id,
                payment_method=payment_method_id,
                metadata=metadata,
                description=description,
            )
            if autopay:
                payment_intent = stripe.PaymentIntent.confirm(
                    payment_intent.id, payment_method=payment_method_id
                )
            return payment_intent
        if getattr(payment_intent, "status", "") == "requires_confirmation" and autopay:
            payment_intent = stripe.PaymentIntent.confirm(
                payment_intent.id, payment_method=payment_method_id
            )
            return payment_intent
        if getattr(payment_intent, "status", "") == "canceled":
            invoice.stripe_payment_intent_id = None

    params: dict[str, object] = {
        "amount": invoice.amount_cents,
        "currency": STRIPE_DEFAULT_CURRENCY,
        "customer": customer_id,
        "description": description,
        "metadata": metadata,
    }

    if autopay:
        if payment_method_id:
            params["payment_method"] = payment_method_id
        params["off_session"] = True
        params["confirm"] = True
    else:
        params["automatic_payment_methods"] = {"enabled": True}
        if payment_method_id:
            params["payment_method"] = payment_method_id

    payment_intent = stripe.PaymentIntent.create(**params)
    invoice.stripe_payment_intent_id = payment_intent.id
    return payment_intent


def describe_stripe_error(error: StripeError) -> str:
    message = getattr(error, "user_message", None) or getattr(error, "message", None)
    if message:
        return message
    return "An unexpected payment processor error occurred."


def _metadata_dict(stripe_object: object) -> dict[str, str]:
    metadata = getattr(stripe_object, "metadata", None) or {}
    try:
        return dict(metadata)
    except TypeError:
        try:
            return dict(metadata.to_dict())  # type: ignore[attr-defined]
        except AttributeError:
            return {}


def _find_invoice_for_intent(intent: object) -> "Invoice | None":
    metadata = _metadata_dict(intent)
    invoice_id = metadata.get("invoice_id")
    if not invoice_id:
        payment_intent_id = getattr(intent, "id", None)
        if payment_intent_id:
            return Invoice.query.filter_by(
                stripe_payment_intent_id=payment_intent_id
            ).first()
        return None
    try:
        invoice_id_int = int(invoice_id)
    except (TypeError, ValueError):
        return None
    return Invoice.query.get(invoice_id_int)


def _resolve_payment_method_record(
    client: "Client", payment_method_id: str | None
) -> "PaymentMethod | None":
    if not payment_method_id:
        return None
    existing = PaymentMethod.query.filter(
        or_(
            PaymentMethod.token == payment_method_id,
            PaymentMethod.stripe_payment_method_id == payment_method_id,
        )
    ).first()
    if existing:
        return existing
    try:
        return sync_stripe_payment_method(
            client,
            payment_method_id,
            set_default=False,
        )
    except StripeError:
        return None


def handle_stripe_event(event: object) -> bool:
    event_type = getattr(event, "type", "")
    data_object = getattr(getattr(event, "data", None), "object", None)
    if not data_object:
        return False

    if event_type == "payment_intent.succeeded":
        return _handle_payment_intent_succeeded(event, data_object)
    if event_type == "payment_intent.payment_failed":
        return _handle_payment_intent_failed(event, data_object)
    if event_type == "setup_intent.succeeded":
        return _handle_setup_intent_succeeded(event, data_object)
    if event_type in {"charge.refunded", "charge.refund.updated"}:
        return _handle_charge_refunded(event, data_object)

    return False


def _handle_payment_intent_succeeded(event: object, intent: object) -> bool:
    invoice = _find_invoice_for_intent(intent)
    if invoice is None:
        return False

    client = invoice.client
    metadata = _metadata_dict(intent)
    autopay_flag = metadata.get(STRIPE_AUTOPAY_METADATA_FLAG) == "true"
    payment_method_id = getattr(intent, "payment_method", None)
    payment_method = _resolve_payment_method_record(client, payment_method_id)

    invoice.status = "Paid"
    invoice.paid_at = utcnow()
    invoice.paid_via = (
        f"Stripe {payment_method.describe()}"
        if payment_method
        else "Stripe"
    )
    invoice.autopay_status = "Paid" if autopay_flag else "Manual"
    invoice.stripe_payment_intent_id = getattr(intent, "id", invoice.stripe_payment_intent_id)

    charges = getattr(getattr(intent, "charges", None), "data", None) or []
    if charges:
        charge = charges[0]
        invoice.stripe_charge_id = getattr(charge, "id", invoice.stripe_charge_id)

    if autopay_flag:
        record_autopay_event(
            client=client,
            invoice=invoice,
            payment_method=payment_method,
            status="success",
            message="Stripe confirmed autopay",
            amount_cents=invoice.amount_cents,
            stripe_payment_intent_id=getattr(intent, "id", None),
            stripe_event_id=getattr(event, "id", None),
        )

    recalculate_client_billing_state(client)
    return True


def _handle_payment_intent_failed(event: object, intent: object) -> bool:
    invoice = _find_invoice_for_intent(intent)
    if invoice is None:
        return False

    metadata = _metadata_dict(intent)
    autopay_flag = metadata.get(STRIPE_AUTOPAY_METADATA_FLAG) == "true"
    if not autopay_flag:
        return False

    client = invoice.client
    payment_method_id = getattr(intent, "payment_method", None)
    payment_method = _resolve_payment_method_record(client, payment_method_id)
    last_error = getattr(intent, "last_payment_error", None)
    message = getattr(last_error, "message", None) or "Autopay failed"

    invoice.autopay_attempted_at = utcnow()
    invoice.autopay_status = "Failed"

    record_autopay_event(
        client=client,
        invoice=invoice,
        payment_method=payment_method,
        status="failed",
        message=message,
        amount_cents=invoice.amount_cents,
        stripe_payment_intent_id=getattr(intent, "id", None),
        stripe_event_id=getattr(event, "id", None),
    )
    recalculate_client_billing_state(client)
    return True


def _handle_setup_intent_succeeded(event: object, setup_intent: object) -> bool:
    payment_method_id = getattr(setup_intent, "payment_method", None)
    if not payment_method_id:
        return False

    metadata = _metadata_dict(setup_intent)
    client_id = metadata.get("client_id")
    client: Client | None = None
    if client_id:
        try:
            client = Client.query.get(int(client_id))
        except (TypeError, ValueError):
            client = None
    if client is None:
        customer_id = getattr(setup_intent, "customer", None)
        if customer_id:
            client = Client.query.filter_by(stripe_customer_id=customer_id).first()

    if client is None:
        return False

    _resolve_payment_method_record(client, payment_method_id)
    return True


def _handle_charge_refunded(event: object, charge: object) -> bool:
    charge_id = getattr(charge, "id", None)
    if not charge_id:
        return False

    invoice = Invoice.query.filter_by(stripe_charge_id=charge_id).first()
    if invoice is None:
        return False

    invoice.status = "Refunded"
    invoice.autopay_status = "Refunded"
    invoice.stripe_refund_id = getattr(charge, "latest_refund", invoice.stripe_refund_id)
    record_autopay_event(
        client=invoice.client,
        invoice=invoice,
        payment_method=None,
        status="refunded",
        message="Stripe issued a refund",
        amount_cents=invoice.amount_cents,
        stripe_payment_intent_id=invoice.stripe_payment_intent_id,
        stripe_event_id=getattr(event, "id", None),
    )
    recalculate_client_billing_state(invoice.client)
    return True


class Client(db.Model):
    __tablename__ = "clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(40))
    address = db.Column(db.String(255))
    company = db.Column(db.String(255))
    project_type = db.Column(db.String(120))
    residential_plan = db.Column(db.String(120))
    phone_plan = db.Column(db.String(120))
    business_plan = db.Column(db.String(120))
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default="New")
    wifi_router_needed = db.Column(db.Boolean, nullable=False, default=False)
    portal_access_code = db.Column(
        db.String(64), nullable=False, unique=True, default=generate_portal_password
    )
    portal_password_hash = db.Column(db.String(255))
    portal_password_updated_at = db.Column(db.DateTime(timezone=True))
    account_reference = db.Column(
        db.String(24), nullable=False, unique=True, default=generate_account_reference
    )
    driver_license_number = db.Column(db.String(120))
    verification_photo_filename = db.Column(db.String(255))
    verification_photo_uploaded_at = db.Column(db.DateTime(timezone=True))
    autopay_enabled = db.Column(db.Boolean, nullable=False, default=False)
    stripe_customer_id = db.Column(db.String(64), unique=True)
    billing_status = db.Column(db.String(40), nullable=False, default="Good Standing")
    billing_status_updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow
    )
    service_suspended = db.Column(db.Boolean, nullable=False, default=False)
    suspension_reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    invoices = db.relationship(
        "Invoice", back_populates="client", cascade="all, delete-orphan"
    )
    equipment = db.relationship(
        "Equipment", back_populates="client", cascade="all, delete-orphan"
    )
    tickets = db.relationship(
        "SupportTicket", back_populates="client", cascade="all, delete-orphan"
    )
    appointments = db.relationship(
        "Appointment", back_populates="client", cascade="all, delete-orphan"
    )
    install_photos = db.relationship(
        "InstallPhoto", back_populates="client", cascade="all, delete-orphan"
    )
    payment_methods = db.relationship(
        "PaymentMethod", back_populates="client", cascade="all, delete-orphan"
    )
    autopay_events = db.relationship(
        "AutopayEvent", back_populates="client", cascade="all, delete-orphan"
    )
    install_acknowledgements = db.relationship(
        "InstallAcknowledgement",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    uisp_devices = db.relationship("UispDevice", back_populates="client")

    def __repr__(self) -> str:
        return f"<Client {self.email}>"

    @property
    def service_summary(self) -> str | None:
        selections = [
            plan
            for plan in (
                self.residential_plan,
                self.phone_plan,
                self.business_plan,
            )
            if plan
        ]
        if selections:
            return ", ".join(selections)
        return self.project_type

    def default_payment_method(self) -> "PaymentMethod | None":
        active_methods = [
            method for method in self.payment_methods if method.status == "Active"
        ]
        if not active_methods:
            return None
        active_methods.sort(key=lambda method: (not method.is_default, method.created_at))
        return active_methods[0]


class ServicePlan(db.Model):
    __tablename__ = "service_plans"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False, default="Residential")
    name = db.Column(db.String(120), nullable=False, unique=True)
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    speed = db.Column(db.String(120))
    description = db.Column(db.Text)
    features_text = db.Column(db.Text)
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    @property
    def feature_list(self) -> list[str]:
        if not self.features_text:
            return []
        return [line.strip() for line in self.features_text.splitlines() if line.strip()]

    def set_features_from_text(self, raw_text: str) -> None:
        features = [line.strip() for line in raw_text.splitlines() if line.strip()]
        self.features_text = "\n".join(features) if features else None

    def __repr__(self) -> str:
        return f"<ServicePlan {self.name} ({self.category})>"


STATUS_OPTIONS = ["New", "In Review", "Active", "On Hold", "Archived"]

DEFAULT_SERVICE_PLANS = [
    {
        "name": "Wireless Internet (WISP)",
        "category": "Residential",
        "price_cents": 6999,
        "speed": "Up to 150 Mbps",
        "description": "Reliable fixed wireless connectivity ideal for streaming, smart homes, and everyday browsing.",
        "features": [
            "Unlimited data with no hard caps",
            "Managed Wi-Fi gateway included",
            "Priority local support from DIXIELAND technicians",
        ],
    },
    {
        "name": "Phone Service",
        "category": "Phone Service",
        "price_cents": 2999,
        "speed": "Digital voice",
        "description": "Crystal clear home and small business voice with enhanced emergency calling.",
        "features": [
            "Unlimited local and long-distance calling",
            "Voicemail-to-email and caller ID",
            "Battery-backed customer premise equipment",
        ],
    },
    {
        "name": "Business Voice Essentials",
        "category": "Phone Service",
        "price_cents": 4999,
        "speed": "Digital voice",
        "description": "Scalable VoIP lines for offices, point-of-sale, and dispatch desks.",
        "features": [
            "Unlimited nationwide calling",
            "Auto attendants and hunt groups",
            "Priority dispatch with 4-hour response",
        ],
    },
    {
        "name": "Internet + Phone Bundle",
        "category": "Residential",
        "price_cents": 9499,
        "speed": "Up to 150 Mbps + Digital voice",
        "description": "Best value bundle for households that want fast wireless internet and dependable phone service together.",
        "features": [
            "Bundled savings on monthly service",
            "Single invoice with autopay support",
            "Priority repair dispatch",
        ],
    },
    {
        "name": "Business Wireless Pro",
        "category": "Business",
        "price_cents": 15999,
        "speed": "Up to 300 Mbps",
        "description": "Enterprise-grade fixed wireless with static IP availability and guaranteed response times.",
        "features": [
            "Managed dual-WAN edge router",
            "Static IP options and VLAN support",
            "24/7 priority NOC escalation",
        ],
    },
]

PLAN_CATEGORY_ORDER = {"Residential": 0, "Phone Service": 1, "Business": 2}

PLAN_FIELD_DEFINITIONS: list[tuple[str, str, str]] = [
    ("Residential", "residential_plan", "Residential plan"),
    ("Phone Service", "phone_plan", "Phone service plan"),
    ("Business", "business_plan", "Business plan"),
]

LEGAL_DOCUMENT_TYPES = {
    "aup": {
        "label": "Acceptable Use Policy",
        "description": "Defines network usage expectations for all wireless subscribers.",
    },
    "privacy": {
        "label": "Privacy Policy",
        "description": "Explains how subscriber information is collected, stored, and protected.",
    },
    "tos": {
        "label": "Terms of Service",
        "description": "Outlines service commitments, billing practices, and account responsibilities.",
    },
}

ALLOWED_DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx"}


DOCUMENT_MIME_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

TRUTHY_VALUES = {"1", "true", "yes", "on", "y"}


def is_truthy(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in TRUTHY_VALUES


def wants_json_response() -> bool:
    """Determine whether the current request expects a JSON response."""

    if request.is_json:
        return True

    requested_with = request.headers.get("X-Requested-With", "").lower()
    if requested_with == "xmlhttprequest":
        return True

    accept_mimetypes = request.accept_mimetypes
    if accept_mimetypes:
        best = accept_mimetypes.best
        if best == "application/json":
            return True
        if (
            accept_mimetypes["application/json"]
            and accept_mimetypes["application/json"]
            >= accept_mimetypes["text/html"]
        ):
            return True

    return False

PORTAL_SESSION_KEY = "client_portal_id"
TECH_SESSION_KEY = "technician_portal_id"
DEFAULT_INSTALL_PHOTO_CATEGORIES = [
    "Arrival & Site Overview",
    "Mounting Location & Hardware",
    "Cable Path & Building Entry",
    "Grounding & Weatherproofing",
    "Interior Equipment & Rack",
    "Power & Battery Backup",
    "Customer Premise Gear & Wi-Fi",
    "Speed Test & Service Validation",
]
OPTIONAL_INSTALL_PHOTO_CATEGORY = "Additional Detail"
ALLOWED_INSTALL_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif"}
ALLOWED_VERIFICATION_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".pdf"}
ALLOWED_TICKET_ATTACHMENT_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".heic",
    ".heif",
}
ALLOWED_TEAM_PHOTO_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_TRUSTED_LOGO_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".svg"}
ALLOWED_SUPPORT_PARTNER_LOGO_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".svg",
}


def get_default_navigation_items() -> list[tuple[str, str, bool]]:
    return [
        ("Sign Up", "/signup", False),
        ("Service Plans", "/services", False),
        ("Blog", "/blog", False),
        ("About", "/about", False),
        ("Legal", "/legal", False),
        ("Client Portal", "/portal/login", False),
    ]


APPOINTMENT_STATUS_OPTIONS = [
    "Pending",
    "Confirmed",
    "Reschedule Requested",
    "Declined",
    "Completed",
]


BRANDING_ASSET_TYPES = {
    "logo": {
        "label": "Primary Logo",
        "description": "Displayed in the site header and used across marketing materials.",
    },
    "favicon": {
        "label": "Favicon",
        "description": "Small icon shown in browser tabs and bookmarks (ICO, PNG, or SVG).",
    },
    "wordmark": {
        "label": "Wordmark",
        "description": "Optional alternate logo treatment for proposals or documentation.",
    },
}

ALLOWED_BRANDING_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "svg",
    "ico",
    "webp",
}


INVOICE_STATUS_OPTIONS = ["Pending", "Paid", "Overdue", "Cancelled"]

TICKET_STATUS_OPTIONS = ["Open", "In Progress", "Resolved", "Closed"]
TICKET_PRIORITY_OPTIONS = ["Low", "Normal", "High", "Urgent"]


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    doc_type = db.Column(db.String(50), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Document {self.doc_type}: {self.original_filename}>"


class NavigationItem(db.Model):
    __tablename__ = "navigation_items"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, nullable=False, index=True)
    open_in_new_tab = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<NavigationItem {self.label} -> {self.url}>"


class BrandingAsset(db.Model):
    __tablename__ = "branding_assets"

    id = db.Column(db.Integer, primary_key=True)
    asset_type = db.Column(db.String(50), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<BrandingAsset {self.asset_type}: {self.original_filename}>"


class SiteTheme(db.Model):
    __tablename__ = "site_theme"

    id = db.Column(db.Integer, primary_key=True)
    background_color = db.Column(db.String(7), nullable=False, default="#0e071a")
    text_color = db.Column(db.String(7), nullable=False, default="#f5f3ff")
    muted_color = db.Column(db.String(7), nullable=False, default="#b5a6d8")
    background_image_filename = db.Column(db.String(255))
    background_image_original = db.Column(db.String(255))

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SiteTheme bg={self.background_color} text={self.text_color}>"


class Invoice(db.Model):
    __tablename__ = "invoices"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="Pending")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    paid_at = db.Column(db.DateTime(timezone=True))
    paid_via = db.Column(db.String(120))
    autopay_attempted_at = db.Column(db.DateTime(timezone=True))
    autopay_status = db.Column(db.String(40))
    stripe_payment_intent_id = db.Column(db.String(64))
    stripe_charge_id = db.Column(db.String(64))
    stripe_refund_id = db.Column(db.String(64))

    client = db.relationship("Client", back_populates="invoices")
    autopay_events = db.relationship(
        "AutopayEvent", back_populates="invoice", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Invoice {self.id} for client {self.client_id}>"


class Equipment(db.Model):
    __tablename__ = "equipment"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    model = db.Column(db.String(120))
    serial_number = db.Column(db.String(120))
    installed_on = db.Column(db.Date)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    client = db.relationship("Client", back_populates="equipment")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Equipment {self.name} for client {self.client_id}>"


class NetworkTower(db.Model):
    __tablename__ = "network_towers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    devices = db.relationship("UispDevice", back_populates="tower")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<NetworkTower {self.name}>"


class UispDevice(db.Model):
    __tablename__ = "uisp_devices"

    id = db.Column(db.Integer, primary_key=True)
    uisp_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    nickname = db.Column(db.String(120))
    model = db.Column(db.String(120))
    mac_address = db.Column(db.String(32))
    site_name = db.Column(db.String(120))
    ip_address = db.Column(db.String(64))
    status = db.Column(db.String(20), nullable=False, default="unknown")
    last_seen_at = db.Column(db.DateTime(timezone=True))
    firmware_version = db.Column(db.String(64))
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"))
    tower_id = db.Column(db.Integer, db.ForeignKey("network_towers.id"))
    notes = db.Column(db.Text)
    outage_notified_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client = db.relationship("Client", back_populates="uisp_devices")
    tower = db.relationship("NetworkTower", back_populates="devices")

    def display_name(self) -> str:
        return self.nickname or self.name

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<UispDevice {self.display_name()} ({self.uisp_id})>"


class Technician(db.Model):
    __tablename__ = "technicians"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    appointments = db.relationship("Appointment", back_populates="technician")
    install_photos = db.relationship(
        "InstallPhoto", back_populates="technician", cascade="all, delete-orphan"
    )
    install_acknowledgements = db.relationship(
        "InstallAcknowledgement",
        back_populates="technician",
        cascade="all, delete-orphan",
    )
    schedule_blocks = db.relationship(
        "TechnicianSchedule",
        back_populates="technician",
        cascade="all, delete-orphan",
        order_by="TechnicianSchedule.start_at",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Technician {self.email}>"


class TechnicianSchedule(db.Model):
    __tablename__ = "technician_schedule"

    id = db.Column(db.Integer, primary_key=True)
    technician_id = db.Column(db.Integer, db.ForeignKey("technicians.id"), nullable=False)
    start_at = db.Column(db.DateTime(timezone=True), nullable=False)
    end_at = db.Column(db.DateTime(timezone=True), nullable=False)
    note = db.Column(db.String(255))
    status = db.Column(db.String(20), nullable=False, default="pending")
    review_note = db.Column(db.Text)
    reviewed_at = db.Column(db.DateTime(timezone=True))
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"))
    cancel_requested_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    technician = db.relationship("Technician", back_populates="schedule_blocks")
    reviewed_by = db.relationship("AdminUser")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"<TechnicianSchedule technician={self.technician_id} "
            f"start={self.start_at:%Y-%m-%d %H:%M} status={self.status}>"
        )


class InstallPhotoRequirement(db.Model):
    __tablename__ = "install_photo_requirements"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(160), nullable=False, unique=True)
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<InstallPhotoRequirement {self.label}>"


class InstallPhoto(db.Model):
    __tablename__ = "install_photos"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    technician_id = db.Column(
        db.Integer, db.ForeignKey("technicians.id"), nullable=False
    )
    category = db.Column(db.String(80), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    client = db.relationship("Client", back_populates="install_photos")
    technician = db.relationship("Technician", back_populates="install_photos")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<InstallPhoto {self.stored_filename} for client {self.client_id}>"


class InstallAcknowledgement(db.Model):
    __tablename__ = "install_acknowledgements"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    technician_id = db.Column(
        db.Integer, db.ForeignKey("technicians.id"), nullable=False
    )
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.id"))
    signed_name = db.Column(db.String(120), nullable=False)
    signature_filename = db.Column(db.String(255), nullable=False)
    signed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    aup_document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))
    privacy_document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))
    tos_document_id = db.Column(db.Integer, db.ForeignKey("documents.id"))

    client = db.relationship("Client", back_populates="install_acknowledgements")
    technician = db.relationship("Technician", back_populates="install_acknowledgements")
    appointment = db.relationship("Appointment", back_populates="acknowledgements")
    aup_document = db.relationship("Document", foreign_keys=[aup_document_id])
    privacy_document = db.relationship("Document", foreign_keys=[privacy_document_id])
    tos_document = db.relationship("Document", foreign_keys=[tos_document_id])

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"<InstallAcknowledgement client={self.client_id} "
            f"signed={self.signed_at:%Y-%m-%d}>"
        )


class PaymentMethod(db.Model):
    __tablename__ = "payment_methods"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    nickname = db.Column(db.String(120))
    brand = db.Column(db.String(40), nullable=False)
    last4 = db.Column(db.String(4), nullable=False)
    exp_month = db.Column(db.Integer, nullable=False)
    exp_year = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(128), nullable=False, unique=True)
    stripe_payment_method_id = db.Column(db.String(64), unique=True)
    billing_zip = db.Column(db.String(12))
    cardholder_name = db.Column(db.String(120))
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(20), nullable=False, default="Active")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client = db.relationship("Client", back_populates="payment_methods")
    autopay_events = db.relationship(
        "AutopayEvent", back_populates="payment_method", cascade="all, delete-orphan"
    )

    def describe(self) -> str:
        return f"{self.brand} ••••{self.last4}"


class AutopayEvent(db.Model):
    __tablename__ = "autopay_events"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    invoice_id = db.Column(db.Integer, db.ForeignKey("invoices.id"))
    payment_method_id = db.Column(db.Integer, db.ForeignKey("payment_methods.id"))
    status = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(255))
    attempted_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    amount_cents = db.Column(db.Integer, nullable=False, default=0)
    stripe_payment_intent_id = db.Column(db.String(64))
    stripe_event_id = db.Column(db.String(64))

    client = db.relationship("Client", back_populates="autopay_events")
    invoice = db.relationship("Invoice", back_populates="autopay_events")
    payment_method = db.relationship("PaymentMethod", back_populates="autopay_events")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AutopayEvent {self.status} client={self.client_id}>"


class SupportTicket(db.Model):
    __tablename__ = "support_tickets"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Open")
    priority = db.Column(db.String(20), nullable=False, default="Normal")
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client = db.relationship("Client", back_populates="tickets")
    attachments = db.relationship(
        "SupportTicketAttachment",
        back_populates="ticket",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SupportTicket {self.id} for client {self.client_id}>"


class SupportTicketAttachment(db.Model):
    __tablename__ = "support_ticket_attachments"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(
        db.Integer, db.ForeignKey("support_tickets.id"), nullable=False, index=True
    )
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    ticket = db.relationship("SupportTicket", back_populates="attachments")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SupportTicketAttachment {self.id} ticket={self.ticket_id}>"


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(255), unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True))

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AdminUser {self.username}>"


class Appointment(db.Model):
    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    technician_id = db.Column(db.Integer, db.ForeignKey("technicians.id"))
    title = db.Column(db.String(120), nullable=False)
    scheduled_for = db.Column(db.DateTime(timezone=True), nullable=False)
    status = db.Column(db.String(40), nullable=False, default="Pending")
    notes = db.Column(db.Text)
    client_message = db.Column(db.Text)
    proposed_time = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client = db.relationship("Client", back_populates="appointments")
    technician = db.relationship("Technician", back_populates="appointments")
    acknowledgements = db.relationship(
        "InstallAcknowledgement",
        back_populates="appointment",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Appointment {self.title} for client {self.client_id}>"


class SNMPConfig(db.Model):
    __tablename__ = "snmp_config"

    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255))
    port = db.Column(db.Integer, nullable=False, default=162)
    community = db.Column(db.String(120), nullable=False, default="public")
    enterprise_oid = db.Column(
        db.String(255), nullable=False, default="1.3.6.1.4.1.8072.9999"
    )
    admin_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SNMPConfig host={self.host} port={self.port}>"


class DownDetectorConfig(db.Model):
    __tablename__ = "down_detector_config"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500))
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<DownDetectorConfig target={self.target_url}>"


class StripeConfig(db.Model):
    __tablename__ = "stripe_config"

    id = db.Column(db.Integer, primary_key=True)
    secret_key = db.Column(db.String(255))
    publishable_key = db.Column(db.String(255))
    webhook_secret = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return "<StripeConfig>"


class NotificationConfig(db.Model):
    __tablename__ = "notification_config"

    id = db.Column(db.Integer, primary_key=True)
    smtp_host = db.Column(db.String(255), nullable=False, default="smtp.office365.com")
    smtp_port = db.Column(db.Integer, nullable=False, default=587)
    use_tls = db.Column(db.Boolean, nullable=False, default=True)
    from_email = db.Column(db.String(255))
    from_name = db.Column(db.String(255))
    reply_to_email = db.Column(db.String(255))
    reply_to_name = db.Column(db.String(255))
    smtp_username = db.Column(db.String(255))
    smtp_password = db.Column(db.String(255))
    tenant_id = db.Column(db.String(255))
    client_id = db.Column(db.String(255))
    client_secret = db.Column(db.String(255))
    list_unsubscribe_url = db.Column(db.String(500))
    list_unsubscribe_mailto = db.Column(db.String(500))
    notify_install_activity = db.Column(db.Boolean, nullable=False, default=True)
    notify_customer_activity = db.Column(db.Boolean, nullable=False, default=True)
    notify_all_account_activity = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def office365_ready(self) -> bool:
        username = (self.smtp_username or "").strip()
        password = (self.smtp_password or "").strip()
        sender = (self.from_email or username or "").strip()
        return bool(username and password and sender)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return "<NotificationConfig>"


class UispConfig(db.Model):
    __tablename__ = "uisp_config"

    id = db.Column(db.Integer, primary_key=True)
    base_url = db.Column(db.String(255))
    api_token = db.Column(db.String(255))
    auto_sync_enabled = db.Column(db.Boolean, nullable=False, default=False)
    auto_sync_interval_minutes = db.Column(db.Integer, nullable=False, default=30)
    last_synced_at = db.Column(db.DateTime(timezone=True))
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return "<UispConfig>"


class TLSConfig(db.Model):
    __tablename__ = "tls_config"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255))
    contact_email = db.Column(db.String(255))
    certificate_path = db.Column(db.String(500))
    private_key_path = db.Column(db.String(500))
    challenge_path = db.Column(db.String(500))
    auto_renew = db.Column(db.Boolean, nullable=False, default=True)
    use_staging = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(50), nullable=False, default="pending")
    last_error = db.Column(db.Text)
    last_provisioned_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def certificate_ready(self) -> bool:
        return bool(
            self.certificate_path
            and self.private_key_path
            and Path(self.certificate_path).exists()
            and Path(self.private_key_path).exists()
        )


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False, unique=True, index=True)
    summary = db.Column(db.String(500))
    content = db.Column(db.Text, nullable=False)
    is_published = db.Column(db.Boolean, nullable=False, default=False)
    published_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<BlogPost {self.slug}>"


class TeamMember(db.Model):
    __tablename__ = "team_members"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(160))
    bio = db.Column(db.Text())
    photo_filename = db.Column(db.String(255))
    photo_original = db.Column(db.String(255))
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<TeamMember {self.name}>"


class TrustedBusiness(db.Model):
    __tablename__ = "trusted_businesses"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    website_url = db.Column(db.String(500))
    logo_filename = db.Column(db.String(255))
    logo_original = db.Column(db.String(255))
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<TrustedBusiness {self.name}>"


class SupportPartner(db.Model):
    __tablename__ = "support_partners"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    website_url = db.Column(db.String(500))
    description = db.Column(db.Text())
    logo_filename = db.Column(db.String(255))
    logo_original = db.Column(db.String(255))
    position = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SupportPartner {self.name}>"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    app.jinja_env.filters.setdefault("slugify", slugify_segment)

    instance_path = Path(app.instance_path)
    db_path = instance_path / "clients.db"
    os.makedirs(instance_path, exist_ok=True)

    secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(16)

    snmp_port_env = os.environ.get("SNMP_TRAP_PORT")
    try:
        snmp_port = int(snmp_port_env) if snmp_port_env else 162
    except ValueError:
        snmp_port = 162

    default_config = {
        "SECRET_KEY": secret_key,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME"),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD"),
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL"),
        "LEGAL_UPLOAD_FOLDER": str(instance_path / "legal"),
        "BRANDING_UPLOAD_FOLDER": str(instance_path / "branding"),
        "THEME_UPLOAD_FOLDER": str(instance_path / "theme"),
        "TEAM_UPLOAD_FOLDER": str(instance_path / "team"),
        "TRUSTED_BUSINESS_UPLOAD_FOLDER": str(instance_path / "trusted_businesses"),
        "SUPPORT_PARTNER_UPLOAD_FOLDER": str(instance_path / "support_partners"),
        "INSTALL_PHOTOS_FOLDER": str(instance_path / "install_photos"),
        "INSTALL_SIGNATURE_FOLDER": str(instance_path / "install_signatures"),
        "CLIENT_VERIFICATION_FOLDER": str(instance_path / "verification"),
        "SUPPORT_TICKET_ATTACHMENT_FOLDER": str(instance_path / "ticket_attachments"),
        "TLS_CHALLENGE_FOLDER": str(instance_path / "acme-challenges"),
        "TLS_CONFIG_FOLDER": str(instance_path / "letsencrypt"),
        "TLS_WORK_FOLDER": str(instance_path / "letsencrypt-work"),
        "TLS_LOG_FOLDER": str(instance_path / "letsencrypt-logs"),
        "CONTACT_EMAIL": os.environ.get(
            "CONTACT_EMAIL", "info@dixielandwireless.com"
        ),
        "CONTACT_PHONE": os.environ.get("CONTACT_PHONE", "2053343969"),
        "STRIPE_SECRET_KEY": os.environ.get("STRIPE_SECRET_KEY"),
        "STRIPE_PUBLISHABLE_KEY": os.environ.get("STRIPE_PUBLISHABLE_KEY"),
        "STRIPE_WEBHOOK_SECRET": os.environ.get("STRIPE_WEBHOOK_SECRET"),
        "UISP_BASE_URL": os.environ.get("UISP_BASE_URL"),
        "UISP_API_TOKEN": os.environ.get("UISP_API_TOKEN"),
        "UISP_API_TIMEOUT": float(os.environ.get("UISP_API_TIMEOUT", "10")),
        "SITE_SHELL_CACHE_SECONDS": float(
            os.environ.get(
                "SITE_SHELL_CACHE_SECONDS", SITE_SHELL_CACHE_SECONDS_DEFAULT
            )
        ),
        "DASHBOARD_OVERVIEW_CACHE_SECONDS": float(
            os.environ.get(
                "DASHBOARD_OVERVIEW_CACHE_SECONDS",
                DASHBOARD_OVERVIEW_CACHE_SECONDS_DEFAULT,
            )
        ),
        "SNMP_TRAP_HOST": os.environ.get("SNMP_TRAP_HOST"),
        "SNMP_TRAP_PORT": snmp_port,
        "SNMP_COMMUNITY": os.environ.get("SNMP_COMMUNITY", "public"),
        "SNMP_ENTERPRISE_OID": os.environ.get(
            "SNMP_ENTERPRISE_OID", "1.3.6.1.4.1.8072.9999"
        ),
        "SNMP_ADMIN_EMAIL": os.environ.get("SNMP_ADMIN_EMAIL"),
        "SNMP_EMAIL_SENDER": None,
    }

    app.config.update(default_config)
    if "ALLOWED_FILE_TRANSFER_SURFACES" not in app.config:
        app.config["ALLOWED_FILE_TRANSFER_SURFACES"] = set(
            FILE_TRANSFER_SURFACES.keys()
        )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    init_stripe(app)

    register_routes(app)

    with app.app_context():
        for folder_key in [
            "LEGAL_UPLOAD_FOLDER",
            "BRANDING_UPLOAD_FOLDER",
            "THEME_UPLOAD_FOLDER",
            "TEAM_UPLOAD_FOLDER",
            "TRUSTED_BUSINESS_UPLOAD_FOLDER",
            "SUPPORT_PARTNER_UPLOAD_FOLDER",
            "INSTALL_PHOTOS_FOLDER",
            "INSTALL_SIGNATURE_FOLDER",
            "CLIENT_VERIFICATION_FOLDER",
            "SUPPORT_TICKET_ATTACHMENT_FOLDER",
            "TLS_CHALLENGE_FOLDER",
            "TLS_CONFIG_FOLDER",
            "TLS_WORK_FOLDER",
            "TLS_LOG_FOLDER",
        ]:
            folder_path = Path(app.config[folder_key])
            folder_path.mkdir(parents=True, exist_ok=True)
        db.create_all()
        apply_stripe_config_from_database(app)
        ensure_billing_schema_once()
        ensure_default_admin_user()
        ensure_client_portal_fields()
        ensure_default_navigation()
        ensure_service_plans_seeded()
        ensure_snmp_configuration()
        ensure_notification_configuration()
        ensure_appointment_technician_field()
        ensure_support_ticket_priority_field()
        ensure_install_photo_requirements_seeded()
        ensure_technician_schedule_review_fields()
        ensure_team_member_bio_field()
        ensure_site_theme_background_fields()
        ensure_down_detector_configuration()
        ensure_tls_configuration()
        ensure_site_theme()
        ensure_uisp_schema()

    return app


def init_db() -> None:
    """Initialize the database tables if they do not exist."""

    app = create_app()
    with app.app_context():
        db.create_all()
        apply_stripe_config_from_database(app)
        ensure_billing_schema_once()
        ensure_default_admin_user()
        ensure_client_portal_fields()
        ensure_default_navigation()
        ensure_service_plans_seeded()
        ensure_snmp_configuration()
        ensure_notification_configuration()
        ensure_appointment_technician_field()
        ensure_support_ticket_priority_field()
        ensure_install_photo_requirements_seeded()
        ensure_technician_schedule_review_fields()
        ensure_team_member_bio_field()
        ensure_site_theme_background_fields()
        ensure_down_detector_configuration()
        ensure_tls_configuration()
        ensure_site_theme()
        ensure_uisp_schema()


def issue_lets_encrypt_certificate(
    app: Flask, config: TLSConfig, *, staging: bool = False
) -> tuple[bool, str | None, Path | None, Path | None]:
    domain = (config.domain or "").strip()
    contact_email = (config.contact_email or "").strip()
    if not domain or not contact_email:
        return False, "Domain and contact email are required before provisioning.", None, None

    certbot_path = shutil.which("certbot")
    if not certbot_path:
        return False, "Certbot is not installed on this system.", None, None

    challenge_folder = Path(app.config["TLS_CHALLENGE_FOLDER"])
    config_folder = Path(app.config["TLS_CONFIG_FOLDER"])
    work_folder = Path(app.config["TLS_WORK_FOLDER"])
    log_folder = Path(app.config["TLS_LOG_FOLDER"])

    for folder in (challenge_folder, config_folder, work_folder, log_folder):
        folder.mkdir(parents=True, exist_ok=True)

    command = [
        certbot_path,
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--webroot",
        "-w",
        str(challenge_folder),
        "-d",
        domain,
        "--email",
        contact_email,
        "--config-dir",
        str(config_folder),
        "--work-dir",
        str(work_folder),
        "--logs-dir",
        str(log_folder),
    ]

    if staging:
        command.append("--test-cert")

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        error_output = result.stderr.strip() or result.stdout.strip()
        message = error_output or "Certbot failed without output."
        return False, message, None, None

    cert_dir = config_folder / "live" / domain
    cert_path = cert_dir / "fullchain.pem"
    key_path = cert_dir / "privkey.pem"
    if not cert_path.exists() or not key_path.exists():
        return False, "Certificate files were not found after provisioning.", None, None

    return True, None, cert_path, key_path


def send_email_via_office365(
    app: Flask, recipient: str, subject: str, body: str
) -> bool:
    config = NotificationConfig.query.first()
    if not config or not recipient:
        return False

    if not config.office365_ready():
        return False

    host = (config.smtp_host or "smtp.office365.com").strip()
    try:
        port = int(config.smtp_port or 587)
    except (TypeError, ValueError):
        port = 587

    from_email = (config.from_email or config.smtp_username or "").strip()
    from_name = (config.from_name or app.config.get("SITE_NAME") or "").strip() or "DixieLand Wireless"
    username = (config.smtp_username or "").strip()
    password = config.smtp_password or ""

    if not from_email or not username or not password:
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((from_name, from_email))
    message["To"] = recipient
    message["Date"] = format_datetime(datetime.now(UTC))
    message["Message-ID"] = make_msgid(domain=from_email.split("@")[-1])

    reply_to_email = (config.reply_to_email or "").strip()
    reply_to_name = (config.reply_to_name or "").strip()
    if reply_to_email:
        if reply_to_name:
            message["Reply-To"] = formataddr((reply_to_name, reply_to_email))
        else:
            message["Reply-To"] = reply_to_email

    unsubscribe_entries: list[str] = []
    mailto_value = (config.list_unsubscribe_mailto or "").strip()
    has_http_unsubscribe = False
    if mailto_value:
        if mailto_value.lower().startswith("mailto:"):
            unsubscribe_entries.append(f"<{mailto_value}>")
        else:
            unsubscribe_entries.append(f"<mailto:{mailto_value}>")
    url_value = (config.list_unsubscribe_url or "").strip()
    if url_value:
        unsubscribe_entries.append(f"<{url_value}>")
        if url_value.lower().startswith("http"):
            has_http_unsubscribe = True
    if unsubscribe_entries:
        message["List-Unsubscribe"] = ", ".join(unsubscribe_entries)
        if has_http_unsubscribe:
            message["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    message.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            if config.use_tls:
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(username, password)
            smtp.send_message(message)
        return True
    except Exception as exc:  # pragma: no cover - external service dependency
        app.logger.warning("Office 365 email delivery failed: %s", exc)
        return False


def send_email_via_snmp(app: Flask, recipient: str, subject: str, body: str) -> bool:
    """Dispatch an email payload via SNMP trap for downstream processing."""

    snmp_config = SNMPConfig.query.first()

    host = (snmp_config.host if snmp_config and snmp_config.host else None) or app.config.get(
        "SNMP_TRAP_HOST"
    )
    if not host or not recipient:
        return False

    port = (
        snmp_config.port if snmp_config and snmp_config.port else app.config.get("SNMP_TRAP_PORT", 162)
    )
    community = (
        snmp_config.community
        if snmp_config and snmp_config.community
        else app.config.get("SNMP_COMMUNITY", "public")
    )
    enterprise_oid = (
        snmp_config.enterprise_oid
        if snmp_config and snmp_config.enterprise_oid
        else app.config.get("SNMP_ENTERPRISE_OID", "1.3.6.1.4.1.8072.9999")
    )

    if snmp_config and snmp_config.admin_email:
        app.config["SNMP_ADMIN_EMAIL"] = snmp_config.admin_email

    try:
        from pysnmp.hlapi import (
            CommunityData,
            ContextData,
            NotificationType,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            sendNotification,
        )
        from pysnmp.proto.rfc1902 import OctetString
    except Exception as exc:  # pragma: no cover - optional dependency
        app.logger.warning("SNMP email dependencies unavailable: %s", exc)
        return False

    try:
        iterator = sendNotification(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, int(port))),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(enterprise_oid)).addVarBinds(
                ObjectType(ObjectIdentity(f"{enterprise_oid}.1"), OctetString(recipient)),
                ObjectType(ObjectIdentity(f"{enterprise_oid}.2"), OctetString(subject)),
                ObjectType(ObjectIdentity(f"{enterprise_oid}.3"), OctetString(body)),
            ),
        )

        error_indication, error_status, error_index, _ = next(iterator)
    except StopIteration:
        return True
    except Exception as exc:  # pragma: no cover - network failure
        app.logger.warning("SNMP email dispatch failed: %s", exc)
        return False

    if error_indication or error_status:
        app.logger.warning(
            "SNMP email delivery error: %s (status=%s index=%s)",
            error_indication,
            error_status,
            error_index,
        )
        return False

    return True


def ensure_default_admin_user() -> None:
    if AdminUser.query.count() > 0:
        return

    username = (current_app.config.get("ADMIN_USERNAME") or "").strip()
    password = current_app.config.get("ADMIN_PASSWORD")
    contact_email = current_app.config.get("ADMIN_EMAIL") or current_app.config.get(
        "CONTACT_EMAIL"
    )

    if not username or not password:
        current_app.logger.warning(
            "No admin users exist and ADMIN_USERNAME/ADMIN_PASSWORD were not provided."
        )
        return

    admin = AdminUser(username=username, email=contact_email)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()


def ensure_default_navigation() -> None:
    max_position = db.session.query(db.func.max(NavigationItem.position)).scalar() or 0
    changed = False

    for label, url, new_tab in get_default_navigation_items():
        existing_item = NavigationItem.query.filter_by(label=label).first()

        if existing_item:
            if (
                existing_item.url != url
                or existing_item.open_in_new_tab != new_tab
            ):
                existing_item.url = url
                existing_item.open_in_new_tab = new_tab
                changed = True
            continue

        max_position += 1
        db.session.add(
            NavigationItem(
                label=label,
                url=url,
                position=max_position,
                open_in_new_tab=new_tab,
            )
        )
        changed = True

    if changed:
        db.session.commit()


def ensure_service_plans_seeded() -> None:
    existing_plans = {
        plan.name: plan for plan in ServicePlan.query.order_by(ServicePlan.position.asc()).all()
    }
    if not existing_plans:
        position = 0
        for plan_data in DEFAULT_SERVICE_PLANS:
            position += 1
            plan = ServicePlan(
                name=plan_data["name"],
                category=plan_data.get("category", "Residential"),
                price_cents=plan_data.get("price_cents", 0),
                speed=plan_data.get("speed"),
                description=plan_data.get("description"),
                position=position,
            )
            plan.set_features_from_text("\n".join(plan_data.get("features", [])))
            db.session.add(plan)

        db.session.commit()
        return

    changed = False
    max_position = (
        db.session.query(db.func.max(ServicePlan.position)).scalar() or len(existing_plans)
    )

    for plan_data in DEFAULT_SERVICE_PLANS:
        name = plan_data["name"]
        plan = existing_plans.get(name)
        if not plan:
            max_position += 1
            plan = ServicePlan(
                name=name,
                category=plan_data.get("category", "Residential"),
                price_cents=plan_data.get("price_cents", 0),
                speed=plan_data.get("speed"),
                description=plan_data.get("description"),
                position=max_position,
            )
            plan.set_features_from_text("\n".join(plan_data.get("features", [])))
            db.session.add(plan)
            changed = True
            continue

        desired_category = plan_data.get("category")
        if (
            plan.name == "Phone Service"
            and desired_category
            and plan.category != desired_category
        ):
            plan.category = desired_category
            changed = True

    if changed:
        db.session.commit()


def get_ordered_service_plan_categories() -> list[tuple[str, list[ServicePlan]]]:
    plans = (
        ServicePlan.query.order_by(
            ServicePlan.category.asc(),
            ServicePlan.position.asc(),
            ServicePlan.id.asc(),
        ).all()
    )
    categories: dict[str, list[ServicePlan]] = defaultdict(list)
    for plan in plans:
        categories[plan.category].append(plan)

    return sorted(
        categories.items(),
        key=lambda item: (
            PLAN_CATEGORY_ORDER.get(item[0], len(PLAN_CATEGORY_ORDER)),
            item[0],
        ),
    )


def build_plan_field_config(
    preselected_plan: str | None = None,
) -> list[dict[str, object]]:
    categorized_plans = {
        category: plans for category, plans in get_ordered_service_plan_categories()
    }
    config: list[dict[str, object]] = []
    for category, field_name, label in PLAN_FIELD_DEFINITIONS:
        plans = categorized_plans.get(category)
        if not plans:
            continue
        selected_name = (
            preselected_plan
            if preselected_plan
            and any(plan.name == preselected_plan for plan in plans)
            else ""
        )
        config.append(
            {
                "category": category,
                "field": field_name,
                "label": label,
                "plans": plans,
                "selected": selected_name,
            }
        )
    return config


def get_service_offerings() -> list[str]:
    plans = (
        ServicePlan.query.order_by(ServicePlan.position.asc(), ServicePlan.id.asc()).all()
    )
    if plans:
        return [plan.name for plan in plans]

    return [plan["name"] for plan in DEFAULT_SERVICE_PLANS]


def ensure_client_portal_fields() -> None:
    inspector = inspect(db.engine)
    columns = {column["name"] for column in inspector.get_columns("clients")}

    with db.engine.begin() as connection:
        if "portal_access_code" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN portal_access_code VARCHAR(64)")
            )
        if "portal_password_hash" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN portal_password_hash VARCHAR(255)")
            )
        if "portal_password_updated_at" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE clients ADD COLUMN portal_password_updated_at TIMESTAMP"
                )
            )
        if "account_reference" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN account_reference VARCHAR(24)")
            )
        if "phone" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN phone VARCHAR(40)")
            )
        if "residential_plan" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN residential_plan VARCHAR(120)")
            )
        if "phone_plan" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN phone_plan VARCHAR(120)")
            )
        if "business_plan" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN business_plan VARCHAR(120)")
            )
        if "wifi_router_needed" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN wifi_router_needed BOOLEAN DEFAULT 0 NOT NULL")
            )
        if "address" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN address VARCHAR(255)")
            )
        if "driver_license_number" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN driver_license_number VARCHAR(120)")
            )
        if "verification_photo_filename" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN verification_photo_filename VARCHAR(255)")
            )
        if "verification_photo_uploaded_at" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN verification_photo_uploaded_at TIMESTAMP")
            )

    ensure_billing_schema_once()

    clients_to_update = Client.query.all()

    updated = False
    for client in clients_to_update:
        if not client.portal_access_code:
            client.portal_access_code = generate_portal_password()
            updated = True
        if not client.account_reference:
            client.account_reference = generate_account_reference()
            updated = True
        if not client.portal_password_hash and client.portal_access_code:
            client.portal_password_hash = generate_password_hash(
                client.portal_access_code
            )
            client.portal_password_updated_at = utcnow()
            updated = True

    if updated:
        db.session.commit()


def ensure_appointment_technician_field() -> None:
    inspector = inspect(db.engine)
    columns = {column["name"] for column in inspector.get_columns("appointments")}

    if "technician_id" not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE appointments ADD COLUMN technician_id INTEGER")
            )


def ensure_support_ticket_priority_field() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {
            column["name"] for column in inspector.get_columns("support_tickets")
        }
    except NoSuchTableError:
        return

    if "priority" in columns:
        return

    with db.engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE support_tickets ADD COLUMN priority VARCHAR(20)"
                " DEFAULT 'Normal' NOT NULL"
            )
        )
        connection.execute(
            text(
                "UPDATE support_tickets SET priority = 'Normal' WHERE priority IS NULL"
            )
        )


def ensure_install_photo_requirements_seeded() -> None:
    inspector = inspect(db.engine)
    try:
        inspector.get_columns("install_photo_requirements")
    except NoSuchTableError:
        return

    if InstallPhotoRequirement.query.count() > 0:
        return

    for index, label in enumerate(DEFAULT_INSTALL_PHOTO_CATEGORIES):
        requirement = InstallPhotoRequirement(label=label, position=index)
        db.session.add(requirement)

    db.session.commit()


def ensure_technician_schedule_review_fields() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {column["name"] for column in inspector.get_columns("technician_schedule")}
    except NoSuchTableError:
        return

    statements: list[str] = []
    if "status" not in columns:
        statements.append(
            "ALTER TABLE technician_schedule ADD COLUMN status VARCHAR(20) DEFAULT 'pending'"
        )
    if "review_note" not in columns:
        statements.append("ALTER TABLE technician_schedule ADD COLUMN review_note TEXT")
    if "reviewed_at" not in columns:
        statements.append("ALTER TABLE technician_schedule ADD COLUMN reviewed_at TIMESTAMP")
    if "reviewed_by_id" not in columns:
        statements.append("ALTER TABLE technician_schedule ADD COLUMN reviewed_by_id INTEGER")
    if "cancel_requested_at" not in columns:
        statements.append(
            "ALTER TABLE technician_schedule ADD COLUMN cancel_requested_at TIMESTAMP"
        )

    if statements:
        with db.engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    if "status" not in columns:
        db.session.execute(
            text(
                "UPDATE technician_schedule SET status = 'approved' "
                "WHERE status IS NULL"
            )
        )
        db.session.commit()


def ensure_team_member_bio_field() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {column["name"] for column in inspector.get_columns("team_members")}
    except NoSuchTableError:
        return

    if "bio" in columns:
        return

    with db.engine.begin() as connection:
        connection.execute(text("ALTER TABLE team_members ADD COLUMN bio TEXT"))


def ensure_client_billing_fields() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {column["name"] for column in inspector.get_columns("clients")}
    except NoSuchTableError:
        return

    statements: list[str] = []
    if "autopay_enabled" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN autopay_enabled BOOLEAN DEFAULT 0 NOT NULL"
        )
    if "billing_status" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN billing_status VARCHAR(40)"
        )
    if "billing_status_updated_at" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN billing_status_updated_at TIMESTAMP"
        )
    if "service_suspended" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN service_suspended BOOLEAN DEFAULT 0 NOT NULL"
        )
    if "suspension_reason" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN suspension_reason VARCHAR(255)"
        )
    if "stripe_customer_id" not in columns:
        statements.append(
            "ALTER TABLE clients ADD COLUMN stripe_customer_id VARCHAR(64)"
        )

    if statements:
        with db.engine.begin() as connection:
            for stmt in statements:
                connection.execute(text(stmt))

    updated = False
    for client in Client.query.all():
        if not client.billing_status:
            client.billing_status = "Good Standing"
            updated = True
        if not client.billing_status_updated_at:
            client.billing_status_updated_at = utcnow()
            updated = True
        if client.service_suspended is None:
            client.service_suspended = False
            updated = True
    if updated:
        db.session.commit()


def ensure_invoice_payment_fields() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {column["name"] for column in inspector.get_columns("invoices")}
    except NoSuchTableError:
        return

    statements: list[str] = []
    if "paid_at" not in columns:
        statements.append(
            "ALTER TABLE invoices ADD COLUMN paid_at TIMESTAMP"
        )
    if "paid_via" not in columns:
        statements.append(
            "ALTER TABLE invoices ADD COLUMN paid_via VARCHAR(120)"
        )
    if "autopay_attempted_at" not in columns:
        statements.append(
            "ALTER TABLE invoices ADD COLUMN autopay_attempted_at TIMESTAMP"
        )
    if "autopay_status" not in columns:
        statements.append(
            "ALTER TABLE invoices ADD COLUMN autopay_status VARCHAR(40)"
        )

    if statements:
        with db.engine.begin() as connection:
            for stmt in statements:
                connection.execute(text(stmt))


def ensure_stripe_schema_once() -> None:
    global _stripe_schema_checked

    if _stripe_schema_checked:
        return

    ensure_stripe_billing_columns()

    _stripe_schema_checked = True


def ensure_stripe_billing_columns() -> None:
    inspector = inspect(db.engine)
    table_column_map = {
        "clients": {
            "stripe_customer_id": "ALTER TABLE clients ADD COLUMN stripe_customer_id VARCHAR(64)"
        },
        "payment_methods": {
            "stripe_payment_method_id": "ALTER TABLE payment_methods ADD COLUMN stripe_payment_method_id VARCHAR(64)"
        },
        "invoices": {
            "stripe_payment_intent_id": "ALTER TABLE invoices ADD COLUMN stripe_payment_intent_id VARCHAR(64)",
            "stripe_charge_id": "ALTER TABLE invoices ADD COLUMN stripe_charge_id VARCHAR(64)",
            "stripe_refund_id": "ALTER TABLE invoices ADD COLUMN stripe_refund_id VARCHAR(64)",
        },
        "autopay_events": {
            "stripe_payment_intent_id": "ALTER TABLE autopay_events ADD COLUMN stripe_payment_intent_id VARCHAR(64)",
            "stripe_event_id": "ALTER TABLE autopay_events ADD COLUMN stripe_event_id VARCHAR(64)",
        },
    }

    statements: list[str] = []
    for table, alterations in table_column_map.items():
        try:
            columns = {column["name"] for column in inspector.get_columns(table)}
        except NoSuchTableError:
            continue

        for column_name, statement in alterations.items():
            if column_name not in columns:
                statements.append(statement)

    if not statements:
        return

    with db.engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def ensure_billing_schema_once() -> None:
    """Ensure autopay-related columns exist without re-running repeatedly."""

    global _billing_schema_checked

    if not _billing_schema_checked:
        ensure_client_billing_fields()
        ensure_invoice_payment_fields()
        _billing_schema_checked = True

    ensure_stripe_schema_once()


def ensure_site_theme_background_fields() -> None:
    inspector = inspect(db.engine)
    try:
        columns = {column["name"] for column in inspector.get_columns("site_theme")}
    except NoSuchTableError:
        return

    alterations: list[str] = []
    if "background_image_filename" not in columns:
        alterations.append(
            "ALTER TABLE site_theme ADD COLUMN background_image_filename VARCHAR(255)"
        )
    if "background_image_original" not in columns:
        alterations.append(
            "ALTER TABLE site_theme ADD COLUMN background_image_original VARCHAR(255)"
        )

    if not alterations:
        return

    with db.engine.begin() as connection:
        for statement in alterations:
            connection.execute(text(statement))


def ensure_uisp_schema() -> None:
    inspector = inspect(db.engine)

    try:
        table_names = set(inspector.get_table_names())
    except Exception:  # pragma: no cover - safety guard
        table_names = set()

    if {"network_towers", "uisp_config"} - table_names:
        # Let SQLAlchemy create any newly introduced UISP-related tables.
        db.create_all()
        inspector = inspect(db.engine)

    try:
        device_columns = {
            column["name"] for column in inspector.get_columns("uisp_devices")
        }
    except NoSuchTableError:
        # The UISP device table does not exist yet; create_all will take care of it.
        db.create_all()
        return

    alterations: list[str] = []
    column_statements = {
        "nickname": "ALTER TABLE uisp_devices ADD COLUMN nickname VARCHAR(120)",
        "site_name": "ALTER TABLE uisp_devices ADD COLUMN site_name VARCHAR(120)",
        "ip_address": "ALTER TABLE uisp_devices ADD COLUMN ip_address VARCHAR(64)",
        "status": (
            "ALTER TABLE uisp_devices ADD COLUMN status VARCHAR(20) "
            "NOT NULL DEFAULT 'unknown'"
        ),
        "last_seen_at": "ALTER TABLE uisp_devices ADD COLUMN last_seen_at TIMESTAMP",
        "firmware_version": (
            "ALTER TABLE uisp_devices ADD COLUMN firmware_version VARCHAR(64)"
        ),
        "tower_id": "ALTER TABLE uisp_devices ADD COLUMN tower_id INTEGER",
        "notes": "ALTER TABLE uisp_devices ADD COLUMN notes TEXT",
        "outage_notified_at": (
            "ALTER TABLE uisp_devices ADD COLUMN outage_notified_at TIMESTAMP"
        ),
        "updated_at": "ALTER TABLE uisp_devices ADD COLUMN updated_at TIMESTAMP",
    }

    for column_name, statement in column_statements.items():
        if column_name not in device_columns:
            alterations.append(statement)

    if not alterations:
        return

    with db.engine.begin() as connection:
        for statement in alterations:
            connection.execute(text(statement))


def ensure_snmp_configuration() -> None:
    config = SNMPConfig.query.first()
    if config:
        return

    port_env = os.environ.get("SNMP_TRAP_PORT")
    try:
        port_value = int(port_env) if port_env else 162
    except (TypeError, ValueError):
        port_value = 162

    config = SNMPConfig(
        host=os.environ.get("SNMP_TRAP_HOST"),
        port=port_value,
        community=os.environ.get("SNMP_COMMUNITY", "public"),
        enterprise_oid=os.environ.get("SNMP_ENTERPRISE_OID", "1.3.6.1.4.1.8072.9999"),
        admin_email=os.environ.get("SNMP_ADMIN_EMAIL"),
    )
    db.session.add(config)
    db.session.commit()


def ensure_notification_configuration() -> NotificationConfig:
    inspector = inspect(db.engine)
    table_missing = False
    try:
        columns = {column["name"] for column in inspector.get_columns("notification_config")}
    except NoSuchTableError:
        columns = set()
        table_missing = True

    statements: list[str] = []
    if "reply_to_email" not in columns:
        statements.append(
            "ALTER TABLE notification_config ADD COLUMN reply_to_email VARCHAR(255)"
        )
    if "reply_to_name" not in columns:
        statements.append(
            "ALTER TABLE notification_config ADD COLUMN reply_to_name VARCHAR(255)"
        )
    if "list_unsubscribe_url" not in columns:
        statements.append(
            "ALTER TABLE notification_config ADD COLUMN list_unsubscribe_url VARCHAR(500)"
        )
    if "list_unsubscribe_mailto" not in columns:
        statements.append(
            "ALTER TABLE notification_config ADD COLUMN list_unsubscribe_mailto VARCHAR(500)"
        )
    if "notify_all_account_activity" not in columns:
        statements.append(
            "ALTER TABLE notification_config ADD COLUMN notify_all_account_activity BOOLEAN NOT NULL DEFAULT 1"
        )

    if statements and not table_missing:
        with db.engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    if table_missing:
        db.create_all()

    config = NotificationConfig.query.first()
    if config:
        return config

    config = NotificationConfig()
    db.session.add(config)
    db.session.commit()
    return config


def apply_stripe_config_from_database(app: Flask) -> StripeConfig:
    config = StripeConfig.query.first()

    def _clean(value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    if config is None:
        config = StripeConfig(
            secret_key=_clean(app.config.get("STRIPE_SECRET_KEY")),
            publishable_key=_clean(app.config.get("STRIPE_PUBLISHABLE_KEY")),
            webhook_secret=_clean(app.config.get("STRIPE_WEBHOOK_SECRET")),
        )
        db.session.add(config)
        db.session.commit()
    else:
        cleaned_secret = _clean(config.secret_key)
        cleaned_publishable = _clean(config.publishable_key)
        cleaned_webhook = _clean(config.webhook_secret)

        changed = False
        if config.secret_key != cleaned_secret:
            config.secret_key = cleaned_secret
            changed = True
        if config.publishable_key != cleaned_publishable:
            config.publishable_key = cleaned_publishable
            changed = True
        if config.webhook_secret != cleaned_webhook:
            config.webhook_secret = cleaned_webhook
            changed = True

        if changed:
            db.session.commit()

    app.config["STRIPE_SECRET_KEY"] = config.secret_key
    app.config["STRIPE_PUBLISHABLE_KEY"] = config.publishable_key
    app.config["STRIPE_WEBHOOK_SECRET"] = config.webhook_secret

    init_stripe(app)

    return config


def ensure_down_detector_configuration() -> None:
    config = DownDetectorConfig.query.first()
    if config:
        return

    config = DownDetectorConfig(target_url=None)
    db.session.add(config)
    db.session.commit()


def ensure_tls_configuration() -> None:
    config = TLSConfig.query.first()
    desired_path = current_app.config.get("TLS_CHALLENGE_FOLDER")
    if config is None:
        config = TLSConfig(challenge_path=desired_path)
        db.session.add(config)
        db.session.commit()
    elif desired_path and config.challenge_path != desired_path:
        config.challenge_path = desired_path
        db.session.commit()


def ensure_site_theme() -> None:
    theme = SiteTheme.query.first()
    if theme is None:
        theme = SiteTheme()
        db.session.add(theme)
        db.session.commit()
        return

    changed = False
    try:
        background = normalize_hex_color(theme.background_color)
    except ValueError:
        background = "#0e071a"
        theme.background_color = background
        changed = True

    text_color, muted_color = derive_theme_palette(background)
    if theme.text_color != text_color:
        theme.text_color = text_color
        changed = True
    if theme.muted_color != muted_color:
        theme.muted_color = muted_color
        changed = True

    if theme.background_image_filename:
        upload_folder = Path(current_app.config["THEME_UPLOAD_FOLDER"])
        file_path = upload_folder / theme.background_image_filename
        if not file_path.exists():
            theme.background_image_filename = None
            theme.background_image_original = None
            changed = True

    if changed:
        db.session.commit()


def get_effective_snmp_settings(app: Flask) -> dict[str, str | int | None]:
    settings: dict[str, str | int | None] = {
        "host": app.config.get("SNMP_TRAP_HOST"),
        "port": app.config.get("SNMP_TRAP_PORT", 162),
        "community": app.config.get("SNMP_COMMUNITY", "public"),
        "enterprise_oid": app.config.get("SNMP_ENTERPRISE_OID", "1.3.6.1.4.1.8072.9999"),
        "admin_email": app.config.get("SNMP_ADMIN_EMAIL"),
    }

    config = SNMPConfig.query.first()
    if config:
        if config.host:
            settings["host"] = config.host
        if config.port:
            settings["port"] = config.port
        if config.community:
            settings["community"] = config.community
        if config.enterprise_oid:
            settings["enterprise_oid"] = config.enterprise_oid
        if config.admin_email:
            settings["admin_email"] = config.admin_email

    return settings


def should_send_notification(category: str) -> bool:
    config = NotificationConfig.query.first()
    if config is None:
        return True

    normalized = category.lower()
    if normalized == "install":
        return config.notify_install_activity
    if normalized == "customer":
        return config.notify_customer_activity or config.notify_all_account_activity
    return config.notify_all_account_activity


def login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            if wants_json_response():
                return jsonify({"error": "Administrator login required."}), 401
            flash("Please log in to access the dashboard.", "warning")
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return wrapper


def client_login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        client_id = session.get(PORTAL_SESSION_KEY)
        if not client_id:
            if wants_json_response():
                return jsonify({"error": "Customer login required."}), 401
            flash("Please log in to access your account.", "warning")
            return redirect(url_for("portal_login", next=request.path))

        client = Client.query.get(client_id)
        if not client:
            session.pop(PORTAL_SESSION_KEY, None)
            if wants_json_response():
                return jsonify({"error": "Customer session expired."}), 401
            flash("We couldn't find that account. Please log in again.", "danger")
            return redirect(url_for("portal_login"))

        g.portal_client = client
        return func(client, *args, **kwargs)

    return wrapper


def technician_login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        technician_id = session.get(TECH_SESSION_KEY)
        if not technician_id:
            if wants_json_response():
                return jsonify({"error": "Technician login required."}), 401
            flash("Log in to access the technician portal.", "warning")
            return redirect(url_for("tech_login", next=request.path))

        technician = Technician.query.get(technician_id)
        if not technician or not technician.is_active:
            session.pop(TECH_SESSION_KEY, None)
            if wants_json_response():
                return jsonify({"error": "Technician session expired."}), 401
            flash("Your technician account is unavailable. Please contact dispatch.", "danger")
            return redirect(url_for("tech_login"))

        g.technician = technician
        return func(technician, *args, **kwargs)

    return wrapper


def invalidate_site_shell_cache(app: Flask | None = None) -> None:
    target_app = app
    if target_app is None:
        try:
            target_app = current_app._get_current_object()
        except RuntimeError:
            target_app = None

    if target_app is None:
        return

    target_app.config.pop(SITE_SHELL_CACHE_KEY, None)


def invalidate_dashboard_overview_cache(app: Flask | None = None) -> None:
    target_app = app
    if target_app is None:
        try:
            target_app = current_app._get_current_object()
        except RuntimeError:
            target_app = None

    if target_app is None:
        return

    target_app.config.pop(DASHBOARD_OVERVIEW_CACHE_KEY, None)


def get_site_shell_snapshot(app: Flask) -> dict[str, object]:
    ttl_seconds = float(
        app.config.get("SITE_SHELL_CACHE_SECONDS", SITE_SHELL_CACHE_SECONDS_DEFAULT)
    )
    now = time.monotonic()
    cached = app.config.get(SITE_SHELL_CACHE_KEY)

    if cached and cached.get("expires_at", 0) > now:
        return cached["payload"]

    navigation_items = [
        SimpleNamespace(
            label=item.label,
            url=item.url,
            open_in_new_tab=bool(item.open_in_new_tab),
        )
        for item in NavigationItem.query.order_by(NavigationItem.position.asc()).all()
    ]

    branding_assets = {
        asset.asset_type: SimpleNamespace(
            asset_type=asset.asset_type,
            original_filename=asset.original_filename,
            uploaded_at=asset.uploaded_at,
        )
        for asset in BrandingAsset.query.all()
    }

    down_detector = DownDetectorConfig.query.first()
    down_detector_snapshot = None
    if down_detector:
        down_detector_snapshot = SimpleNamespace(
            target_url=down_detector.target_url,
            updated_at=down_detector.updated_at,
        )

    service_offerings = get_service_offerings()
    plan_categories = [
        category
        for category, _plans in get_ordered_service_plan_categories()
        if category
    ]

    site_theme = SiteTheme.query.first()
    if site_theme is None:
        site_theme_snapshot = SimpleNamespace(
            background_color="#0e071a",
            text_color="#f5f3ff",
            muted_color="#b5a6d8",
            background_image_filename=None,
            background_image_original=None,
        )
    else:
        site_theme_snapshot = SimpleNamespace(
            background_color=site_theme.background_color,
            text_color=site_theme.text_color,
            muted_color=site_theme.muted_color,
            background_image_filename=site_theme.background_image_filename,
            background_image_original=site_theme.background_image_original,
        )

    payload = {
        "navigation_items": navigation_items,
        "branding_assets": branding_assets,
        "service_offerings": service_offerings,
        "plan_categories": plan_categories,
        "site_theme": site_theme_snapshot,
        "down_detector_config": down_detector_snapshot,
    }

    app.config[SITE_SHELL_CACHE_KEY] = {
        "payload": payload,
        "expires_at": now + ttl_seconds,
    }
    return payload


def get_dashboard_overview_snapshot(app: Flask) -> dict[str, object]:
    ttl_seconds = float(
        app.config.get(
            "DASHBOARD_OVERVIEW_CACHE_SECONDS",
            DASHBOARD_OVERVIEW_CACHE_SECONDS_DEFAULT,
        )
    )
    now_monotonic = time.monotonic()
    cached = app.config.get(DASHBOARD_OVERVIEW_CACHE_KEY)

    if cached and cached.get("expires_at", 0) > now_monotonic:
        return cached["payload"]

    start_of_week = utcnow() - timedelta(days=7)
    total_clients = Client.query.count()
    new_this_week = Client.query.filter(Client.created_at >= start_of_week).count()
    outstanding_amount_cents = (
        db.session.query(db.func.coalesce(db.func.sum(Invoice.amount_cents), 0))
        .filter(~Invoice.status.in_(["Paid", "Cancelled"]))
        .scalar()
    )
    open_ticket_total = (
        db.session.query(db.func.count(SupportTicket.id))
        .filter(SupportTicket.status.in_(["Open", "In Progress"]))
        .scalar()
    )
    active_clients = Client.query.filter_by(status="Active").count()
    onboarding_clients = (
        Client.query.filter(Client.status.in_(["New", "In Review"]))
        .count()
    )
    clients_without_password = (
        Client.query.filter(Client.portal_password_hash.is_(None)).count()
    )
    pending_invoices_total = (
        Invoice.query.filter(Invoice.status.in_(["Pending", "Overdue"]))
        .count()
    )
    overdue_amount_cents = (
        db.session.query(db.func.coalesce(db.func.sum(Invoice.amount_cents), 0))
        .filter(Invoice.status == "Overdue")
        .scalar()
    )
    equipment_total = Equipment.query.count()
    network_new_this_week = (
        Equipment.query.filter(Equipment.created_at >= start_of_week).count()
    )
    clients_with_equipment = (
        db.session.query(db.func.count(db.func.distinct(Equipment.client_id))).scalar()
        or 0
    )
    support_created_this_week = (
        SupportTicket.query.filter(SupportTicket.created_at >= start_of_week).count()
    )
    support_updates = (
        SupportTicket.query.filter(SupportTicket.updated_at >= start_of_week).count()
    )
    billing_invoices_created = (
        Invoice.query.filter(Invoice.created_at >= start_of_week).count()
    )

    upcoming_statuses = ["Pending", "Confirmed", "Reschedule Requested"]
    now = utcnow()
    appointments_total = Appointment.query.count()
    upcoming_appointments_count = (
        Appointment.query.filter(
            Appointment.status.in_(upcoming_statuses),
            Appointment.scheduled_for >= now - timedelta(days=1),
        ).count()
    )
    pending_appointments = (
        Appointment.query.filter_by(status="Pending").count()
    )
    reschedule_requests = (
        Appointment.query.filter_by(status="Reschedule Requested").count()
    )
    appointments_created_this_week = (
        Appointment.query.filter(Appointment.created_at >= start_of_week).count()
    )

    upcoming_appointments_list = (
        Appointment.query.options(joinedload(Appointment.client))
        .filter(Appointment.status.in_(upcoming_statuses))
        .order_by(Appointment.scheduled_for.asc())
        .limit(5)
        .all()
    )

    recent_clients = (
        Client.query.order_by(Client.created_at.desc()).limit(5).all()
    )
    recent_invoices = (
        Invoice.query.options(joinedload(Invoice.client))
        .order_by(Invoice.created_at.desc())
        .limit(5)
        .all()
    )
    recent_equipment = (
        Equipment.query.options(joinedload(Equipment.client))
        .order_by(Equipment.created_at.desc())
        .limit(5)
        .all()
    )
    recent_tickets = (
        SupportTicket.query.options(joinedload(SupportTicket.client))
        .order_by(SupportTicket.created_at.desc())
        .limit(5)
        .all()
    )

    def _client_namespace(client: Client | None) -> SimpleNamespace | None:
        if client is None:
            return None
        return SimpleNamespace(name=client.name)

    overview_payload = {
        "total_clients": total_clients,
        "new_this_week": new_this_week,
        "outstanding_amount_cents": outstanding_amount_cents,
        "open_ticket_total": open_ticket_total,
        "active_clients": active_clients,
        "onboarding_clients": onboarding_clients,
        "clients_without_password": clients_without_password,
        "pending_invoices_total": pending_invoices_total,
        "overdue_amount_cents": overdue_amount_cents,
        "equipment_total": equipment_total,
        "network_new_this_week": network_new_this_week,
        "clients_with_equipment": clients_with_equipment,
        "support_created_this_week": support_created_this_week,
        "support_updates": support_updates,
        "billing_invoices_created": billing_invoices_created,
        "appointments_total": appointments_total,
        "pending_appointments": pending_appointments,
        "upcoming_appointments_count": upcoming_appointments_count,
        "reschedule_requests": reschedule_requests,
        "appointments_created_this_week": appointments_created_this_week,
        "recent_clients": [
            SimpleNamespace(
                name=client.name,
                created_at=client.created_at,
                status=client.status,
                service_summary=client.service_summary,
            )
            for client in recent_clients
        ],
        "recent_invoices": [
            SimpleNamespace(
                description=invoice.description,
                status=invoice.status,
                amount_cents=invoice.amount_cents,
                client=_client_namespace(invoice.client),
            )
            for invoice in recent_invoices
        ],
        "recent_equipment": [
            SimpleNamespace(
                name=device.name,
                created_at=device.created_at,
                model=device.model,
                client=_client_namespace(device.client),
            )
            for device in recent_equipment
        ],
        "upcoming_appointments": [
            SimpleNamespace(
                title=appointment.title,
                status=appointment.status,
                scheduled_for=appointment.scheduled_for,
                client=_client_namespace(appointment.client),
            )
            for appointment in upcoming_appointments_list
        ],
        "recent_tickets": [
            SimpleNamespace(
                subject=ticket.subject,
                status=ticket.status,
                updated_at=ticket.updated_at,
                client=_client_namespace(ticket.client),
            )
            for ticket in recent_tickets
        ],
    }

    overview_payload["operations_snapshot"] = [
        {
            "key": "customers",
            "title": "Customers",
            "description": "Growth and onboarding momentum across your service area.",
            "metrics": [
                {"label": "Total Clients", "value": total_clients},
                {"label": "Active Clients", "value": active_clients},
                {"label": "Onboarding", "value": onboarding_clients},
                {
                    "label": "Passwords Pending",
                    "value": clients_without_password,
                },
            ],
            "footer": f"{new_this_week} new signups this week",
        },
        {
            "key": "network",
            "title": "Network",
            "description": "Hardware deployed to keep customers online.",
            "metrics": [
                {"label": "Devices Online", "value": equipment_total},
                {"label": "Clients With Gear", "value": clients_with_equipment},
                {
                    "label": "Upcoming Visits",
                    "value": upcoming_appointments_count,
                },
                {
                    "label": "Reschedule Requests",
                    "value": reschedule_requests,
                },
            ],
            "footer": (
                f"{appointments_created_this_week} appointments scheduled this week • "
                f"{network_new_this_week} installs logged"
            ),
        },
        {
            "key": "support",
            "title": "Support",
            "description": "Ticket activity from your subscribers.",
            "metrics": [
                {"label": "Open Tickets", "value": open_ticket_total},
                {"label": "New Tickets", "value": support_created_this_week},
                {"label": "Updates This Week", "value": support_updates},
            ],
            "footer": f"{support_updates} tickets touched this week",
        },
        {
            "key": "billing",
            "title": "Billing",
            "description": "Cash flow indicators and invoice workload.",
            "metrics": [
                {
                    "label": "Outstanding Balance",
                    "value": outstanding_amount_cents,
                    "format": "currency",
                },
                {
                    "label": "Overdue Balance",
                    "value": overdue_amount_cents,
                    "format": "currency",
                },
                {
                    "label": "Pending Invoices",
                    "value": pending_invoices_total,
                },
                {
                    "label": "Invoices This Week",
                    "value": billing_invoices_created,
                },
            ],
            "footer": f"{billing_invoices_created} invoices posted this week",
        },
    ]

    app.config[DASHBOARD_OVERVIEW_CACHE_KEY] = {
        "payload": overview_payload,
        "expires_at": now_monotonic + ttl_seconds,
    }

    return overview_payload


def _site_shell_cache_invalidator(mapper, connection, target):  # noqa: ARG001
    invalidate_site_shell_cache()


def _dashboard_overview_cache_invalidator(mapper, connection, target):  # noqa: ARG001
    invalidate_dashboard_overview_cache()


for model in (
    NavigationItem,
    BrandingAsset,
    SiteTheme,
    ServicePlan,
    DownDetectorConfig,
):
    for event_name in ("after_insert", "after_update", "after_delete"):
        event.listen(model, event_name, _site_shell_cache_invalidator)

for model in (
    Client,
    Invoice,
    SupportTicket,
    Equipment,
    Appointment,
    InstallPhoto,
):
    for event_name in ("after_insert", "after_update", "after_delete"):
        event.listen(model, event_name, _dashboard_overview_cache_invalidator)


def register_routes(app: Flask) -> None:
    def _resolve_document(doc_type: str):
        if doc_type not in LEGAL_DOCUMENT_TYPES:
            abort(404)

        document = Document.query.filter_by(doc_type=doc_type).first()
        if not document:
            abort(404)

        upload_folder = Path(app.config["LEGAL_UPLOAD_FOLDER"])
        file_path = upload_folder / document.stored_filename

        if not file_path.exists():
            abort(404)

        return document, upload_folder, file_path

    def _get_uisp_config() -> UispConfig | None:
        return UispConfig.query.order_by(UispConfig.id.asc()).first()

    def _resolve_uisp_credentials() -> tuple[str | None, str | None, UispConfig | None]:
        config = _get_uisp_config()
        base_url = (config.base_url or "").strip() if config else ""
        api_token = (config.api_token or "").strip() if config else ""
        if not base_url:
            base_url = (app.config.get("UISP_BASE_URL") or "").strip()
        if not api_token:
            api_token = (app.config.get("UISP_API_TOKEN") or "").strip()
        return base_url or None, api_token or None, config

    def _build_uisp_client() -> UispApiClient:
        timeout_value = app.config.get("UISP_API_TIMEOUT", 10.0)
        try:
            timeout = float(timeout_value)
        except (TypeError, ValueError):
            timeout = 10.0
        base_url, api_token, _ = _resolve_uisp_credentials()
        return UispApiClient(base_url or "", api_token or "", timeout=timeout)

    def _collect_outage_recipients(device: UispDevice) -> list[str]:
        recipients: set[str] = set()
        if device.client and device.client.email:
            recipients.add(device.client.email)
        admin_email = (app.config.get("ADMIN_EMAIL") or "").strip()
        if admin_email:
            recipients.add(admin_email)
        snmp_admin = (app.config.get("SNMP_ADMIN_EMAIL") or "").strip()
        if snmp_admin:
            recipients.add(snmp_admin)
        for technician in Technician.query.filter_by(is_active=True).all():
            if technician.email:
                recipients.add(technician.email)
        return sorted(recipients)

    def _format_last_seen(timestamp: datetime | None) -> str:
        if not timestamp:
            return "Unknown"
        return timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M %Z")

    def dispatch_notification(
        recipient: str, subject: str, body: str, category: str = "general"
    ) -> bool:
        if not recipient:
            return False

        if should_send_notification(category):
            if send_email_via_office365(app, recipient, subject, body):
                return True
        else:
            return False

        sender = app.config.get("SNMP_EMAIL_SENDER")
        if callable(sender):
            try:
                return bool(sender(recipient, subject, body))
            except Exception as exc:  # pragma: no cover - defensive guard
                app.logger.warning("Custom SNMP email sender failed: %s", exc)
                return False

        return send_email_via_snmp(app, recipient, subject, body)

    @app.template_filter("currency")
    def format_currency(value: int | float | Decimal | None):
        if value is None:
            return "$0.00"
        cents = int(value)
        dollars = Decimal(cents) / Decimal(100)
        return f"${dollars:,.2f}"

    @app.template_filter("cents_to_dollars")
    def cents_to_dollars(value: int | None):
        if value is None:
            return "0.00"
        cents = int(value)
        dollars = Decimal(cents) / Decimal(100)
        return f"{dollars:.2f}"

    @app.template_filter("date_or_dash")
    def format_date(value: date | None):
        if not value:
            return "—"
        return value.strftime("%b %d, %Y")

    @app.before_request
    def ensure_billing_schema():
        ensure_billing_schema_once()

    @app.context_processor
    def inject_status_options():
        snapshot = get_site_shell_snapshot(app)
        support_urls = {
            url_for("support"),
            url_for("uptime"),
            url_for("service_cancellation"),
            url_for("down_detector"),
        }
        navigation_items = [
            item
            for item in snapshot["navigation_items"]
            if item.url not in support_urls
        ]
        branding_assets = snapshot["branding_assets"]
        down_detector_config = snapshot["down_detector_config"]
        contact_email = app.config.get(
            "CONTACT_EMAIL", "info@dixielandwireless.com"
        )
        contact_phone_raw = app.config.get("CONTACT_PHONE", "2053343969")
        phone_display, phone_href = normalize_phone_number(contact_phone_raw)
        if not phone_display:
            phone_display = contact_phone_raw
        if not phone_href:
            phone_href = f"tel:{contact_phone_raw}" if contact_phone_raw else None
        support_links = [
            {
                "label": "Contact Support",
                "url": f"mailto:{contact_email}",
                "external": True,
            },
            {
                "label": "Call Support",
                "url": phone_href if phone_href else "tel:2053343969",
                "external": True,
            },
            {"label": "Support Center", "url": url_for("support"), "external": False},
            {"label": "Uptime Status", "url": url_for("uptime"), "external": False},
            {
                "label": "Service Cancellation",
                "url": url_for("service_cancellation"),
                "external": False,
            },
            {
                "label": "Down Detector",
                "url": url_for("down_detector"),
                "external": bool(
                    down_detector_config and down_detector_config.target_url
                ),
            },
        ]

        service_offerings = snapshot["service_offerings"]
        plan_category_links = [
            {
                "label": f"{category} Plans",
                "url": f"{url_for('service_plans')}#plans-{slugify_segment(category)}",
            }
            for category in snapshot["plan_categories"]
        ]

        site_theme = snapshot["site_theme"]

        return {
            "status_options": STATUS_OPTIONS,
            "current_year": utcnow().year,
            "legal_document_types": LEGAL_DOCUMENT_TYPES,
            "navigation_items": navigation_items,
            "branding_assets": branding_assets,
            "branding_asset_types": BRANDING_ASSET_TYPES,
            "invoice_status_options": INVOICE_STATUS_OPTIONS,
            "ticket_status_options": TICKET_STATUS_OPTIONS,
            "service_offerings": service_offerings,
            "appointment_status_options": APPOINTMENT_STATUS_OPTIONS,
            "contact_email": contact_email,
            "contact_phone": contact_phone_raw,
            "contact_phone_display": phone_display,
            "contact_phone_href": phone_href,
            "support_links": support_links,
            "down_detector_config": down_detector_config,
            "plan_category_links": plan_category_links,
            "site_theme": site_theme,
        }

    @app.route("/.well-known/acme-challenge/<token>")
    def acme_http_challenge(token: str):
        if "/" in token or "\\" in token or token.startswith("."):
            abort(404)

        challenge_dir = Path(app.config["TLS_CHALLENGE_FOLDER"])
        file_path = challenge_dir / token
        if not file_path.exists():
            abort(404)
        return send_site_file("acme-challenge", challenge_dir, token)

    @app.route("/")
    def index():
        trusted_businesses = (
            TrustedBusiness.query.order_by(
                TrustedBusiness.position.asc(), TrustedBusiness.id.asc()
            )
            .limit(12)
            .all()
        )
        support_partners = (
            SupportPartner.query.order_by(
                SupportPartner.position.asc(), SupportPartner.id.asc()
            )
            .limit(9)
            .all()
        )
        return render_template(
            "index.html",
            trusted_businesses=trusted_businesses,
            support_partners=support_partners,
        )

    @app.route("/services")
    def service_plans():
        ordered_categories = get_ordered_service_plan_categories()

        return render_template("service_plans.html", plans_by_category=ordered_categories)

    @app.route("/phone-service")
    def phone_service():
        plans = (
            ServicePlan.query.filter_by(category="Phone Service")
            .order_by(ServicePlan.position.asc(), ServicePlan.id.asc())
            .all()
        )
        return render_template("phone_service.html", plans=plans)

    @app.route("/about")
    def about():
        team_members = (
            TeamMember.query.order_by(TeamMember.position.asc(), TeamMember.id.asc())
            .all()
        )
        return render_template("about.html", team_members=team_members)

    @app.route("/support")
    def support():
        return render_template("support.html")

    @app.route("/uptime")
    def uptime():
        uptime_metrics = {
            "current_status": "Operational",
            "uptime_30": "99.982%",
            "uptime_90": "99.965%",
            "next_window": "June 15, 10:00 PM - 12:00 AM",
        }
        incidents = [
            {
                "title": "Scheduled tower maintenance",
                "date": "May 20",
                "status": "Completed",
                "summary": (
                    "Preventative maintenance on Sector 3 tower. Customers experienced"
                    " brief interruptions overnight."
                ),
            },
            {
                "title": "Fiber backhaul interruption",
                "date": "April 04",
                "status": "Resolved",
                "summary": "Carrier fiber splice caused packet loss for south region subscribers.",
            },
        ]
        return render_template(
            "uptime.html", uptime_metrics=uptime_metrics, incidents=incidents
        )

    @app.route("/cancellation")
    def service_cancellation():
        return render_template("cancellation.html")

    @app.route("/status/down-detector")
    def down_detector():
        config = DownDetectorConfig.query.first()
        if config and config.target_url:
            return redirect(config.target_url)
        return render_template("down_detector.html")

    @app.route("/blog")
    def blog():
        posts = (
            BlogPost.query.filter_by(is_published=True)
            .order_by(BlogPost.published_at.desc(), BlogPost.created_at.desc())
            .all()
        )
        return render_template("blog.html", posts=posts)

    @app.route("/blog/<slug>")
    def blog_post(slug: str):
        post = BlogPost.query.filter_by(slug=slug).first_or_404()

        if not post.is_published and not session.get("admin_authenticated"):
            abort(404)

        return render_template("blog_post.html", post=post)

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        selected_plan = request.args.get("plan", "").strip()
        if request.method == "POST":
            ensure_file_surface_enabled("signup-verification")
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            company = request.form.get("company", "").strip()
            phone = request.form.get("phone", "").strip()
            address = request.form.get("address", "").strip()
            service_plan = request.form.get("service_plan", "").strip()
            wants_residential = is_truthy(request.form.get("wants_residential"))
            wants_business = is_truthy(request.form.get("wants_business"))
            wants_phone = request.form.get("wants_phone", "no").strip().lower() == "yes"
            wifi_router_needed = (
                request.form.get("wifi_router_needed", "no").strip().lower() == "yes"
            )
            residential_plan = request.form.get("residential_plan", "").strip()
            phone_plan = request.form.get("phone_plan", "").strip()
            business_plan = request.form.get("business_plan", "").strip()
            notes = request.form.get("notes", "").strip()
            driver_license_number = request.form.get("driver_license_number", "").strip()
            password = request.form.get("password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            verification_file = request.files.get("verification_photo")

            if not name or not email:
                flash("Name and email are required.", "danger")
                return redirect(url_for("signup"))

            if not phone:
                flash("A contact phone number is required.", "danger")
                return redirect(url_for("signup"))

            if not address:
                flash("Please provide the service address for your installation.", "danger")
                return redirect(url_for("signup"))

            if not driver_license_number:
                flash("Share your driver's license number so we can verify your account.", "danger")
                return redirect(url_for("signup"))

            if not password:
                flash("Create a portal password to finish your signup.", "danger")
                return redirect(url_for("signup"))

            if len(password) < 8:
                flash("Portal passwords must be at least 8 characters long.", "danger")
                return redirect(url_for("signup"))

            if password != confirm_password:
                flash("Passwords do not match. Please try again.", "danger")
                return redirect(url_for("signup"))

            if not verification_file or not verification_file.filename:
                flash(
                    "Upload a photo or scan of your identification so we can verify service eligibility.",
                    "danger",
                )
                return redirect(url_for("signup"))

            if not allowed_verification_file(verification_file.filename):
                flash("Upload a JPG, PNG, HEIC, or PDF file for verification.", "danger")
                return redirect(url_for("signup"))

            existing = Client.query.filter_by(email=email).first()
            if existing:
                flash("This email address has already been registered.", "warning")
                return redirect(url_for("signup"))

            if not wants_residential:
                residential_plan = ""
            if not wants_business:
                business_plan = ""
            if not wants_phone:
                phone_plan = ""

            if wants_residential and not residential_plan:
                flash("Select a residential plan to continue.", "danger")
                return redirect(url_for("signup"))

            if wants_business and not business_plan:
                flash("Select a business plan to continue.", "danger")
                return redirect(url_for("signup"))

            if wants_phone and not phone_plan:
                flash("Select a phone service plan to continue.", "danger")
                return redirect(url_for("signup"))

            selected_services = [
                value
                for value in (residential_plan, phone_plan, business_plan)
                if value
            ]
            plan_summary = ", ".join(selected_services) if selected_services else service_plan

            client = Client(
                name=name,
                email=email,
                phone=phone or None,
                address=address or None,
                company=company or None,
                project_type=plan_summary or None,
                residential_plan=residential_plan or None,
                phone_plan=phone_plan or None,
                business_plan=business_plan or None,
                notes=notes or None,
                driver_license_number=driver_license_number or None,
                wifi_router_needed=wifi_router_needed,
            )
            client.portal_password_hash = generate_password_hash(password)
            client.portal_password_updated_at = utcnow()
            db.session.add(client)
            db.session.commit()

            if verification_file and verification_file.filename:
                store_client_verification_photo(app, client, verification_file)
                db.session.commit()

            session[PORTAL_SESSION_KEY] = client.id
            session["portal_authenticated_at"] = utcnow().isoformat()

            flash("Account created! You're signed in to the customer portal.", "success")
            return redirect(url_for("portal_dashboard"))

        plan_field_config = build_plan_field_config(selected_plan)
        plan_fields = {field["field"]: field for field in plan_field_config}
        return render_template(
            "signup.html",
            preselected_plan=selected_plan,
            plan_field_config=plan_field_config,
            residential_field=plan_fields.get("residential_plan"),
            phone_field=plan_fields.get("phone_plan"),
            business_field=plan_fields.get("business_plan"),
        )

    @app.route("/thank-you")
    def thank_you():
        return render_template("thank_you.html")

    @app.route("/portal/login", methods=["GET", "POST"])
    def portal_login():
        if session.get(PORTAL_SESSION_KEY):
            existing_client = Client.query.get(session[PORTAL_SESSION_KEY])
            if existing_client:
                return redirect(url_for("portal_dashboard"))

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "").strip()

            client_record = Client.query.filter_by(email=email).first()
            if client_record and not client_record.portal_password_hash:
                flash(
                    "Your portal password has not been issued yet. Please contact support.",
                    "warning",
                )
            elif (
                client_record
                and password
                and client_record.portal_password_hash
                and check_password_hash(client_record.portal_password_hash, password)
            ):
                session[PORTAL_SESSION_KEY] = client_record.id
                session["portal_authenticated_at"] = utcnow().isoformat()
                flash("Welcome to your customer portal!", "success")
                redirect_target = request.args.get("next") or url_for("portal_dashboard")
                return redirect(redirect_target)

            else:
                flash("Invalid email or password. Please try again.", "danger")

        return render_template("portal_login.html")

    @app.get("/portal/logout")
    def portal_logout():
        session.pop(PORTAL_SESSION_KEY, None)
        session.pop("portal_authenticated_at", None)
        flash("You have been logged out of the customer portal.", "info")
        return redirect(url_for("portal_login"))

    @app.route("/portal")
    @client_login_required
    def portal_dashboard(client: Client):
        invoices = (
            Invoice.query.filter_by(client_id=client.id)
            .order_by(Invoice.due_date.asc())
            .all()
        )
        equipment_items = (
            Equipment.query.filter_by(client_id=client.id)
            .order_by(Equipment.installed_on.asc())
            .all()
        )
        tickets = (
            SupportTicket.query.filter_by(client_id=client.id)
            .order_by(SupportTicket.created_at.desc())
            .all()
        )
        appointments = (
            Appointment.query.filter_by(client_id=client.id)
            .order_by(Appointment.scheduled_for.asc())
            .all()
        )

        outstanding_invoices = [
            invoice for invoice in invoices if invoice.status not in {"Paid", "Cancelled"}
        ]
        total_due_cents = sum(invoice.amount_cents for invoice in outstanding_invoices)
        upcoming_due_date = None
        dated_invoices = [
            invoice.due_date
            for invoice in outstanding_invoices
            if invoice.due_date is not None
        ]
        if dated_invoices:
            upcoming_due_date = min(dated_invoices)

        open_ticket_count = sum(
            1 for ticket in tickets if ticket.status in {"Open", "In Progress"}
        )

        selected_services = [
            plan
            for plan in (
                client.residential_plan,
                client.phone_plan,
                client.business_plan,
            )
            if plan
        ]

        return render_template(
            "portal_dashboard.html",
            client=client,
            invoices=invoices,
            equipment_items=equipment_items,
            tickets=tickets,
            appointments=appointments,
            total_due_cents=total_due_cents,
            upcoming_due_date=upcoming_due_date,
            open_ticket_count=open_ticket_count,
            selected_services=selected_services,
            ticket_priority_options=TICKET_PRIORITY_OPTIONS,
            payment_methods=client.payment_methods,
            stripe_publishable_key=current_app.config.get("STRIPE_PUBLISHABLE_KEY"),
            stripe_ready=stripe_active(),
        )

    @app.post("/portal/payment-methods")
    @client_login_required
    def portal_add_payment_method(client: Client):
        if not stripe_active():
            return (
                jsonify({"error": "Card management requires Stripe configuration."}),
                400,
            )

        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        payment_method_id_raw = payload.get("payment_method_id")
        if payment_method_id_raw is None:
            payment_method_id_raw = request.form.get("payment_method_id", "")
        payment_method_id = (payment_method_id_raw or "").strip()
        if "set_default" in payload:
            set_default_flag = payload.get("set_default")
        else:
            set_default_flag = request.form.get("set_default")
        set_default = is_truthy(set_default_flag) or not client.payment_methods

        if not payment_method_id:
            return jsonify({"error": "Missing Stripe payment method id."}), 400

        try:
            method = sync_stripe_payment_method(
                client,
                payment_method_id,
                set_default=set_default,
            )
        except StripeError as error:
            db.session.rollback()
            return jsonify({"error": describe_stripe_error(error)}), 400
        except IntegrityError as error:
            db.session.rollback()
            current_app.logger.exception(
                "Failed to save Stripe payment method for client %s", client.id
            )
            return (
                jsonify(
                    {
                        "error": (
                            "We couldn't save that card. Please try again "
                            "or contact support."
                        )
                    }
                ),
                400,
            )
        except Exception as error:  # pragma: no cover - defensive catch-all
            db.session.rollback()
            current_app.logger.exception(
                "Unexpected error while saving payment method for client %s",
                client.id,
            )
            return (
                jsonify(
                    {
                        "error": (
                            "Something went wrong while saving your card. "
                            "Please try again."
                        )
                    }
                ),
                500,
            )

        db.session.commit()

        return (
            jsonify(
                {
                    "status": "ok",
                    "method": {
                        "id": method.id,
                        "brand": method.brand,
                        "last4": method.last4,
                        "exp_month": method.exp_month,
                        "exp_year": method.exp_year,
                        "cardholder_name": method.cardholder_name,
                        "is_default": method.is_default,
                    },
                }
            ),
            200,
        )

    @app.get("/portal/payment-methods/setup-intent")
    @client_login_required
    def portal_setup_intent(client: Client):
        if not stripe_active():
            return (
                jsonify({"error": "Stripe is not configured."}),
                400,
            )

        customer_id = ensure_stripe_customer(client)
        if customer_id is None:
            return (
                jsonify({"error": "Unable to prepare Stripe customer."}),
                400,
            )

        setup_intent = stripe.SetupIntent.create(
            customer=customer_id,
            usage="off_session",
            payment_method_types=["card"],
            metadata={"client_id": str(client.id)},
        )

        return jsonify({"client_secret": setup_intent.client_secret})

    @app.post("/portal/autopay")
    @client_login_required
    def portal_autopay(client: Client):
        action = (request.form.get("action") or "enable").strip().lower()

        if action == "disable":
            client.autopay_enabled = False
            if stripe_active():
                try:
                    customer_id = ensure_stripe_customer(client)
                    if customer_id:
                        stripe.Customer.modify(
                            customer_id,
                            invoice_settings={"default_payment_method": None},
                        )
                except StripeError:
                    pass
            db.session.commit()
            flash("Autopay has been disabled. Future invoices must be paid manually.", "info")
            return redirect(url_for("portal_dashboard"))

        if not stripe_active():
            flash("Autopay is unavailable until Stripe is configured.", "danger")
            return redirect(url_for("portal_dashboard"))

        method_id = request.form.get("payment_method_id", type=int)
        if method_id:
            method = PaymentMethod.query.filter_by(
                id=method_id, client_id=client.id
            ).first()
        else:
            method = client.default_payment_method()

        if method is None or not method.token or not method.token.startswith("pm_"):
            flash("Save a Stripe card before enabling autopay.", "danger")
            return redirect(url_for("portal_dashboard"))

        for other in client.payment_methods:
            other.is_default = other.id == method.id
        client.autopay_enabled = True

        try:
            customer_id = ensure_stripe_customer(client)
            if customer_id:
                stripe.Customer.modify(
                    customer_id,
                    invoice_settings={"default_payment_method": method.token},
                )
        except StripeError as error:
            db.session.rollback()
            flash(
                f"Stripe could not enable autopay: {describe_stripe_error(error)}",
                "danger",
            )
            return redirect(url_for("portal_dashboard"))

        db.session.commit()
        flash("Autopay is now enabled. Upcoming invoices will charge your saved card.", "success")
        return redirect(url_for("portal_dashboard"))

    @app.get("/portal/invoices/<int:invoice_id>/pay")
    @client_login_required
    def portal_pay_invoice(client: Client, invoice_id: int):
        invoice = (
            Invoice.query.filter_by(id=invoice_id, client_id=client.id).first()
        )
        if invoice is None:
            flash("We couldn't find that invoice.", "danger")
            return redirect(url_for("portal_dashboard"))

        if invoice.status == "Paid":
            flash("This invoice has already been paid.", "info")
            return redirect(url_for("portal_dashboard"))

        if not stripe_active():
            flash("Online payments are unavailable right now. Please contact support.", "danger")
            return redirect(url_for("portal_dashboard"))

        try:
            payment_intent = ensure_invoice_payment_intent(
                invoice,
                autopay=False,
                client=client,
            )
        except StripeError as error:
            db.session.rollback()
            flash(
                f"We couldn't start the payment: {describe_stripe_error(error)}",
                "danger",
            )
            return redirect(url_for("portal_dashboard"))

        if payment_intent is None:
            flash("Payment processing is offline at the moment.", "danger")
            return redirect(url_for("portal_dashboard"))

        db.session.commit()

        return render_template(
            "portal_payment.html",
            client=client,
            invoice=invoice,
            payment_intent_client_secret=payment_intent.client_secret,
            stripe_publishable_key=current_app.config.get("STRIPE_PUBLISHABLE_KEY"),
        )

    @app.post("/portal/tickets")
    @client_login_required
    def portal_create_ticket(client: Client):
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        priority_value = request.form.get("priority", "Normal").strip().title()
        if priority_value not in TICKET_PRIORITY_OPTIONS:
            priority_value = "Normal"

        uploaded_files = [
            file
            for file in request.files.getlist("attachments")
            if file and getattr(file, "filename", "")
        ]

        if uploaded_files:
            ensure_file_surface_enabled("support-ticket-attachments")

        for file in uploaded_files:
            if not allowed_ticket_attachment(file.filename):
                flash(
                    "Upload JPG, PNG, GIF, or HEIC images for ticket attachments.",
                    "danger",
                )
                return redirect(url_for("portal_dashboard"))

        if not subject or not message:
            flash("Please provide both a subject and description for your ticket.", "danger")
            return redirect(url_for("portal_dashboard"))

        ticket = SupportTicket(
            client_id=client.id,
            subject=subject,
            message=message,
            priority=priority_value,
        )
        db.session.add(ticket)
        db.session.flush()

        if uploaded_files:
            for file in uploaded_files:
                store_ticket_attachment(current_app, ticket, file)
            ticket.updated_at = utcnow()
        db.session.commit()

        flash("Your support request has been submitted. We'll reach out shortly.", "success")
        return redirect(url_for("portal_dashboard"))

    @app.post("/portal/appointments/<int:appointment_id>/action")
    @client_login_required
    def portal_update_appointment(client: Client, appointment_id: int):
        appointment = (
            Appointment.query.filter_by(id=appointment_id, client_id=client.id)
            .first()
        )
        if not appointment:
            flash("We couldn't find that appointment.", "danger")
            return redirect(url_for("portal_dashboard"))

        action = request.form.get("action", "").strip().lower()
        message = request.form.get("message", "").strip() or None

        if action == "approve":
            appointment.status = "Confirmed"
            appointment.client_message = message
            appointment.proposed_time = None
            confirmation_text = "Appointment confirmed."
            subject = f"Appointment confirmed by {client.name}"
        elif action == "decline":
            appointment.status = "Declined"
            appointment.client_message = message
            appointment.proposed_time = None
            confirmation_text = "Appointment declined."
            subject = f"Appointment declined by {client.name}"
        elif action == "reschedule":
            new_time_raw = request.form.get("scheduled_for", "").strip()
            if not new_time_raw:
                flash("Select a new time to request a reschedule.", "danger")
                return redirect(url_for("portal_dashboard"))
            try:
                new_time = datetime.fromisoformat(new_time_raw)
            except ValueError:
                flash("Use a valid date and time for your request.", "danger")
                return redirect(url_for("portal_dashboard"))

            if new_time.tzinfo is None:
                new_time = new_time.replace(tzinfo=UTC)

            appointment.status = "Reschedule Requested"
            appointment.proposed_time = new_time
            appointment.client_message = message
            confirmation_text = "Reschedule request submitted."
            subject = f"{client.name} requested a new appointment time"
        else:
            flash("Unsupported appointment action.", "danger")
            return redirect(url_for("portal_dashboard"))

        appointment.updated_at = utcnow()
        db.session.commit()

        admin_settings = get_effective_snmp_settings(app)
        admin_recipient = admin_settings.get("admin_email")
        if admin_recipient:
            dispatch_notification(
                admin_recipient,
                subject,
                (
                    f"Client: {client.name}\n"
                    f"Scheduled for: {appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}\n"
                    f"Status: {appointment.status}\n"
                    + (f"Message: {appointment.client_message}\n" if appointment.client_message else "")
                    + (
                        f"Proposed time: {appointment.proposed_time.strftime('%Y-%m-%d %H:%M %Z')}\n"
                        if appointment.proposed_time
                        else ""
                    )
                ),
                category="customer",
            )

        flash(confirmation_text, "success")
        return redirect(url_for("portal_dashboard"))

    @app.route("/tech/login", methods=["GET", "POST"])
    def tech_login():
        existing_id = session.get(TECH_SESSION_KEY)
        if existing_id:
            existing = Technician.query.get(existing_id)
            if existing and existing.is_active:
                return redirect(url_for("tech_dashboard"))
            session.pop(TECH_SESSION_KEY, None)

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "").strip()

            technician = Technician.query.filter_by(email=email).first()
            if (
                technician
                and technician.is_active
                and password
                and check_password_hash(technician.password_hash, password)
            ):
                session[TECH_SESSION_KEY] = technician.id
                session["technician_authenticated_at"] = utcnow().isoformat()
                flash("Welcome to the field operations portal.", "success")
                next_url = request.args.get("next") or url_for("tech_dashboard")
                return redirect(next_url)

            flash("Invalid technician credentials or inactive account.", "danger")

        return render_template("tech_login.html")

    @app.get("/tech/logout")
    def tech_logout():
        session.pop(TECH_SESSION_KEY, None)
        session.pop("technician_authenticated_at", None)
        flash("You have been logged out of the technician portal.", "info")
        return redirect(url_for("tech_login"))

    @app.route("/tech")
    @technician_login_required
    def tech_dashboard(technician: Technician):
        now = utcnow()
        appointments = (
            Appointment.query.filter_by(technician_id=technician.id)
            .order_by(Appointment.scheduled_for.asc())
            .all()
        )

        def _scheduled_for(visit: Appointment) -> datetime:
            scheduled = visit.scheduled_for
            if scheduled.tzinfo is None:
                scheduled = scheduled.replace(tzinfo=UTC)
            return scheduled

        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        today_appointments: list[Appointment] = []
        future_appointments: list[Appointment] = []
        past_appointments: list[Appointment] = []

        for appointment in appointments:
            scheduled_at = _scheduled_for(appointment)
            if scheduled_at < today_start:
                past_appointments.append(appointment)
            elif scheduled_at >= today_end:
                future_appointments.append(appointment)
            else:
                today_appointments.append(appointment)

        today_appointments = sorted(today_appointments, key=_scheduled_for)
        future_appointments = sorted(future_appointments, key=_scheduled_for)
        past_appointments = sorted(
            past_appointments, key=_scheduled_for, reverse=True
        )
        recent = past_appointments[:5]
        displayed_past = past_appointments[:10]

        current_appointments = today_appointments
        upcoming_appointments = future_appointments
        completed_appointments = displayed_past

        def _coerce_utc(dt: datetime | None) -> datetime:
            if dt is None:
                return now
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

        def _format_time(dt: datetime) -> str:
            return dt.strftime("%I:%M %p").lstrip("0")

        active_schedule_blocks = (
            TechnicianSchedule.query.filter(
                TechnicianSchedule.technician_id == technician.id,
                TechnicianSchedule.status.in_(["approved", "cancel_pending"]),
            )
            .order_by(TechnicianSchedule.start_at.asc())
            .all()
        )
        pending_schedule_requests = (
            TechnicianSchedule.query.filter(
                TechnicianSchedule.technician_id == technician.id,
                TechnicianSchedule.status == "pending",
            )
            .order_by(TechnicianSchedule.start_at.asc())
            .all()
        )
        rejected_schedule_requests = (
            TechnicianSchedule.query.filter(
                TechnicianSchedule.technician_id == technician.id,
                TechnicianSchedule.status == "rejected",
            )
            .order_by(TechnicianSchedule.updated_at.desc())
            .all()
        )
        grace_cutoff = now - timedelta(hours=1)

        def _with_utc(dt: datetime) -> datetime:
            if dt is None:
                return now
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt

        upcoming_schedule: list[TechnicianSchedule] = []
        past_schedule_blocks: list[TechnicianSchedule] = []
        for block in active_schedule_blocks:
            block_end = _with_utc(block.end_at)
            if block_end >= grace_cutoff:
                upcoming_schedule.append(block)
            else:
                past_schedule_blocks.append(block)

        upcoming_schedule.sort(key=lambda block: _with_utc(block.start_at))
        past_schedule = sorted(
            past_schedule_blocks,
            key=lambda block: _with_utc(block.start_at),
            reverse=True,
        )[:5]

        calendar_reference: datetime | None = None
        for candidate in [
            *(appointment.scheduled_for for appointment in appointments),
            *(block.start_at for block in active_schedule_blocks),
        ]:
            if candidate is not None:
                calendar_reference = candidate
                break

        display_tz = (
            calendar_reference.tzinfo
            if calendar_reference is not None and calendar_reference.tzinfo
            else UTC
        )
        display_now = now.astimezone(display_tz)
        calendar_start_display = display_now.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        calendar_start_display -= timedelta(days=calendar_start_display.weekday())
        calendar_days = 14
        calendar_start = calendar_start_display.astimezone(UTC)
        calendar_end = calendar_start + timedelta(days=calendar_days)

        relevant_schedule = [
            block
            for block in active_schedule_blocks
            if _coerce_utc(block.end_at) >= calendar_start
            and _coerce_utc(block.start_at) < calendar_end
        ]

        relevant_appointments = [
            visit
            for visit in appointments
            if calendar_start
            <= _coerce_utc(visit.scheduled_for)
            < calendar_end
        ]

        current_appointment_ids = {ap.id for ap in today_appointments}
        calendar_days_payload: list[dict[str, object]] = []
        for offset in range(calendar_days):
            day_start_utc = calendar_start + timedelta(days=offset)
            day_end_utc = day_start_utc + timedelta(days=1)
            day_display = day_start_utc.astimezone(display_tz)

            block_entries: list[tuple[datetime, dict[str, str]]] = []
            for block in relevant_schedule:
                block_start_utc = _coerce_utc(block.start_at)
                block_end_utc = _coerce_utc(block.end_at)
                if block_end_utc <= day_start_utc or block_start_utc >= day_end_utc:
                    continue
                start_display = block_start_utc.astimezone(display_tz)
                end_display = block_end_utc.astimezone(display_tz)
                block_entries.append(
                    (
                        block_start_utc,
                        {
                            "time_range": f"{_format_time(start_display)} – {_format_time(end_display)}",
                            "note": block.note or "",
                        },
                    )
                )

            block_entries.sort(key=lambda item: item[0])
            day_blocks = [payload for _, payload in block_entries]

            job_entries: list[tuple[datetime, dict[str, object]]] = []
            for visit in relevant_appointments:
                visit_start_utc = _coerce_utc(visit.scheduled_for)
                if not (day_start_utc <= visit_start_utc < day_end_utc):
                    continue
                visit_display = visit_start_utc.astimezone(display_tz)
                job_entries.append(
                    (
                        visit_start_utc,
                        {
                            "time": _format_time(visit_display),
                            "title": visit.title,
                            "client": visit.client.name if visit.client else "",
                            "status": visit.status,
                            "link": url_for(
                                "tech_appointment_detail", appointment_id=visit.id
                            ),
                            "is_current": visit.id in current_appointment_ids,
                        },
                    )
                )

            job_entries.sort(key=lambda item: item[0])
            day_jobs = [payload for _, payload in job_entries]

            calendar_days_payload.append(
                {
                    "date": day_display,
                    "is_today": day_display.date() == display_now.date(),
                    "has_jobs": bool(day_jobs),
                    "blocks": day_blocks,
                    "appointments": day_jobs,
                }
            )

        dashboard_calendar_weeks = [
            calendar_days_payload[i : i + 7]
            for i in range(0, len(calendar_days_payload), 7)
        ]

        calendar_range_label = "{start} – {end}".format(
            start=calendar_start_display.strftime("%b %d"),
            end=(calendar_start_display + timedelta(days=calendar_days - 1)).strftime(
                "%b %d"
            ),
        )

        required_categories = get_required_install_photo_categories()
        photo_category_choices = get_install_photo_category_choices()

        client_ids = {ap.client_id for ap in appointments}
        raw_photo_map: dict[int, dict[str, list[InstallPhoto]]] = defaultdict(
            lambda: defaultdict(list)
        )
        acknowledgements_map: dict[int, InstallAcknowledgement] = {}
        if client_ids:
            photos = (
                InstallPhoto.query.filter(InstallPhoto.client_id.in_(client_ids))
                .order_by(InstallPhoto.uploaded_at.desc())
                .all()
            )
            for photo in photos:
                raw_photo_map[photo.client_id][photo.category].append(photo)
            acknowledgements = (
                InstallAcknowledgement.query.filter(
                    InstallAcknowledgement.client_id.in_(client_ids)
                )
                .order_by(InstallAcknowledgement.signed_at.desc())
                .all()
            )
            for acknowledgement in acknowledgements:
                acknowledgements_map.setdefault(
                    acknowledgement.client_id, acknowledgement
                )

        photo_map = {cid: dict(category_map) for cid, category_map in raw_photo_map.items()}
        missing_requirements: dict[int, list[str]] = {}
        for ap in appointments:
            missing = [
                category
                for category in required_categories
                if not raw_photo_map[ap.client_id].get(category)
            ]
            if ap.client_id not in acknowledgements_map:
                missing.append("Customer Acceptance Signature")
            missing_requirements[ap.client_id] = missing

        recent_uploads = (
            InstallPhoto.query.filter_by(technician_id=technician.id)
            .order_by(InstallPhoto.uploaded_at.desc())
            .limit(8)
            .all()
        )

        return render_template(
            "tech_dashboard.html",
            technician=technician,
            current_appointments=current_appointments,
            today_appointments=today_appointments,
            future_appointments=future_appointments,
            upcoming_appointments=upcoming_appointments,
            completed_appointments=completed_appointments,
            past_appointments=displayed_past,
            recent_appointments=recent,
            missing_requirements=missing_requirements,
            photo_map=photo_map,
            photo_categories=photo_category_choices,
            required_categories=required_categories,
            recent_uploads=recent_uploads,
            acknowledgements_map=acknowledgements_map,
            upcoming_schedule=upcoming_schedule,
            past_schedule=past_schedule,
            pending_schedule_requests=pending_schedule_requests,
            rejected_schedule_requests=rejected_schedule_requests,
            dashboard_calendar_weeks=dashboard_calendar_weeks,
            calendar_range_label=calendar_range_label,
        )

    @app.post("/tech/schedule")
    @technician_login_required
    def create_technician_schedule(technician: Technician):
        date_raw = request.form.get("date", "").strip()
        start_time_raw = request.form.get("start_time", "").strip()
        end_time_raw = request.form.get("end_time", "").strip()
        note = request.form.get("note", "").strip() or None

        if not (date_raw and start_time_raw and end_time_raw):
            flash("Select a schedule date, start time, and end time.", "danger")
            return redirect(url_for("tech_dashboard"))

        try:
            start_at = datetime.strptime(
                f"{date_raw} {start_time_raw}", "%Y-%m-%d %H:%M"
            ).replace(tzinfo=UTC)
            end_at = datetime.strptime(
                f"{date_raw} {end_time_raw}", "%Y-%m-%d %H:%M"
            ).replace(tzinfo=UTC)
        except ValueError:
            flash("Enter a valid schedule date and time.", "danger")
            return redirect(url_for("tech_dashboard"))

        if end_at <= start_at:
            flash("End time must be after the start time.", "danger")
            return redirect(url_for("tech_dashboard"))

        schedule_block = TechnicianSchedule(
            technician_id=technician.id,
            start_at=start_at,
            end_at=end_at,
            note=note,
            status="pending",
            review_note=None,
            reviewed_at=None,
            reviewed_by_id=None,
            cancel_requested_at=None,
        )
        db.session.add(schedule_block)
        db.session.commit()

        flash(
            "Shift submitted for manager approval. You'll see it on your calendar once approved.",
            "info",
        )
        return redirect(url_for("tech_dashboard"))

    @app.post("/tech/schedule/<int:block_id>/delete")
    @technician_login_required
    def delete_technician_schedule(technician: Technician, block_id: int):
        schedule_block = (
            TechnicianSchedule.query.filter_by(
                id=block_id, technician_id=technician.id
            )
            .order_by(TechnicianSchedule.start_at.desc())
            .first()
        )
        if schedule_block is None:
            flash("Schedule entry not found.", "danger")
            return redirect(url_for("tech_dashboard"))

        if schedule_block.status == "pending":
            db.session.delete(schedule_block)
            db.session.commit()
            flash("Pending schedule request withdrawn.", "info")
            return redirect(url_for("tech_dashboard"))

        if schedule_block.status == "rejected":
            db.session.delete(schedule_block)
            db.session.commit()
            flash("Rejected schedule request removed.", "info")
            return redirect(url_for("tech_dashboard"))

        if schedule_block.status == "cancel_pending":
            flash("Cancellation already awaiting manager approval.", "warning")
            return redirect(url_for("tech_dashboard"))

        if schedule_block.status == "cancelled":
            db.session.delete(schedule_block)
            db.session.commit()
            flash("Cancelled schedule entry cleared.", "info")
            return redirect(url_for("tech_dashboard"))

        schedule_block.status = "cancel_pending"
        schedule_block.cancel_requested_at = utcnow()
        schedule_block.review_note = None
        schedule_block.reviewed_at = None
        schedule_block.reviewed_by_id = None
        db.session.commit()

        flash("Cancellation request sent for manager approval.", "info")
        return redirect(url_for("tech_dashboard"))

    @app.route("/tech/appointments/<int:appointment_id>")
    @technician_login_required
    def tech_appointment_detail(technician: Technician, appointment_id: int):
        appointment = (
            Appointment.query.filter_by(id=appointment_id, technician_id=technician.id)
            .first_or_404()
        )
        now = utcnow()

        def _coerce_utc(dt: datetime | None) -> datetime:
            if dt is None:
                return now
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

        def _format_time(dt: datetime) -> str:
            return dt.strftime("%I:%M %p").lstrip("0")

        required_categories = get_required_install_photo_categories()
        photo_category_choices = get_install_photo_category_choices()
        photos = (
            InstallPhoto.query.filter_by(client_id=appointment.client_id)
            .order_by(InstallPhoto.uploaded_at.desc())
            .all()
        )
        photos_by_category: dict[str, list[InstallPhoto]] = defaultdict(list)
        for photo in photos:
            photos_by_category[photo.category].append(photo)

        missing_categories = [
            category
            for category in required_categories
            if not photos_by_category.get(category)
        ]

        acknowledgement = (
            InstallAcknowledgement.query.filter_by(appointment_id=appointment.id)
            .order_by(InstallAcknowledgement.signed_at.desc())
            .first()
        )
        if acknowledgement is None:
            acknowledgement = (
                InstallAcknowledgement.query.filter_by(client_id=appointment.client_id)
                .order_by(InstallAcknowledgement.signed_at.desc())
                .first()
            )

        appointment_start = _coerce_utc(appointment.scheduled_for)
        display_tz = appointment.scheduled_for.tzinfo or UTC
        calendar_start = appointment_start.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        calendar_start -= timedelta(days=calendar_start.weekday())
        calendar_days = 14
        calendar_end = calendar_start + timedelta(days=calendar_days)

        schedule_blocks = (
            TechnicianSchedule.query.filter(
                TechnicianSchedule.technician_id == technician.id,
                TechnicianSchedule.status.in_(["approved", "cancel_pending"]),
            )
            .order_by(TechnicianSchedule.start_at.asc())
            .all()
        )
        relevant_schedule = [
            block
            for block in schedule_blocks
            if _coerce_utc(block.end_at) >= calendar_start
            and _coerce_utc(block.start_at) < calendar_end
        ]

        technician_appointments = (
            Appointment.query.filter_by(technician_id=technician.id)
            .order_by(Appointment.scheduled_for.asc())
            .all()
        )
        relevant_appointments = [
            visit
            for visit in technician_appointments
            if calendar_start <= _coerce_utc(visit.scheduled_for) < calendar_end
        ]

        today_display_date = now.astimezone(display_tz).date()
        appointment_display_date = appointment_start.astimezone(display_tz).date()
        availability_days: list[dict[str, object]] = []
        for offset in range(calendar_days):
            day_start_utc = calendar_start + timedelta(days=offset)
            day_end_utc = day_start_utc + timedelta(days=1)
            day_display = day_start_utc.astimezone(display_tz)
            day_blocks: list[dict[str, str]] = []
            for block in relevant_schedule:
                block_start_utc = _coerce_utc(block.start_at)
                block_end_utc = _coerce_utc(block.end_at)
                if block_end_utc <= day_start_utc or block_start_utc >= day_end_utc:
                    continue
                start_display = block_start_utc.astimezone(display_tz)
                end_display = block_end_utc.astimezone(display_tz)
                day_blocks.append(
                    {
                        "time_range": f"{_format_time(start_display)} – {_format_time(end_display)}",
                        "note": block.note or "",
                    }
                )

            day_appointments: list[dict[str, object]] = []
            for visit in relevant_appointments:
                visit_start_utc = _coerce_utc(visit.scheduled_for)
                if not (day_start_utc <= visit_start_utc < day_end_utc):
                    continue
                visit_display = visit_start_utc.astimezone(display_tz)
                day_appointments.append(
                    {
                        "time": _format_time(visit_display),
                        "title": visit.title,
                        "client": visit.client.name if visit.client else "",
                        "status": visit.status,
                        "link": url_for(
                            "tech_appointment_detail", appointment_id=visit.id
                        ),
                        "is_current": visit.id == appointment.id,
                    }
                )

            availability_days.append(
                {
                    "date": day_display,
                    "is_today": day_display.date() == today_display_date,
                    "is_appointment_day": day_display.date()
                    == appointment_display_date,
                    "blocks": day_blocks,
                    "appointments": day_appointments,
                }
            )

        availability_weeks = [
            availability_days[i : i + 7]
            for i in range(0, len(availability_days), 7)
        ]

        legal_documents = {
            key: Document.query.filter_by(doc_type=key).first()
            for key in ("aup", "privacy", "tos")
        }

        return render_template(
            "tech_appointment.html",
            technician=technician,
            appointment=appointment,
            client=appointment.client,
            photos_by_category=dict(photos_by_category),
            missing_categories=missing_categories,
            photo_categories=photo_category_choices,
            required_categories=required_categories,
            acknowledgement=acknowledgement,
            legal_documents=legal_documents,
            availability_weeks=availability_weeks,
        )

    @app.post("/tech/clients/<int:client_id>/photos")
    @technician_login_required
    def upload_install_photo_technician(technician: Technician, client_id: int):
        client = Client.query.get_or_404(client_id)
        appointment_id_raw = request.form.get("appointment_id", "").strip()
        appointment: Appointment | None = None
        if appointment_id_raw:
            try:
                appointment_id = int(appointment_id_raw)
            except (TypeError, ValueError):
                appointment_id = None
            else:
                appointment = (
                    Appointment.query.filter_by(
                        id=appointment_id, technician_id=technician.id
                    )
                    .order_by(Appointment.scheduled_for.desc())
                    .first()
                )
        if appointment is None:
            appointment = (
                Appointment.query.filter_by(client_id=client.id, technician_id=technician.id)
                .order_by(Appointment.scheduled_for.desc())
                .first()
            )
        if appointment is None:
            flash("You do not have access to that customer record.", "danger")
            return redirect(url_for("tech_dashboard"))

        required_categories = get_required_install_photo_categories()
        photo_category_choices = get_install_photo_category_choices()
        category_default = (
            required_categories[0]
            if required_categories
            else photo_category_choices[0]
            if photo_category_choices
            else OPTIONAL_INSTALL_PHOTO_CATEGORY
        )
        category = request.form.get("category", "").strip() or category_default
        if category not in photo_category_choices:
            flash("Choose a supported photo category.", "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        ensure_file_surface_enabled("install-photo")
        file = request.files.get("photo")
        if not file or not file.filename:
            flash("Choose a photo to upload.", "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        if not allowed_install_file(file.filename):
            flash("Upload JPG, PNG, or HEIC images for installation records.", "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        notes = request.form.get("notes", "").strip() or None

        install_folder = Path(app.config["INSTALL_PHOTOS_FOLDER"]) / f"client_{client.id}"
        install_folder.mkdir(parents=True, exist_ok=True)

        timestamp = utcnow().strftime("%Y%m%d%H%M%S")
        safe_name = secure_filename(file.filename)
        stored_filename = f"{timestamp}_{safe_name}" if safe_name else f"{timestamp}.jpg"
        relative_path = Path(f"client_{client.id}") / stored_filename
        file.save(install_folder / stored_filename)

        photo = InstallPhoto(
            client_id=client.id,
            technician_id=technician.id,
            category=category,
            original_filename=file.filename,
            stored_filename=str(relative_path),
            notes=notes,
        )
        db.session.add(photo)
        db.session.commit()

        flash("Photo uploaded to the customer record.", "success")
        redirect_target = request.form.get("next") or url_for(
            "tech_appointment_detail", appointment_id=appointment.id
        )
        return redirect(redirect_target)

    @app.post("/tech/appointments/<int:appointment_id>/acknowledgements")
    @technician_login_required
    def submit_install_acknowledgement(
        technician: Technician, appointment_id: int
    ):
        appointment = (
            Appointment.query.filter_by(id=appointment_id, technician_id=technician.id)
            .first_or_404()
        )
        signed_name = request.form.get("signed_name", "").strip()
        signature_data = request.form.get("signature_data", "")
        aup_accept = request.form.get("accept_aup")
        privacy_accept = request.form.get("accept_privacy")
        tos_accept = request.form.get("accept_tos")

        if not signed_name:
            flash("Enter the customer's printed name before capturing their signature.", "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        if not (aup_accept and privacy_accept and tos_accept):
            flash("Confirm the customer acknowledged the AUP, Privacy Policy, and TOS.", "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        acknowledgement = (
            InstallAcknowledgement.query.filter_by(appointment_id=appointment.id)
            .order_by(InstallAcknowledgement.signed_at.desc())
            .first()
        )
        if acknowledgement is None:
            acknowledgement = InstallAcknowledgement(
                client_id=appointment.client_id,
                technician_id=technician.id,
                appointment_id=appointment.id,
                signed_name=signed_name,
                signature_filename="",
            )
            db.session.add(acknowledgement)
        else:
            delete_install_signature_image(app, acknowledgement)
            acknowledgement.signed_name = signed_name
            acknowledgement.technician_id = technician.id
            acknowledgement.appointment_id = appointment.id

        acknowledgement.signed_at = utcnow()

        documents = {
            key: Document.query.filter_by(doc_type=key).first()
            for key in ("aup", "privacy", "tos")
        }
        acknowledgement.aup_document_id = (
            documents["aup"].id if documents.get("aup") else None
        )
        acknowledgement.privacy_document_id = (
            documents["privacy"].id if documents.get("privacy") else None
        )
        acknowledgement.tos_document_id = (
            documents["tos"].id if documents.get("tos") else None
        )

        try:
            store_install_signature_image(app, acknowledgement, signature_data)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

        db.session.commit()

        flash("Customer acknowledgement captured and stored.", "success")
        return redirect(url_for("tech_appointment_detail", appointment_id=appointment.id))

    @app.get("/install-photos/<int:photo_id>")
    def serve_install_photo(photo_id: int):
        photo = InstallPhoto.query.get_or_404(photo_id)
        authorized = False
        if session.get("admin_authenticated"):
            authorized = True
        technician_id = session.get(TECH_SESSION_KEY)
        if technician_id and technician_id == photo.technician_id:
            authorized = True
        client_id = session.get(PORTAL_SESSION_KEY)
        if client_id and client_id == photo.client_id:
            authorized = True
        if not authorized:
            abort(403)

        base_folder = Path(app.config["INSTALL_PHOTOS_FOLDER"])
        file_path = base_folder / photo.stored_filename
        if not file_path.exists():
            abort(404)

        mimetype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        return send_site_file(
            "install-photo", file_path.parent, file_path.name, mimetype=mimetype
        )

    @app.get("/install-signatures/<int:ack_id>")
    def serve_install_signature(ack_id: int):
        acknowledgement = InstallAcknowledgement.query.get_or_404(ack_id)
        authorized = False
        if session.get("admin_authenticated"):
            authorized = True
        technician_id = session.get(TECH_SESSION_KEY)
        if technician_id and technician_id == acknowledgement.technician_id:
            authorized = True
        client_id = session.get(PORTAL_SESSION_KEY)
        if client_id and client_id == acknowledgement.client_id:
            authorized = True
        if not authorized:
            abort(403)

        base_folder = Path(app.config["INSTALL_SIGNATURE_FOLDER"])
        file_path = base_folder / acknowledgement.signature_filename
        if not file_path.exists():
            abort(404)

        return send_site_file(
            "install-signature",
            file_path.parent,
            file_path.name,
            mimetype="image/png",
        )

    @app.get("/support-ticket-attachments/<int:attachment_id>")
    def serve_ticket_attachment(attachment_id: int):
        attachment = SupportTicketAttachment.query.get_or_404(attachment_id)
        ticket = attachment.ticket

        authorized = False
        if session.get("admin_authenticated"):
            authorized = True
        client_id = session.get(PORTAL_SESSION_KEY)
        if client_id and ticket and client_id == ticket.client_id:
            authorized = True
        if not authorized:
            abort(403)

        base_folder = Path(app.config["SUPPORT_TICKET_ATTACHMENT_FOLDER"])
        file_path = base_folder / attachment.stored_filename
        if not file_path.exists():
            abort(404)

        mimetype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        return send_site_file(
            "support-ticket-attachments",
            file_path.parent,
            file_path.name,
            mimetype=mimetype,
            download_name=attachment.original_filename,
        )

    @app.get("/clients/<int:client_id>/verification-photo")
    def client_verification_photo(client_id: int):
        client_record = Client.query.get_or_404(client_id)

        authorized = False
        if session.get("admin_authenticated"):
            authorized = True
        portal_client_id = session.get(PORTAL_SESSION_KEY)
        if portal_client_id and portal_client_id == client_record.id:
            authorized = True
        if not authorized:
            abort(403)

        if not client_record.verification_photo_filename:
            abort(404)

        base_folder = Path(app.config["CLIENT_VERIFICATION_FOLDER"])
        file_path = base_folder / client_record.verification_photo_filename
        if not file_path.exists():
            abort(404)

        mimetype = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        return send_site_file(
            "client-verification",
            file_path.parent,
            file_path.name,
            mimetype=mimetype,
        )

    @app.route("/legal")
    def legal():
        documents = {key: None for key in LEGAL_DOCUMENT_TYPES}
        for document in Document.query.all():
            documents[document.doc_type] = document

        return render_template("legal.html", documents=documents)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username_or_email = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if username_or_email and password:
                admin = AdminUser.query.filter(
                    or_(
                        AdminUser.username == username_or_email,
                        AdminUser.email == username_or_email,
                    )
                ).first()

                if admin and admin.check_password(password):
                    session["admin_authenticated"] = True
                    session["admin_logged_in_at"] = utcnow().isoformat()
                    session["admin_user_id"] = admin.id
                    admin.last_login_at = utcnow()
                    db.session.commit()
                    flash("Welcome back!", "success")
                    redirect_target = request.args.get("next") or url_for("dashboard")
                    return redirect(redirect_target)

            flash("Invalid credentials. Please try again.", "danger")

        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        active_section = request.args.get("section", "overview") or "overview"
        valid_sections = {
            "overview",
            "customers",
            "billing",
            "network",
            "support",
            "appointments",
            "navigation",
            "branding",
            "legal",
            "blog",
            "plans",
            "field",
            "security",
            "notifications",
            "story",
        }
        if active_section not in valid_sections:
            active_section = "overview"

        status_filter = request.args.get("status")
        if status_filter not in STATUS_OPTIONS:
            status_filter = None

        clients: list[Client] = []
        technicians: list[Technician] = []
        focus_client_id = request.args.get("focus", type=int)
        selected_client: Client | None = None
        selected_client_invoices: list[Invoice] = []
        selected_client_equipment: list[Equipment] = []
        selected_client_tickets: list[SupportTicket] = []
        selected_client_appointments: list[Appointment] = []
        selected_client_photo_map: dict[str, list[InstallPhoto]] = {}
        selected_client_missing_categories: list[str] = []
        selected_client_service_groups: list[tuple[str, str]] = []
        selected_client_portal_enabled = False
        required_photo_categories = get_required_install_photo_categories()
        install_photo_categories = get_install_photo_category_choices()
        install_photo_requirements: list[InstallPhotoRequirement] = []
        tls_config: TLSConfig | None = None
        tls_certificate_ready = False
        tls_challenge_folder = current_app.config.get("TLS_CHALLENGE_FOLDER")
        admin_users: list[AdminUser] = []
        recent_autopay_events: list[AutopayEvent] = []
        suspended_clients: list[Client] = []
        team_members: list[TeamMember] = []
        trusted_businesses: list[TrustedBusiness] = []
        support_partners: list[SupportPartner] = []
        stripe_config: StripeConfig | None = None
        pending_schedule_requests: list[TechnicianSchedule] = []
        recent_schedule_decisions: list[TechnicianSchedule] = []
        notification_config: NotificationConfig | None = None
        office365_ready = False
        uisp_devices: list[UispDevice] = []
        unassigned_uisp_devices: list[UispDevice] = []
        network_towers: list[NetworkTower] = []
        uisp_config: UispConfig | None = None
        if active_section in {
            "customers",
            "billing",
            "network",
            "support",
            "appointments",
            "notifications",
        }:
            query = Client.query.order_by(Client.created_at.desc())
            if status_filter:
                query = query.filter_by(status=status_filter)
            clients = query.all()

        if active_section == "billing":
            recent_autopay_events = (
                AutopayEvent.query.order_by(AutopayEvent.attempted_at.desc())
                .limit(15)
                .all()
            )

        if active_section in {"network", "field"} and clients:
            suspended_clients = [client for client in clients if client.service_suspended]

        if active_section == "network":
            uisp_devices = UispDevice.query.order_by(UispDevice.name.asc()).all()
            unassigned_uisp_devices = [
                device for device in uisp_devices if device.client_id is None
            ]
            network_towers = (
                NetworkTower.query.order_by(NetworkTower.name.asc()).all()
            )
            uisp_config = _get_uisp_config()

        if active_section == "story":
            team_members = (
                TeamMember.query.order_by(TeamMember.position.asc(), TeamMember.id.asc())
                .all()
            )
            trusted_businesses = (
                TrustedBusiness.query.order_by(
                    TrustedBusiness.position.asc(), TrustedBusiness.id.asc()
                )
                .all()
            )
            support_partners = (
                SupportPartner.query.order_by(
                    SupportPartner.position.asc(), SupportPartner.id.asc()
                ).all()
            )
        elif active_section == "overview":
            support_partners = (
                SupportPartner.query.order_by(
                    SupportPartner.position.asc(), SupportPartner.id.asc()
                ).all()
            )

        if active_section == "customers" and focus_client_id:
            selected_client = Client.query.get(focus_client_id)
            if selected_client:
                selected_client_portal_enabled = bool(selected_client.portal_password_hash)
                selected_client_invoices = (
                    Invoice.query.filter_by(client_id=selected_client.id)
                    .order_by(Invoice.created_at.desc())
                    .limit(6)
                    .all()
                )
                selected_client_equipment = (
                    Equipment.query.filter_by(client_id=selected_client.id)
                    .order_by(Equipment.created_at.desc())
                    .limit(6)
                    .all()
                )
                selected_client_tickets = (
                    SupportTicket.query.filter_by(client_id=selected_client.id)
                    .order_by(SupportTicket.created_at.desc())
                    .limit(6)
                    .all()
                )
                selected_client_appointments = (
                    Appointment.query.filter_by(client_id=selected_client.id)
                    .order_by(Appointment.scheduled_for.desc())
                    .limit(6)
                    .all()
                )
                selected_client_photo_map = {
                    category: [] for category in install_photo_categories
                }
                client_photos = (
                    InstallPhoto.query.filter_by(client_id=selected_client.id)
                    .order_by(InstallPhoto.uploaded_at.desc())
                    .all()
                )
                for photo in client_photos:
                    selected_client_photo_map.setdefault(photo.category, []).append(photo)
                selected_client_missing_categories = [
                    category
                    for category in required_photo_categories
                    if not selected_client_photo_map.get(category)
                ]
                if selected_client.residential_plan:
                    selected_client_service_groups.append(
                        ("Residential", selected_client.residential_plan)
                    )
                if selected_client.business_plan:
                    selected_client_service_groups.append(
                        ("Business", selected_client.business_plan)
                    )
                if selected_client.phone_plan:
                    selected_client_service_groups.append(
                        ("Phone Service", selected_client.phone_plan)
                    )

        if active_section in {"appointments", "field"}:
            technicians = (
                Technician.query.filter_by(is_active=True)
                .order_by(Technician.name.asc())
                .all()
            )

        if active_section == "security":
            admin_users = AdminUser.query.order_by(AdminUser.created_at.asc()).all()

        appointments: list[Appointment] = []
        if active_section == "appointments":
            appointments = (
                Appointment.query.order_by(Appointment.scheduled_for.asc()).all()
            )
        elif active_section == "field":
            field_records = (
                Appointment.query.order_by(Appointment.scheduled_for.asc()).all()
            )
            cutoff = utcnow() - timedelta(days=2)
            appointments = []
            for record in field_records:
                scheduled_for = record.scheduled_for
                if scheduled_for.tzinfo is None:
                    scheduled_for = scheduled_for.replace(tzinfo=UTC)
                if scheduled_for >= cutoff:
                    appointments.append(record)

        overview_metrics: dict[str, object] = {}
        operations_snapshot: list[dict[str, object]] = []
        recent_clients: list[SimpleNamespace] = []
        recent_invoices: list[SimpleNamespace] = []
        recent_equipment: list[SimpleNamespace] = []
        recent_tickets: list[SimpleNamespace] = []
        upcoming_appointments_list: list[SimpleNamespace] = []
        total_clients = 0
        new_this_week = 0
        outstanding_amount_cents = 0
        open_ticket_total = 0
        active_clients = 0
        onboarding_clients = 0
        clients_without_password = 0
        pending_invoices_total = 0
        overdue_amount_cents = 0
        equipment_total = 0
        network_new_this_week = 0
        clients_with_equipment = 0
        support_created_this_week = 0
        support_updates = 0
        billing_invoices_created = 0
        appointments_total = 0
        pending_appointments = 0
        upcoming_appointments_count = 0
        reschedule_requests = 0
        appointments_created_this_week = 0
        recent_appointments: list[Appointment] = []

        if active_section == "overview":
            overview_metrics = get_dashboard_overview_snapshot(current_app)
            total_clients = overview_metrics["total_clients"]
            new_this_week = overview_metrics["new_this_week"]
            outstanding_amount_cents = overview_metrics["outstanding_amount_cents"]
            open_ticket_total = overview_metrics["open_ticket_total"]
            active_clients = overview_metrics["active_clients"]
            onboarding_clients = overview_metrics["onboarding_clients"]
            clients_without_password = overview_metrics["clients_without_password"]
            pending_invoices_total = overview_metrics["pending_invoices_total"]
            overdue_amount_cents = overview_metrics["overdue_amount_cents"]
            equipment_total = overview_metrics["equipment_total"]
            network_new_this_week = overview_metrics["network_new_this_week"]
            clients_with_equipment = overview_metrics["clients_with_equipment"]
            support_created_this_week = overview_metrics["support_created_this_week"]
            support_updates = overview_metrics["support_updates"]
            billing_invoices_created = overview_metrics["billing_invoices_created"]
            appointments_total = overview_metrics["appointments_total"]
            pending_appointments = overview_metrics["pending_appointments"]
            upcoming_appointments_count = overview_metrics["upcoming_appointments_count"]
            reschedule_requests = overview_metrics["reschedule_requests"]
            appointments_created_this_week = overview_metrics[
                "appointments_created_this_week"
            ]
            operations_snapshot = overview_metrics["operations_snapshot"]
            recent_clients = overview_metrics["recent_clients"]
            recent_invoices = overview_metrics["recent_invoices"]
            recent_equipment = overview_metrics["recent_equipment"]
            recent_tickets = overview_metrics["recent_tickets"]
            upcoming_appointments_list = overview_metrics["upcoming_appointments"]

        upcoming_statuses = ["Pending", "Confirmed", "Reschedule Requested"]
        if active_section in {"appointments", "field"} and not overview_metrics:
            now = utcnow()
            start_of_week = now - timedelta(days=7)
            appointments_total = Appointment.query.count()
            upcoming_appointments_count = (
                Appointment.query.filter(
                    Appointment.status.in_(upcoming_statuses),
                    Appointment.scheduled_for >= now - timedelta(days=1),
                ).count()
            )
            pending_appointments = (
                Appointment.query.filter_by(status="Pending").count()
            )
            reschedule_requests = (
                Appointment.query.filter_by(status="Reschedule Requested").count()
            )
            appointments_created_this_week = (
                Appointment.query.filter(Appointment.created_at >= start_of_week).count()
            )
            recent_appointments = (
                Appointment.query.order_by(Appointment.updated_at.desc()).limit(5).all()
            )
        recent_install_photos: list[InstallPhoto] = []
        field_requirements: dict[int, list[str]] = {}
        field_photo_map: dict[int, dict[str, list[InstallPhoto]]] = {}
        if active_section == "field":
            install_photo_requirements = get_install_photo_requirements()
            recent_install_photos = (
                InstallPhoto.query.order_by(InstallPhoto.uploaded_at.desc())
                .limit(12)
                .all()
            )
            appointment_client_ids = {ap.client_id for ap in appointments}
            photo_lookup: dict[int, dict[str, list[InstallPhoto]]] = defaultdict(lambda: defaultdict(list))
            if appointment_client_ids:
                photos = (
                    InstallPhoto.query.filter(InstallPhoto.client_id.in_(appointment_client_ids))
                    .order_by(InstallPhoto.uploaded_at.desc())
                    .all()
                )
                for photo in photos:
                    photo_lookup[photo.client_id][photo.category].append(photo)
            field_photo_map = {cid: dict(categories) for cid, categories in photo_lookup.items()}
            for ap in appointments:
                category_map = photo_lookup.get(ap.client_id, {})
                missing = [
                    category
                    for category in required_photo_categories
                    if not category_map.get(category)
                ]
                field_requirements[ap.id] = missing

            pending_schedule_requests = (
                TechnicianSchedule.query.filter(
                    TechnicianSchedule.status.in_("pending cancel_pending".split())
                )
                .order_by(TechnicianSchedule.start_at.asc())
                .all()
            )
            recent_schedule_decisions = (
                TechnicianSchedule.query.filter(
                    TechnicianSchedule.reviewed_at.isnot(None),
                    TechnicianSchedule.status.in_(
                        ("approved", "rejected", "cancelled")
                    ),
                )
                .order_by(TechnicianSchedule.reviewed_at.desc())
                .limit(10)
                .all()
            )

        tls_config = TLSConfig.query.first()
        if tls_config:
            tls_certificate_ready = tls_config.certificate_ready()

        stripe_config = StripeConfig.query.first()

        operations_snapshot = [
            {
                "key": "customers",
                "title": "Customers",
                "description": "Growth and onboarding momentum across your service area.",
                "metrics": [
                    {"label": "Total Clients", "value": total_clients},
                    {"label": "Active Clients", "value": active_clients},
                    {"label": "Onboarding", "value": onboarding_clients},
                    {"label": "Passwords Pending", "value": clients_without_password},
                ],
                "footer": f"{new_this_week} new signups this week",
            },
            {
                "key": "network",
                "title": "Network",
                "description": "Hardware deployed to keep customers online.",
                "metrics": [
                    {"label": "Devices Online", "value": equipment_total},
                    {"label": "Clients With Gear", "value": clients_with_equipment},
                    {"label": "Upcoming Visits", "value": upcoming_appointments_count},
                    {"label": "Reschedule Requests", "value": reschedule_requests},
                ],
                "footer": (
                    f"{appointments_created_this_week} appointments scheduled this week • "
                    f"{network_new_this_week} installs logged"
                ),
            },
            {
                "key": "support",
                "title": "Support",
                "description": "Ticket activity from your subscribers.",
                "metrics": [
                    {"label": "Open Tickets", "value": open_ticket_total},
                    {"label": "New Tickets", "value": support_created_this_week},
                    {"label": "Updates This Week", "value": support_updates},
                ],
                "footer": f"{support_updates} tickets touched this week",
            },
            {
                "key": "billing",
                "title": "Billing",
                "description": "Cash flow indicators and invoice workload.",
                "metrics": [
                    {
                        "label": "Outstanding Balance",
                        "value": outstanding_amount_cents,
                        "format": "currency",
                    },
                    {
                        "label": "Overdue Balance",
                        "value": overdue_amount_cents,
                        "format": "currency",
                    },
                    {"label": "Pending Invoices", "value": pending_invoices_total},
                    {"label": "Invoices This Week", "value": billing_invoices_created},
                ],
                "footer": f"{billing_invoices_created} invoices posted this week",
            },
        ]

        documents = {key: None for key in LEGAL_DOCUMENT_TYPES}
        for document in Document.query.all():
            documents[document.doc_type] = document

        navigation_items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        branding_records = {asset.asset_type: asset for asset in BrandingAsset.query.all()}
        site_theme = SiteTheme.query.first()

        snmp_settings = get_effective_snmp_settings(app)
        snmp_enabled = bool(snmp_settings.get("host") or app.config.get("SNMP_EMAIL_SENDER"))
        snmp_config = SNMPConfig.query.first()
        down_detector_config = DownDetectorConfig.query.first()

        if active_section == "notifications":
            notification_config = ensure_notification_configuration()
        else:
            notification_config = NotificationConfig.query.first()

        if notification_config:
            office365_ready = notification_config.office365_ready()

        blog_posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()

        service_plans = ServicePlan.query.order_by(
            ServicePlan.category.asc(),
            ServicePlan.position.asc(),
            ServicePlan.id.asc(),
        ).all()
        ordered_plan_categories = get_ordered_service_plan_categories()
        plan_field_config = build_plan_field_config()

        return render_template(
            "dashboard.html",
            clients=clients,
            active_section=active_section,
            operations_snapshot=operations_snapshot,
            total_clients=total_clients,
            new_this_week=new_this_week,
            outstanding_amount_cents=outstanding_amount_cents,
            open_ticket_total=open_ticket_total,
            active_clients=active_clients,
            onboarding_clients=onboarding_clients,
            clients_without_password=clients_without_password,
            pending_invoices_total=pending_invoices_total,
            overdue_amount_cents=overdue_amount_cents,
            equipment_total=equipment_total,
            recent_clients=recent_clients,
            recent_invoices=recent_invoices,
            recent_equipment=recent_equipment,
            recent_tickets=recent_tickets,
            selected_client=selected_client,
            selected_client_invoices=selected_client_invoices,
            selected_client_equipment=selected_client_equipment,
            selected_client_tickets=selected_client_tickets,
            ticket_priority_options=TICKET_PRIORITY_OPTIONS,
            selected_client_appointments=selected_client_appointments,
            selected_client_photo_map=selected_client_photo_map,
            selected_client_missing_categories=selected_client_missing_categories,
            selected_client_service_groups=selected_client_service_groups,
            selected_client_portal_enabled=selected_client_portal_enabled,
            focus_client_id=focus_client_id,
            status_filter=status_filter,
            legal_documents=documents,
            navigation_items=navigation_items,
            branding_assets=branding_records,
            appointments=appointments,
            technicians=technicians,
            appointments_total=appointments_total,
            pending_appointments=pending_appointments,
            upcoming_appointments=upcoming_appointments_list,
            recent_appointments=recent_appointments,
            snmp_enabled=snmp_enabled,
            snmp_config=snmp_config,
            snmp_settings=snmp_settings,
            blog_posts=blog_posts,
            down_detector_config=down_detector_config,
            notification_config=notification_config,
            office365_ready=office365_ready,
            service_plans=service_plans,
            service_plans_by_category=ordered_plan_categories,
            plan_field_config=plan_field_config,
            recent_install_photos=recent_install_photos,
            install_photo_categories=install_photo_categories,
            required_photo_categories=required_photo_categories,
            install_photo_requirements=install_photo_requirements,
            field_requirements=field_requirements,
            field_photo_map=field_photo_map,
            pending_schedule_requests=pending_schedule_requests,
            recent_schedule_decisions=recent_schedule_decisions,
            tls_config=tls_config,
            tls_certificate_ready=tls_certificate_ready,
            tls_challenge_folder=tls_challenge_folder,
            uisp_devices=uisp_devices,
            unassigned_uisp_devices=unassigned_uisp_devices,
            network_towers=network_towers,
            uisp_config=uisp_config,
            admin_users=admin_users,
            current_admin_id=session.get("admin_user_id"),
            site_theme=site_theme,
            team_members=team_members,
            trusted_businesses=trusted_businesses,
            support_partners=support_partners,
            recent_autopay_events=recent_autopay_events,
            suspended_clients=suspended_clients,
            stripe_config=stripe_config,
            stripe_ready=stripe_active(),
        )

    @app.get("/dashboard/customers/<int:client_id>")
    @login_required
    def admin_client_account(client_id: int):
        client = Client.query.get_or_404(client_id)

        required_photo_categories = get_required_install_photo_categories()
        install_photo_categories = get_install_photo_category_choices()

        invoices = (
            Invoice.query.filter_by(client_id=client.id)
            .order_by(Invoice.created_at.desc())
            .all()
        )
        equipment_items = (
            Equipment.query.filter_by(client_id=client.id)
            .order_by(Equipment.created_at.desc())
            .all()
        )
        assigned_uisp_devices = (
            UispDevice.query.filter_by(client_id=client.id)
            .order_by(UispDevice.name.asc())
            .all()
        )
        available_uisp_devices = (
            UispDevice.query.filter(UispDevice.client_id.is_(None))
            .order_by(UispDevice.name.asc())
            .all()
        )
        tickets = (
            SupportTicket.query.filter_by(client_id=client.id)
            .order_by(SupportTicket.updated_at.desc())
            .all()
        )
        appointments = (
            Appointment.query.filter_by(client_id=client.id)
            .order_by(Appointment.scheduled_for.desc())
            .all()
        )
        network_towers = (
            NetworkTower.query.order_by(NetworkTower.name.asc()).all()
        )

        current_time = utcnow()
        upcoming_appointments = []
        for appointment in appointments:
            scheduled_for = appointment.scheduled_for
            if scheduled_for.tzinfo is None:
                scheduled_for = scheduled_for.replace(tzinfo=UTC)
            if scheduled_for >= current_time:
                upcoming_appointments.append(appointment)

        photo_map: dict[str, list[InstallPhoto]] = {
            category: [] for category in install_photo_categories
        }
        client_photos = (
            InstallPhoto.query.filter_by(client_id=client.id)
            .order_by(InstallPhoto.uploaded_at.desc())
            .all()
        )
        for photo in client_photos:
            photo_map.setdefault(photo.category, []).append(photo)

        missing_photo_categories = [
            category
            for category in required_photo_categories
            if not photo_map.get(category)
        ]

        service_groups: list[tuple[str, str]] = []
        if client.residential_plan:
            service_groups.append(("Residential", client.residential_plan))
        if client.business_plan:
            service_groups.append(("Business", client.business_plan))
        if client.phone_plan:
            service_groups.append(("Phone Service", client.phone_plan))

        categorized_plans = {
            category: plans
            for category, plans in get_ordered_service_plan_categories()
        }
        plan_field_config: list[dict[str, object]] = []
        for category, field_name, label in PLAN_FIELD_DEFINITIONS:
            plans = categorized_plans.get(category)
            if not plans:
                continue
            plan_field_config.append(
                {
                    "category": category,
                    "field": field_name,
                    "label": label,
                    "plans": plans,
                    "selected": getattr(client, field_name) or "",
                }
            )

        outstanding_invoices = [
            invoice
            for invoice in invoices
            if invoice.status not in {"Paid", "Cancelled"}
        ]
        outstanding_balance_cents = sum(
            invoice.amount_cents for invoice in outstanding_invoices
        )

        due_dates = [
            invoice.due_date
            for invoice in outstanding_invoices
            if invoice.due_date is not None
        ]
        upcoming_due_date = min(due_dates) if due_dates else None

        open_ticket_count = sum(
            1 for ticket in tickets if ticket.status in {"Open", "In Progress"}
        )

        address = client.address or ""
        encoded_address = quote_plus(address) if address else None
        google_maps_url = (
            f"https://www.google.com/maps/dir/?api=1&destination={encoded_address}"
            if encoded_address
            else None
        )
        apple_maps_url = (
            f"https://maps.apple.com/?daddr={encoded_address}"
            if encoded_address
            else None
        )

        technicians = (
            Technician.query.order_by(Technician.name.asc()).all()
        )

        payment_methods = (
            PaymentMethod.query.filter_by(client_id=client.id)
            .order_by(PaymentMethod.created_at.desc())
            .all()
        )
        autopay_activity = (
            AutopayEvent.query.filter_by(client_id=client.id)
            .order_by(AutopayEvent.attempted_at.desc())
            .limit(10)
            .all()
        )
        latest_acknowledgement = (
            InstallAcknowledgement.query.filter_by(client_id=client.id)
            .order_by(InstallAcknowledgement.signed_at.desc())
            .first()
        )
        current_year = date.today().year

        return render_template(
            "admin_client_account.html",
            client=client,
            invoices=invoices,
            equipment_items=equipment_items,
            tickets=tickets,
            appointments=appointments,
            photo_map=photo_map,
            missing_photo_categories=missing_photo_categories,
            service_groups=service_groups,
            portal_enabled=bool(client.portal_password_hash),
            outstanding_balance_cents=outstanding_balance_cents,
            upcoming_due_date=upcoming_due_date,
            open_ticket_count=open_ticket_count,
            google_maps_url=google_maps_url,
            apple_maps_url=apple_maps_url,
            required_photo_categories=required_photo_categories,
            install_photo_categories=install_photo_categories,
            ticket_priority_options=TICKET_PRIORITY_OPTIONS,
            upcoming_appointments=upcoming_appointments,
            plan_field_config=plan_field_config,
            status_options=STATUS_OPTIONS,
            invoice_status_options=INVOICE_STATUS_OPTIONS,
            appointment_status_options=APPOINTMENT_STATUS_OPTIONS,
            technicians=technicians,
            payment_methods=payment_methods,
            autopay_activity=autopay_activity,
            latest_acknowledgement=latest_acknowledgement,
            current_year=current_year,
            stripe_ready=stripe_active(),
            stripe_publishable_key=current_app.config.get("STRIPE_PUBLISHABLE_KEY"),
            assigned_uisp_devices=assigned_uisp_devices,
            available_uisp_devices=available_uisp_devices,
            network_towers=network_towers,
        )

    @app.post("/documents/upload")
    @login_required
    def upload_document():
        ensure_file_surface_enabled("legal-documents")
        doc_type = request.form.get("doc_type", "")
        file = request.files.get("document")

        if doc_type not in LEGAL_DOCUMENT_TYPES:
            flash("Invalid document category.", "danger")
            return redirect(url_for("dashboard", section="legal"))

        if not file or not file.filename:
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("dashboard", section="legal"))

        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
            allowed_list = ", ".join(sorted(ALLOWED_DOCUMENT_EXTENSIONS))
            flash(f"Unsupported file type. Allowed formats: {allowed_list}.", "danger")
            return redirect(url_for("dashboard", section="legal"))

        upload_folder = Path(app.config["LEGAL_UPLOAD_FOLDER"])
        os.makedirs(upload_folder, exist_ok=True)

        stored_filename = f"{doc_type}_{int(utcnow().timestamp())}.{extension}"
        file_path = upload_folder / stored_filename
        file.save(file_path)

        document = Document.query.filter_by(doc_type=doc_type).first()
        if document:
            previous_path = upload_folder / document.stored_filename
            if previous_path.exists():
                previous_path.unlink()
            document.original_filename = file.filename
            document.stored_filename = stored_filename
            document.uploaded_at = utcnow()
        else:
            document = Document(
                doc_type=doc_type,
                original_filename=file.filename,
                stored_filename=stored_filename,
            )
            db.session.add(document)

        db.session.commit()
        flash(f"{LEGAL_DOCUMENT_TYPES[doc_type]['label']} uploaded successfully.", "success")
        return redirect(url_for("dashboard", section="legal"))

    @app.get("/documents/<doc_type>/file")
    def serve_document_file(doc_type: str):
        document, upload_folder, file_path = _resolve_document(doc_type)
        extension = file_path.suffix.lower().lstrip(".")
        mimetype = DOCUMENT_MIME_TYPES.get(extension, "application/octet-stream")

        return send_site_file(
            "legal-documents",
            upload_folder,
            document.stored_filename,
            mimetype=mimetype,
            as_attachment=False,
            download_name=document.original_filename,
        )

    @app.get("/documents/<doc_type>")
    def download_document(doc_type: str):
        document, upload_folder, _ = _resolve_document(doc_type)

        return send_site_file(
            "legal-documents",
            upload_folder,
            document.stored_filename,
            as_attachment=True,
            download_name=document.original_filename,
        )

    @app.get("/documents/<doc_type>/view")
    def view_document(doc_type: str):
        document, _, file_path = _resolve_document(doc_type)
        extension = file_path.suffix.lower().lstrip(".")
        file_url = url_for("serve_document_file", doc_type=doc_type, _external=True)

        if extension == "pdf":
            embed_url = file_url
            viewer = "pdf"
        else:
            embed_url = (
                "https://view.officeapps.live.com/op/embed.aspx?src="
                + quote_plus(file_url)
            )
            viewer = "office"

        metadata = LEGAL_DOCUMENT_TYPES.get(doc_type)
        if not metadata:
            abort(404)

        return render_template(
            "document_viewer.html",
            document=document,
            metadata=metadata,
            embed_url=embed_url,
            viewer=viewer,
        )

    @app.post("/clients/<int:client_id>/portal/reset-password")
    @login_required
    def reset_portal_password(client_id: int):
        client = Client.query.get_or_404(client_id)
        temporary_password = generate_portal_password()
        client.portal_password_hash = generate_password_hash(temporary_password)
        client.portal_password_updated_at = utcnow()
        client.portal_access_code = secrets.token_hex(16)
        db.session.commit()
        flash(
            f"Temporary portal password for {client.email}: {temporary_password}",
            "info",
        )
        return _redirect_back_to_dashboard("customers", focus=client_id)

    @app.post("/clients/<int:client_id>/portal/set-password")
    @login_required
    def set_portal_password(client_id: int):
        client = Client.query.get_or_404(client_id)
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not password:
            flash("Please provide a password for the client portal.", "danger")
            return _redirect_back_to_dashboard("customers", focus=client_id)

        if password != confirm:
            flash("Passwords do not match. Please try again.", "danger")
            return _redirect_back_to_dashboard("customers", focus=client_id)

        if len(password) < 8:
            flash("Portal passwords must be at least 8 characters long.", "danger")
            return _redirect_back_to_dashboard("customers", focus=client_id)

        client.portal_password_hash = generate_password_hash(password)
        client.portal_password_updated_at = utcnow()
        client.portal_access_code = secrets.token_hex(16)
        db.session.commit()
        flash(f"Portal password updated for {client.email}.", "success")
        return _redirect_back_to_dashboard("customers", focus=client_id)

    def _redirect_back_to_dashboard(
        default_section: str = "overview", focus: int | None = None
    ):
        next_url = request.args.get("next") or request.form.get("next")
        if next_url:
            return redirect(next_url)

        params: dict[str, str] = {}
        status_value = request.args.get("status")
        if status_value:
            params["status"] = status_value
        section_value = request.args.get("section") or default_section
        if section_value:
            params["section"] = section_value
        focus_value: str | None = request.args.get("focus")
        if focus is not None:
            focus_value = str(focus)
        if focus_value:
            params["focus"] = focus_value
        return redirect(url_for("dashboard", **params))

    @app.post("/dashboard/field/schedule/<int:block_id>/approve")
    @login_required
    def approve_technician_schedule(block_id: int):
        schedule_block = TechnicianSchedule.query.get_or_404(block_id)
        note = request.form.get("note", "").strip() or None
        admin_id = session.get("admin_user_id")
        status = schedule_block.status
        technician_name = (
            schedule_block.technician.name if schedule_block.technician else "technician"
        )

        if status in {"pending", "rejected"}:
            schedule_block.status = "approved"
            schedule_block.review_note = note
            schedule_block.reviewed_at = utcnow()
            schedule_block.reviewed_by_id = admin_id
            schedule_block.cancel_requested_at = None
            db.session.commit()
            flash(
                f"Shift on {schedule_block.start_at.strftime('%b %d, %Y')} for "
                f"{technician_name} approved.",
                "success",
            )
            return _redirect_back_to_dashboard("field")

        if status == "cancel_pending":
            schedule_block.status = "cancelled"
            schedule_block.review_note = note
            schedule_block.reviewed_at = utcnow()
            schedule_block.reviewed_by_id = admin_id
            schedule_block.cancel_requested_at = None
            db.session.commit()
            flash(
                f"Cancellation approved. {technician_name}'s shift was removed.",
                "success",
            )
            return _redirect_back_to_dashboard("field")

        flash("Schedule change already processed.", "info")
        return _redirect_back_to_dashboard("field")

    @app.post("/dashboard/field/schedule/<int:block_id>/reject")
    @login_required
    def reject_technician_schedule(block_id: int):
        schedule_block = TechnicianSchedule.query.get_or_404(block_id)
        note = request.form.get("note", "").strip() or None
        admin_id = session.get("admin_user_id")
        status = schedule_block.status
        technician_name = (
            schedule_block.technician.name if schedule_block.technician else "technician"
        )

        if status == "pending":
            schedule_block.status = "rejected"
            schedule_block.review_note = note
            schedule_block.reviewed_at = utcnow()
            schedule_block.reviewed_by_id = admin_id
            schedule_block.cancel_requested_at = None
            db.session.commit()
            flash(
                f"Schedule request for {technician_name} declined.",
                "info",
            )
            return _redirect_back_to_dashboard("field")

        if status == "cancel_pending":
            schedule_block.status = "approved"
            schedule_block.review_note = note
            schedule_block.reviewed_at = utcnow()
            schedule_block.reviewed_by_id = admin_id
            schedule_block.cancel_requested_at = None
            db.session.commit()
            flash(
                f"Cancellation denied. {technician_name}'s shift remains scheduled.",
                "warning",
            )
            return _redirect_back_to_dashboard("field")

        flash("Schedule change already resolved.", "info")
        return _redirect_back_to_dashboard("field")

    @app.post("/clients")
    @login_required
    def create_client_admin():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        company = request.form.get("company", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        service_plan = request.form.get("service_plan", "").strip()
        residential_plan = request.form.get("residential_plan", "").strip()
        phone_plan = request.form.get("phone_plan", "").strip()
        business_plan = request.form.get("business_plan", "").strip()
        status_value = request.form.get("status", "New").strip() or "New"
        notes = request.form.get("notes", "").strip()
        driver_license_number = request.form.get("driver_license_number", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        verification_file = request.files.get("verification_photo")
        wifi_router_needed = (
            request.form.get("wifi_router_needed", "no").strip().lower() == "yes"
        )

        if not name or not email:
            flash("Customer name and email are required.", "danger")
            return _redirect_back_to_dashboard("customers")

        existing = Client.query.filter_by(email=email).first()
        if existing:
            flash("A customer with that email already exists.", "warning")
            return _redirect_back_to_dashboard("customers")

        if status_value not in STATUS_OPTIONS:
            status_value = "New"

        if password and len(password) < 8:
            flash("Portal passwords must be at least 8 characters long.", "danger")
            return _redirect_back_to_dashboard("customers")

        if password and password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return _redirect_back_to_dashboard("customers")

        if verification_file and verification_file.filename:
            ensure_file_surface_enabled("client-verification")
        if verification_file and verification_file.filename and not allowed_verification_file(
            verification_file.filename
        ):
            flash("Upload a JPG, PNG, HEIC, or PDF file for verification.", "danger")
            return _redirect_back_to_dashboard("customers")

        selected_services = [
            value
            for value in (residential_plan, phone_plan, business_plan)
            if value
        ]
        plan_summary = ", ".join(selected_services) if selected_services else service_plan

        client = Client(
            name=name,
            email=email,
            phone=phone or None,
            address=address or None,
            company=company or None,
            project_type=plan_summary or None,
            residential_plan=residential_plan or None,
            phone_plan=phone_plan or None,
            business_plan=business_plan or None,
            notes=notes or None,
            status=status_value,
            driver_license_number=driver_license_number or None,
            wifi_router_needed=wifi_router_needed,
        )

        if password:
            client.portal_password_hash = generate_password_hash(password)
            client.portal_password_updated_at = utcnow()

        db.session.add(client)
        db.session.commit()

        if verification_file and verification_file.filename:
            store_client_verification_photo(app, client, verification_file)
            db.session.commit()

        flash(f"Customer {client.name} added.", "success")
        return _redirect_back_to_dashboard("customers")

    @app.post("/clients/<int:client_id>/service-plans")
    @login_required
    def update_client_service_plans(client_id: int):
        client = Client.query.get_or_404(client_id)
        residential_plan = request.form.get("residential_plan", "").strip()
        phone_plan = request.form.get("phone_plan", "").strip()
        business_plan = request.form.get("business_plan", "").strip()
        status_value = request.form.get("status", client.status).strip() or client.status
        wifi_router_flag = request.form.get("wifi_router_needed")

        if status_value not in STATUS_OPTIONS:
            status_value = client.status

        client.residential_plan = residential_plan or None
        client.phone_plan = phone_plan or None
        client.business_plan = business_plan or None
        client.status = status_value
        client.wifi_router_needed = bool(wifi_router_flag)

        selected_services = [
            value
            for value in (
                client.residential_plan,
                client.phone_plan,
                client.business_plan,
            )
            if value
        ]
        client.project_type = ", ".join(selected_services) if selected_services else None

        db.session.commit()

        flash("Service plans updated.", "success")

        next_url = request.form.get("next") or request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("admin_client_account", client_id=client.id))

    @app.post("/clients/<int:client_id>/verification")
    @login_required
    def upload_client_verification(client_id: int):
        client = Client.query.get_or_404(client_id)
        action = request.form.get("action", "upload").strip().lower()

        if action == "remove":
            delete_client_verification_photo(app, client)
            client.verification_photo_filename = None
            client.verification_photo_uploaded_at = None
            db.session.commit()
            flash("Verification photo removed.", "info")
            return _redirect_back_to_dashboard("customers")

        file = request.files.get("verification_photo")
        if not file or not file.filename:
            flash("Choose a verification file to upload.", "danger")
            return _redirect_back_to_dashboard("customers")

        ensure_file_surface_enabled("client-verification")
        if not allowed_verification_file(file.filename):
            flash("Upload a JPG, PNG, HEIC, or PDF file for verification.", "danger")
            return _redirect_back_to_dashboard("customers")

        store_client_verification_photo(app, client, file)
        db.session.commit()

        flash("Verification photo updated.", "success")
        return _redirect_back_to_dashboard("customers")

    @app.get("/clients/<int:client_id>/payment-methods/setup-intent")
    @login_required
    def admin_payment_method_setup_intent(client_id: int):
        client = Client.query.get_or_404(client_id)

        if not stripe_active():
            return jsonify({"error": "Stripe is not configured."}), 400

        customer_id = ensure_stripe_customer(client)
        if customer_id is None:
            return jsonify({"error": "Unable to prepare Stripe customer."}), 400

        setup_intent = stripe.SetupIntent.create(
            customer=customer_id,
            usage="off_session",
            payment_method_types=["card"],
            metadata={
                "client_id": str(client.id),
                "created_by": "admin",
            },
        )

        return jsonify({"client_secret": setup_intent.client_secret})

    @app.post("/clients/<int:client_id>/payment-methods")
    @login_required
    def add_payment_method(client_id: int):
        client = Client.query.get_or_404(client_id)

        payload = request.get_json(silent=True)
        wants_json = payload is not None

        if not stripe_active():
            if wants_json:
                return (
                    jsonify({"error": "Stripe is not configured."}),
                    400,
                )
            flash(
                "Configure Stripe API keys before adding payment methods.",
                "danger",
            )
            return _redirect_back_to_dashboard("billing", focus=client.id)

        if payload is None:
            payload = {}

        payment_method_raw = payload.get("payment_method_id")
        if payment_method_raw is None:
            payment_method_raw = request.form.get("stripe_payment_method_id", "")
        stripe_payment_method_id = (payment_method_raw or "").strip()

        if "set_default" in payload:
            set_default_flag = payload.get("set_default")
        else:
            set_default_flag = request.form.get("set_default")
        set_default = is_truthy(set_default_flag) or not client.payment_methods

        if "nickname" in payload:
            nickname_raw = payload.get("nickname")
            nickname = (nickname_raw or "").strip() or None
        else:
            nickname = request.form.get("nickname", "").strip() or None

        if not stripe_payment_method_id:
            if wants_json:
                return (
                    jsonify({"error": "Provide a Stripe payment method identifier."}),
                    400,
                )
            flash("Provide a Stripe payment method identifier.", "danger")
            return _redirect_back_to_dashboard("billing", focus=client.id)

        try:
            payment_method = sync_stripe_payment_method(
                client,
                stripe_payment_method_id,
                set_default=set_default,
            )
        except StripeError as error:
            db.session.rollback()
            error_message = describe_stripe_error(error)
            if wants_json:
                return (
                    jsonify({"error": f"Unable to save the payment method: {error_message}"}),
                    400,
                )
            flash(
                f"Unable to save the payment method: {error_message}",
                "danger",
            )
            return _redirect_back_to_dashboard("billing", focus=client.id)
        except IntegrityError:
            db.session.rollback()
            current_app.logger.exception(
                "Failed to save Stripe payment method for client %s", client.id
            )
            if wants_json:
                return (
                    jsonify(
                        {
                            "error": (
                                "We couldn't save that card. Please try again or contact support."
                            )
                        }
                    ),
                    400,
                )
            flash(
                "We couldn't save that card. Please try again or contact support.",
                "danger",
            )
            return _redirect_back_to_dashboard("billing", focus=client.id)
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Unexpected error while saving payment method for client %s",
                client.id,
            )
            if wants_json:
                return (
                    jsonify(
                        {
                            "error": (
                                "Something went wrong while saving the card. Please try again."
                            )
                        }
                    ),
                    500,
                )
            flash(
                "Something went wrong while saving the card. Please try again.",
                "danger",
            )
            return _redirect_back_to_dashboard("billing", focus=client.id)

        if nickname:
            payment_method.nickname = nickname

        db.session.commit()

        if wants_json:
            return (
                jsonify(
                    {
                        "status": "ok",
                        "method": {
                            "id": payment_method.id,
                            "brand": payment_method.brand,
                            "last4": payment_method.last4,
                            "exp_month": payment_method.exp_month,
                            "exp_year": payment_method.exp_year,
                            "cardholder_name": payment_method.cardholder_name,
                            "is_default": payment_method.is_default,
                        },
                    }
                ),
                200,
            )

        flash(f"Saved {payment_method.describe()} for {client.name}.", "success")

        next_url = request.form.get("next") or request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("admin_client_account", client_id=client.id))

    @app.post("/payment-methods/<int:method_id>/make-default")
    @login_required
    def make_default_payment_method(method_id: int):
        method = PaymentMethod.query.get_or_404(method_id)
        client = method.client
        for other in client.payment_methods:
            other.is_default = other.id == method.id
        if stripe_active() and method.token:
            try:
                customer_id = ensure_stripe_customer(client)
                if customer_id:
                    stripe.Customer.modify(
                        customer_id,
                        invoice_settings={"default_payment_method": method.token},
                    )
            except StripeError as error:
                flash(
                    f"Stripe update failed: {describe_stripe_error(error)}",
                    "warning",
                )
        db.session.commit()

        flash(f"{method.describe()} is now the default payment method.", "success")

        next_url = request.form.get("next") or request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("admin_client_account", client_id=client.id))

    @app.post("/payment-methods/<int:method_id>/delete")
    @login_required
    def delete_payment_method(method_id: int):
        method = PaymentMethod.query.get_or_404(method_id)
        client = method.client
        stripe_id = method.token or method.stripe_payment_method_id
        if stripe_active() and stripe_id:
            try:
                stripe.PaymentMethod.detach(stripe_id)
            except StripeError as error:
                flash(
                    f"Stripe detach failed: {describe_stripe_error(error)}",
                    "warning",
                )
        db.session.delete(method)
        db.session.flush()

        autopay_disabled = False
        if client.autopay_enabled and not client.default_payment_method():
            client.autopay_enabled = False
            autopay_disabled = True

        if autopay_disabled and stripe_active():
            try:
                customer_id = ensure_stripe_customer(client)
                if customer_id:
                    stripe.Customer.modify(
                        customer_id,
                        invoice_settings={"default_payment_method": None},
                    )
            except StripeError:
                pass

        db.session.commit()

        message = f"Removed {method.describe()} from {client.name}."
        if autopay_disabled:
            message += " Autopay was disabled because no default method remains."
        flash(message, "info")

        next_url = request.form.get("next") or request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("admin_client_account", client_id=client.id))

    @app.post("/clients/<int:client_id>/autopay")
    @login_required
    def configure_autopay(client_id: int):
        client = Client.query.get_or_404(client_id)
        action = (request.form.get("action") or "enable").strip().lower()

        if action == "disable":
            client.autopay_enabled = False
            db.session.commit()
            flash(f"Autopay disabled for {client.name}.", "info")
            next_url = request.form.get("next") or request.args.get("next")
            if next_url:
                return redirect(next_url)
            return redirect(url_for("admin_client_account", client_id=client.id))

        if not stripe_active():
            flash("Enable Stripe before turning on autopay.", "danger")
            return redirect(url_for("admin_client_account", client_id=client.id))

        method_id = request.form.get("payment_method_id", type=int)
        if method_id:
            method = PaymentMethod.query.filter_by(id=method_id, client_id=client.id).first()
            if method is None:
                flash("Select a valid payment method to enable autopay.", "danger")
                return redirect(url_for("admin_client_account", client_id=client.id))
        else:
            method = client.default_payment_method()

        if method is None:
            flash("Add a payment method before enabling autopay.", "danger")
            return redirect(url_for("admin_client_account", client_id=client.id))

        if not method.token or not method.token.startswith("pm_"):
            flash(
                "Autopay requires a Stripe card on file. Ask the customer to update their card.",
                "danger",
            )
            return redirect(url_for("admin_client_account", client_id=client.id))

        for other in client.payment_methods:
            other.is_default = other.id == method.id
        client.autopay_enabled = True
        try:
            customer_id = ensure_stripe_customer(client)
            if customer_id:
                stripe.Customer.modify(
                    customer_id,
                    invoice_settings={"default_payment_method": method.token},
                )
        except StripeError as error:
            db.session.rollback()
            flash(
                f"Stripe rejected the autopay update: {describe_stripe_error(error)}",
                "danger",
            )
            return redirect(url_for("admin_client_account", client_id=client.id))

        db.session.commit()

        flash(f"Autopay enabled using {method.describe()}.", "success")

        next_url = request.form.get("next") or request.args.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("admin_client_account", client_id=client.id))

    @app.post("/autopay/run")
    @login_required
    def run_autopay():
        if not stripe_active():
            flash(
                "Stripe is not configured, so autopay cannot process charges.",
                "warning",
            )
            return _redirect_back_to_dashboard("billing")

        today = date.today()
        autopay_clients = Client.query.filter_by(autopay_enabled=True).all()
        processed_accounts = 0
        submitted_charges = 0
        failed_charges = 0
        skipped_accounts = 0

        for client in autopay_clients:
            default_method = client.default_payment_method()
            due_invoices = [
                invoice
                for invoice in client.invoices
                if invoice.status in {"Pending", "Overdue"}
                and (invoice.due_date is None or invoice.due_date <= today)
            ]

            if not due_invoices:
                if default_method:
                    record_autopay_event(
                        client=client,
                        invoice=None,
                        payment_method=default_method,
                        status="skipped",
                        message="No invoices due",
                        amount_cents=0,
                    )
                skipped_accounts += 1
                continue

            processed_accounts += 1

            if (
                default_method is None
                or not default_method.token
                or not default_method.token.startswith("pm_")
            ):
                for invoice in due_invoices:
                    invoice.autopay_attempted_at = utcnow()
                    invoice.autopay_status = "Missing Method"
                    record_autopay_event(
                        client=client,
                        invoice=invoice,
                        payment_method=None,
                        status="failed",
                        message="Autopay failed: no default method",
                        amount_cents=invoice.amount_cents,
                    )
                    failed_charges += 1
                recalculate_client_billing_state(client)
                continue

            try:
                sync_stripe_payment_method(client, default_method.token, set_default=True)
            except StripeError as error:
                for invoice in due_invoices:
                    invoice.autopay_attempted_at = utcnow()
                    invoice.autopay_status = "Failed"
                    record_autopay_event(
                        client=client,
                        invoice=invoice,
                        payment_method=default_method,
                        status="failed",
                        message=f"Autopay failed to sync card: {describe_stripe_error(error)}",
                        amount_cents=invoice.amount_cents,
                    )
                    failed_charges += 1
                recalculate_client_billing_state(client)
                continue

            for invoice in due_invoices:
                try:
                    payment_intent = ensure_invoice_payment_intent(
                        invoice,
                        autopay=True,
                        client=client,
                        payment_method_id=default_method.token,
                    )
                except StripeError as error:
                    invoice.autopay_attempted_at = utcnow()
                    invoice.autopay_status = "Failed"
                    record_autopay_event(
                        client=client,
                        invoice=invoice,
                        payment_method=default_method,
                        status="failed",
                        message=describe_stripe_error(error),
                        amount_cents=invoice.amount_cents,
                    )
                    failed_charges += 1
                    continue

                invoice.autopay_attempted_at = utcnow()
                if payment_intent is None:
                    invoice.autopay_status = "Manual"
                    continue

                invoice.autopay_status = "Processing"
                record_autopay_event(
                    client=client,
                    invoice=invoice,
                    payment_method=default_method,
                    status="pending",
                    message="Submitted to Stripe for processing",
                    amount_cents=invoice.amount_cents,
                    stripe_payment_intent_id=payment_intent.id,
                )
                submitted_charges += 1

            recalculate_client_billing_state(client)

        for client in Client.query.filter_by(autopay_enabled=False).all():
            recalculate_client_billing_state(client)

        db.session.commit()

        summary = (
            f"Autopay processed {processed_accounts} accounts and submitted "
            f"{submitted_charges} payments to Stripe"
        )
        if failed_charges:
            summary += f" and {failed_charges} failures"
        if skipped_accounts:
            summary += f"; {skipped_accounts} accounts had nothing due"

        flash(summary + ".", "info" if failed_charges == 0 else "warning")
        return _redirect_back_to_dashboard("billing")

    @app.post("/stripe/webhook")
    def stripe_webhook():
        if not stripe_active():
            return jsonify({"status": "disabled"}), 200

        payload = request.data
        sig_header = request.headers.get("Stripe-Signature")
        webhook_secret = current_app.config.get("STRIPE_WEBHOOK_SECRET")

        try:
            if webhook_secret:
                event = stripe.Webhook.construct_event(
                    payload, sig_header, webhook_secret
                )
            else:
                json_payload = json.loads(payload.decode("utf-8"))
                event = stripe.Event.construct_from(json_payload, stripe.api_key)
        except (ValueError, SignatureVerificationError, StripeError) as error:
            return jsonify({"error": str(error)}), 400

        handled = handle_stripe_event(event)
        if handled:
            db.session.commit()
            invalidate_dashboard_overview_cache()
            invalidate_site_shell_cache()
            return jsonify({"status": "ok"}), 200

        db.session.rollback()
        return jsonify({"status": "ignored"}), 200

    @app.post("/clients/<int:client_id>/invoices")
    @login_required
    def create_invoice(client_id: int):
        client = Client.query.get_or_404(client_id)
        description = request.form.get("description", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        due_date_raw = request.form.get("due_date", "").strip()
        status_value = request.form.get("status", "Pending").strip() or "Pending"

        if not description or not amount_raw:
            flash("Invoice description and amount are required.", "danger")
            return _redirect_back_to_dashboard("billing")

        try:
            amount_decimal = Decimal(amount_raw).quantize(Decimal("0.01"))
        except (InvalidOperation, TypeError):
            flash("Please provide a valid invoice amount.", "danger")
            return _redirect_back_to_dashboard("billing")

        amount_cents = int(amount_decimal * 100)
        if amount_cents < 0:
            flash("Invoice amounts must be positive.", "danger")
            return _redirect_back_to_dashboard("billing")

        due_date_value = None
        if due_date_raw:
            try:
                due_date_value = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for due dates.", "danger")
                return _redirect_back_to_dashboard("billing")

        if status_value not in INVOICE_STATUS_OPTIONS:
            status_value = "Pending"

        invoice = Invoice(
            client_id=client.id,
            description=description,
            amount_cents=amount_cents,
            due_date=due_date_value,
            status=status_value,
        )
        if status_value == "Paid":
            invoice.paid_at = utcnow()
            invoice.paid_via = "Manual entry"
            invoice.autopay_status = "Manual"
        db.session.add(invoice)
        recalculate_client_billing_state(client)
        db.session.commit()

        if client.email:
            amount_display = f"${(Decimal(invoice.amount_cents) / Decimal(100)).quantize(Decimal('0.01')):,.2f}"
            due_line = (
                f"Due date: {invoice.due_date.strftime('%Y-%m-%d')}"
                if invoice.due_date
                else "Due date: Not set"
            )
            dispatch_notification(
                client.email,
                f"Invoice posted: {invoice.description}",
                (
                    f"Hello {client.name},\n\n"
                    f"We've posted a new invoice (#{invoice.id}) for {amount_display}.\n"
                    f"Description: {invoice.description}\n"
                    f"{due_line}\n"
                    f"Status: {invoice.status}\n\n"
                    "You can review this invoice and make payments in your customer portal."
                ),
                category="billing",
            )

        flash(f"Invoice added for {client.name}.", "success")
        return _redirect_back_to_dashboard("billing")

    @app.post("/invoices/<int:invoice_id>/update")
    @login_required
    def update_invoice(invoice_id: int):
        invoice = Invoice.query.get_or_404(invoice_id)
        description = request.form.get("description", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        due_date_raw = request.form.get("due_date", "").strip()
        status_value = request.form.get("status", invoice.status).strip() or invoice.status

        if not description or not amount_raw:
            flash("Description and amount are required to update an invoice.", "danger")
            return _redirect_back_to_dashboard("billing")

        try:
            amount_decimal = Decimal(amount_raw).quantize(Decimal("0.01"))
        except (InvalidOperation, TypeError):
            flash("Please provide a valid invoice amount.", "danger")
            return _redirect_back_to_dashboard("billing")

        amount_cents = int(amount_decimal * 100)
        if amount_cents < 0:
            flash("Invoice amounts must be positive.", "danger")
            return _redirect_back_to_dashboard("billing")

        due_date_value = None
        if due_date_raw:
            try:
                due_date_value = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for due dates.", "danger")
                return _redirect_back_to_dashboard("billing")

        if status_value not in INVOICE_STATUS_OPTIONS:
            flash("Unknown invoice status.", "danger")
            return _redirect_back_to_dashboard("billing")

        invoice.description = description
        invoice.amount_cents = amount_cents
        invoice.due_date = due_date_value
        invoice.status = status_value
        invoice.updated_at = utcnow()
        if status_value == "Paid":
            invoice.paid_at = invoice.paid_at or utcnow()
            if not invoice.paid_via:
                invoice.paid_via = "Manual update"
            invoice.autopay_status = invoice.autopay_status or "Manual"
        else:
            invoice.paid_via = None
            if status_value != "Paid":
                invoice.paid_at = None
        recalculate_client_billing_state(invoice.client)
        db.session.commit()

        client = invoice.client
        if client and client.email:
            amount_display = f"${(Decimal(invoice.amount_cents) / Decimal(100)).quantize(Decimal('0.01')):,.2f}"
            due_line = (
                f"Due date: {invoice.due_date.strftime('%Y-%m-%d')}"
                if invoice.due_date
                else "Due date: Not set"
            )
            dispatch_notification(
                client.email,
                f"Invoice updated: {invoice.description}",
                (
                    f"Hello {client.name},\n\n"
                    f"We've updated your invoice (#{invoice.id}).\n"
                    f"Description: {invoice.description}\n"
                    f"Amount: {amount_display}\n"
                    f"{due_line}\n"
                    f"Status: {invoice.status}\n\n"
                    "Log in to your customer portal to review the latest details."
                ),
                category="billing",
            )

        flash("Invoice updated.", "success")
        return _redirect_back_to_dashboard("billing")

    @app.post("/invoices/<int:invoice_id>/delete")
    @login_required
    def delete_invoice(invoice_id: int):
        invoice = Invoice.query.get_or_404(invoice_id)
        client = invoice.client
        db.session.delete(invoice)
        recalculate_client_billing_state(client)
        db.session.commit()
        flash("Invoice removed.", "info")
        return _redirect_back_to_dashboard("billing")

    @app.post("/invoices/<int:invoice_id>/refund")
    @login_required
    def refund_invoice(invoice_id: int):
        invoice = Invoice.query.get_or_404(invoice_id)
        if not stripe_active() or not invoice.stripe_payment_intent_id:
            flash("Refunds require a completed Stripe payment.", "danger")
            return _redirect_back_to_dashboard("billing", focus=invoice.client_id)

        try:
            refund = stripe.Refund.create(
                payment_intent=invoice.stripe_payment_intent_id,
                amount=invoice.amount_cents,
            )
        except StripeError as error:
            flash(
                f"Unable to issue the refund: {describe_stripe_error(error)}",
                "danger",
            )
            return _redirect_back_to_dashboard("billing", focus=invoice.client_id)

        invoice.status = "Refunded"
        invoice.autopay_status = "Refunded"
        invoice.stripe_refund_id = getattr(refund, "id", invoice.stripe_refund_id)
        record_autopay_event(
            client=invoice.client,
            invoice=invoice,
            payment_method=None,
            status="refunded",
            message="Refund issued via Stripe",
            amount_cents=invoice.amount_cents,
            stripe_payment_intent_id=invoice.stripe_payment_intent_id,
        )
        recalculate_client_billing_state(invoice.client)
        db.session.commit()

        flash("Refund initiated with Stripe.", "success")
        return _redirect_back_to_dashboard("billing", focus=invoice.client_id)

    @app.post("/uisp/config")
    @login_required
    def update_uisp_config():
        base_url = (request.form.get("base_url") or "").strip()
        api_token = (request.form.get("api_token") or "").strip()
        auto_sync_enabled = is_truthy(request.form.get("auto_sync_enabled"))
        interval_raw = (request.form.get("auto_sync_interval") or "").strip()

        if interval_raw:
            try:
                interval = int(interval_raw)
            except ValueError:
                flash("Sync interval must be a valid number of minutes.", "danger")
                return _redirect_back_to_dashboard("network")
        else:
            interval = 30

        interval = max(5, min(interval, 1440))

        config = _get_uisp_config()
        if not config:
            config = UispConfig()
            db.session.add(config)

        config.base_url = base_url or None
        config.api_token = api_token or None
        config.auto_sync_enabled = auto_sync_enabled
        config.auto_sync_interval_minutes = interval
        config.updated_at = utcnow()
        db.session.commit()

        if base_url:
            app.config["UISP_BASE_URL"] = base_url
        if api_token:
            app.config["UISP_API_TOKEN"] = api_token

        flash("UISP settings updated.", "success")
        return _redirect_back_to_dashboard("network")

    @app.post("/network/towers")
    @login_required
    def create_network_tower():
        name = (request.form.get("name") or "").strip()
        location = (request.form.get("location") or "").strip() or None
        notes = (request.form.get("notes") or "").strip() or None

        if not name:
            flash("Tower name is required.", "danger")
            return _redirect_back_to_dashboard("network")

        tower = NetworkTower(name=name, location=location, notes=notes)
        db.session.add(tower)
        db.session.commit()

        flash(f"Tower {tower.name} added.", "success")
        return _redirect_back_to_dashboard("network")

    @app.post("/network/towers/<int:tower_id>/update")
    @login_required
    def update_network_tower(tower_id: int):
        tower = NetworkTower.query.get_or_404(tower_id)
        name = (request.form.get("name") or "").strip()
        location = (request.form.get("location") or "").strip() or None
        notes = (request.form.get("notes") or "").strip() or None

        if not name:
            flash("Tower name is required.", "danger")
            return _redirect_back_to_dashboard("network")

        tower.name = name
        tower.location = location
        tower.notes = notes
        tower.updated_at = utcnow()
        db.session.commit()

        flash("Tower details updated.", "success")
        return _redirect_back_to_dashboard("network")

    @app.post("/network/towers/<int:tower_id>/delete")
    @login_required
    def delete_network_tower(tower_id: int):
        tower = NetworkTower.query.get_or_404(tower_id)
        for device in tower.devices:
            device.tower = None
            device.updated_at = utcnow()
        db.session.delete(tower)
        db.session.commit()

        flash("Tower removed.", "info")
        return _redirect_back_to_dashboard("network")

    @app.post("/uisp/devices/import")
    @login_required
    def import_uisp_devices():
        try:
            api_client = _build_uisp_client()
        except UispApiError:
            flash(
                "Add your UISP base URL and API token before syncing devices.",
                "danger",
            )
            return _redirect_back_to_dashboard("network")

        try:
            payload = api_client.fetch_devices()
        except UispApiError as exc:
            flash(f"Unable to sync UISP devices: {exc}", "danger")
            return _redirect_back_to_dashboard("network")

        if not payload:
            flash("No devices were returned from UISP.", "info")
            return _redirect_back_to_dashboard("network")

        def _clean_string(value: object | None) -> str | None:
            if value is None:
                return None
            if isinstance(value, str):
                cleaned = value.strip()
            else:
                cleaned = str(value).strip()
            return cleaned or None

        created = 0
        updated = 0
        outages = 0
        now = utcnow()
        _, _, config = _resolve_uisp_credentials()
        towers_by_name = {
            tower.name.lower(): tower
            for tower in NetworkTower.query.order_by(NetworkTower.name.asc()).all()
        }

        for entry in payload:
            uisp_id = _clean_string(entry.get("id") or entry.get("_id"))
            if not uisp_id:
                continue

            identification = entry.get("identification") or {}
            name = (
                _clean_string(identification.get("name") or entry.get("name"))
                or f"UISP Device {uisp_id}"
            )
            model = _clean_string(identification.get("model") or entry.get("model"))
            mac = _clean_string(
                identification.get("mac")
                or entry.get("macAddress")
                or entry.get("mac")
            )
            site_info = entry.get("site") or {}
            site_name = _clean_string(site_info.get("name") or entry.get("siteName"))
            ip_address = _clean_string(entry.get("ipAddress") or entry.get("ip"))

            status_info = entry.get("status") or {}
            status_raw = (
                status_info.get("value")
                or status_info.get("state")
                or entry.get("status")
            )
            if status_raw is None and isinstance(status_info.get("online"), bool):
                status_raw = "online" if status_info.get("online") else "offline"
            status_value = (_clean_string(status_raw) or "unknown").lower()
            if status_value not in {"online", "offline"}:
                if "off" in status_value:
                    status_value = "offline"
                elif "on" in status_value:
                    status_value = "online"
                else:
                    status_value = "unknown"

            last_seen = parse_uisp_timestamp(
                status_info.get("lastSeen")
                or status_info.get("last_seen")
                or entry.get("lastSeen")
                or entry.get("last_seen")
            )

            firmware_info = entry.get("firmware") or {}
            firmware_version = _clean_string(
                firmware_info.get("version")
                or entry.get("firmwareVersion")
                or entry.get("firmware_version")
            )

            device = UispDevice.query.filter_by(uisp_id=uisp_id).first()
            is_new = False
            if not device:
                device = UispDevice(uisp_id=uisp_id, name=name)
                db.session.add(device)
                created += 1
                is_new = True

            previous_status = device.status
            previous_values = (
                device.name,
                device.model,
                device.mac_address,
                device.site_name,
                device.ip_address,
                device.firmware_version,
                device.last_seen_at,
            )

            device.name = name
            device.model = model
            device.mac_address = mac
            device.site_name = site_name
            device.ip_address = ip_address
            device.firmware_version = firmware_version
            device.last_seen_at = last_seen
            device.updated_at = now

            if site_name and not device.tower_id:
                matched = towers_by_name.get(site_name.lower())
                if matched:
                    device.tower = matched

            status_changed = previous_status != status_value
            device.status = status_value

            if not is_new:
                if (
                    previous_values
                    != (
                        name,
                        model,
                        mac,
                        site_name,
                        ip_address,
                        firmware_version,
                        last_seen,
                    )
                    or status_changed
                ):
                    updated += 1

            should_notify_outage = (
                status_value == "offline"
                and (device.outage_notified_at is None or status_changed)
            )

            if should_notify_outage:
                recipients = _collect_outage_recipients(device)
                if recipients:
                    subject = f"Outage detected: {device.display_name()}"
                    body = (
                        "Hello,\n\n"
                        f"UISP has reported that {device.display_name()} is offline.\n"
                        f"Site: {device.site_name or 'Unknown'}\n"
                        f"Tower: {device.tower.name if device.tower else 'Unassigned'}\n"
                        f"IP address: {device.ip_address or 'N/A'}\n"
                        f"MAC address: {device.mac_address or 'N/A'}\n"
                        f"Last seen: {_format_last_seen(device.last_seen_at)}\n"
                        f"Assigned customer: {device.client.name if device.client else 'Unassigned'}\n\n"
                        "Technicians and administrators have been notified so service can be restored."
                    )
                    for recipient in recipients:
                        dispatch_notification(
                            recipient,
                            subject,
                            body,
                            category="network",
                        )
                device.outage_notified_at = now
                outages += 1
            elif status_value == "online" and status_changed:
                device.outage_notified_at = None

        db.session.commit()

        if config:
            config.last_synced_at = now
            config.updated_at = now
            db.session.commit()

        flash(
            (
                f"Synced {created} new UISP device{'s' if created != 1 else ''}"
                f" and updated {updated}."
                + (
                    f" Triggered {outages} outage alert{'s' if outages != 1 else ''}."
                    if outages
                    else ""
                )
            ),
            "success" if created or updated else "info",
        )

        return _redirect_back_to_dashboard("network")

    @app.post("/uisp/devices/<int:device_id>/assign")
    @login_required
    def assign_uisp_device(device_id: int):
        device = UispDevice.query.get_or_404(device_id)
        nickname = (request.form.get("nickname") or "").strip() or None
        notes = (request.form.get("notes") or "").strip() or None
        client_id_raw = (request.form.get("client_id") or "").strip()
        tower_id_raw = (request.form.get("tower_id") or "").strip()

        target_client: Client | None = None
        if client_id_raw:
            try:
                client_id = int(client_id_raw)
            except (TypeError, ValueError):
                flash("Select a valid customer for this device.", "danger")
                return _redirect_back_to_dashboard("network")

            target_client = Client.query.get(client_id)
            if not target_client:
                flash("The selected customer could not be found.", "danger")
                return _redirect_back_to_dashboard("network")

        target_tower: NetworkTower | None = None
        if tower_id_raw:
            try:
                tower_id = int(tower_id_raw)
            except (TypeError, ValueError):
                flash("Select a valid tower for this device.", "danger")
                return _redirect_back_to_dashboard("network")
            target_tower = NetworkTower.query.get(tower_id)
            if not target_tower:
                flash("The selected tower could not be found.", "danger")
                return _redirect_back_to_dashboard("network")

        previous_client_id = device.client_id
        previous_tower_id = device.tower_id
        device.nickname = nickname
        device.notes = notes
        device.client_id = target_client.id if target_client else None
        device.tower = target_tower
        device.updated_at = utcnow()

        if device.status == "online" and target_client is None:
            device.outage_notified_at = None

        db.session.commit()

        messages: list[str] = []
        if target_client and target_client.id != previous_client_id:
            messages.append(f"{device.display_name()} assigned to {target_client.name}.")
        elif target_client is None and previous_client_id is not None:
            messages.append(f"{device.display_name()} is now unassigned.")

        if target_tower and target_tower.id != previous_tower_id:
            messages.append(f"Linked to tower {target_tower.name}.")
        elif target_tower is None and previous_tower_id is not None:
            messages.append("Removed from its tower assignment.")

        if not messages:
            messages.append("UISP device details updated.")

        flash(" ".join(messages), "success")

        return _redirect_back_to_dashboard("network")

    @app.post("/clients/<int:client_id>/equipment")
    @login_required
    def create_equipment(client_id: int):
        client = Client.query.get_or_404(client_id)
        name = request.form.get("name", "").strip()
        model = request.form.get("model", "").strip() or None
        serial_number = request.form.get("serial_number", "").strip() or None
        installed_on_raw = request.form.get("installed_on", "").strip()
        notes = request.form.get("notes", "").strip() or None

        if not name:
            flash("Equipment name is required.", "danger")
            return _redirect_back_to_dashboard("network")

        installed_on_value = None
        if installed_on_raw:
            try:
                installed_on_value = datetime.strptime(installed_on_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for install dates.", "danger")
                return _redirect_back_to_dashboard("network")

        equipment = Equipment(
            client_id=client.id,
            name=name,
            model=model,
            serial_number=serial_number,
            installed_on=installed_on_value,
            notes=notes,
        )
        db.session.add(equipment)
        db.session.commit()

        if client.email:
            installed_line = (
                f"Installed on: {equipment.installed_on.strftime('%Y-%m-%d')}"
                if equipment.installed_on
                else "Installed on: Not set"
            )
            notes_line = f"Notes: {equipment.notes}\n" if equipment.notes else ""
            dispatch_notification(
                client.email,
                f"Equipment added: {equipment.name}",
                (
                    f"Hello {client.name},\n\n"
                    "We've added new equipment to your account.\n"
                    f"Name: {equipment.name}\n"
                    f"Model: {equipment.model or 'Not provided'}\n"
                    f"Serial: {equipment.serial_number or 'Not provided'}\n"
                    f"{installed_line}\n"
                    f"{notes_line}"
                    "\nYou can review your equipment details in the customer portal."
                ),
                category="account",
            )

        flash(f"Equipment added for {client.name}.", "success")
        return _redirect_back_to_dashboard("network")

    @app.post("/equipment/<int:equipment_id>/update")
    @login_required
    def update_equipment(equipment_id: int):
        equipment = Equipment.query.get_or_404(equipment_id)
        name = request.form.get("name", "").strip()
        model = request.form.get("model", "").strip() or None
        serial_number = request.form.get("serial_number", "").strip() or None
        installed_on_raw = request.form.get("installed_on", "").strip()
        notes = request.form.get("notes", "").strip() or None

        if not name:
            flash("Equipment name is required.", "danger")
            return _redirect_back_to_dashboard("network")

        installed_on_value = None
        if installed_on_raw:
            try:
                installed_on_value = datetime.strptime(installed_on_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for install dates.", "danger")
                return _redirect_back_to_dashboard("network")

        equipment.name = name
        equipment.model = model
        equipment.serial_number = serial_number
        equipment.installed_on = installed_on_value
        equipment.notes = notes
        db.session.commit()

        client = equipment.client
        if client and client.email:
            installed_line = (
                f"Installed on: {equipment.installed_on.strftime('%Y-%m-%d')}"
                if equipment.installed_on
                else "Installed on: Not set"
            )
            notes_line = f"Notes: {equipment.notes}\n" if equipment.notes else ""
            dispatch_notification(
                client.email,
                f"Equipment updated: {equipment.name}",
                (
                    f"Hello {client.name},\n\n"
                    "We've updated the equipment details on your account.\n"
                    f"Name: {equipment.name}\n"
                    f"Model: {equipment.model or 'Not provided'}\n"
                    f"Serial: {equipment.serial_number or 'Not provided'}\n"
                    f"{installed_line}\n"
                    f"{notes_line}"
                    "\nVisit your customer portal to review the latest equipment information."
                ),
                category="account",
            )

        flash("Equipment updated.", "success")
        return _redirect_back_to_dashboard("network")

    @app.post("/equipment/<int:equipment_id>/delete")
    @login_required
    def delete_equipment(equipment_id: int):
        equipment = Equipment.query.get_or_404(equipment_id)
        db.session.delete(equipment)
        db.session.commit()
        flash("Equipment removed.", "info")
        return _redirect_back_to_dashboard("network")

    @app.post("/appointments")
    @login_required
    def create_appointment_admin():
        client_id_raw = request.form.get("client_id", "").strip()
        title = request.form.get("title", "").strip()
        scheduled_for_raw = request.form.get("scheduled_for", "").strip()
        notes = request.form.get("notes", "").strip() or None
        technician_id_raw = request.form.get("technician_id", "").strip()
        technician: Technician | None = None

        try:
            client_id = int(client_id_raw)
        except (TypeError, ValueError):
            flash("Select a customer for the appointment.", "danger")
            return _redirect_back_to_dashboard("appointments")

        client = Client.query.get(client_id)
        if not client:
            flash("Customer not found.", "danger")
            return _redirect_back_to_dashboard("appointments")

        if not title:
            flash("Provide an appointment title.", "danger")
            return _redirect_back_to_dashboard("appointments")

        if not scheduled_for_raw:
            flash("Choose a scheduled date and time.", "danger")
            return _redirect_back_to_dashboard("appointments")

        try:
            scheduled_for_value = datetime.fromisoformat(scheduled_for_raw)
        except ValueError:
            flash("Use the provided picker to select a valid date and time.", "danger")
            return _redirect_back_to_dashboard("appointments")

        if scheduled_for_value.tzinfo is None:
            scheduled_for_value = scheduled_for_value.replace(tzinfo=UTC)

        if technician_id_raw:
            try:
                technician_id = int(technician_id_raw)
            except (TypeError, ValueError):
                flash("Choose a valid technician for the visit.", "danger")
                return _redirect_back_to_dashboard("appointments")

            technician = Technician.query.get(technician_id)
            if not technician:
                flash("Selected technician was not found.", "danger")
                return _redirect_back_to_dashboard("appointments")
            if not technician.is_active:
                flash("The selected technician is inactive.", "danger")
                return _redirect_back_to_dashboard("appointments")

        appointment = Appointment(
            client_id=client.id,
            title=title,
            scheduled_for=scheduled_for_value,
            status="Pending",
            notes=notes,
            technician_id=technician.id if technician else None,
        )

        db.session.add(appointment)
        db.session.commit()

        dispatch_notification(
            client.email,
            f"New appointment scheduled: {title}",
            (
                f"Hello {client.name},\n\n"
                f"An appointment titled '{title}' has been scheduled for "
                f"{appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}.\n"
                + (f"Notes: {appointment.notes}\n\n" if appointment.notes else "\n")
                + "Reply from your portal to confirm or request changes."
            ),
            category="customer",
        )

        if technician:
            dispatch_notification(
                technician.email,
                f"New field visit assigned: {title}",
                (
                    f"Client: {client.name}\n"
                    f"Scheduled for: {appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}\n"
                    + (f"Notes: {appointment.notes}\n" if appointment.notes else "")
                ),
                category="install",
            )

        flash("Appointment scheduled.", "success")
        return _redirect_back_to_dashboard("appointments")

    @app.post("/appointments/<int:appointment_id>/update")
    @login_required
    def update_appointment_admin(appointment_id: int):
        appointment = Appointment.query.get_or_404(appointment_id)
        previous_technician_id = appointment.technician_id
        status_value = (
            request.form.get("status", appointment.status).strip() or appointment.status
        )
        scheduled_for_raw = request.form.get("scheduled_for", "").strip()
        use_proposed = request.form.get("use_proposed") == "on"
        notes = request.form.get("notes", "").strip() or None
        technician_id_raw = request.form.get("technician_id")
        new_technician: Technician | None = None

        if status_value not in APPOINTMENT_STATUS_OPTIONS:
            flash("Unknown appointment status.", "danger")
            return _redirect_back_to_dashboard("appointments")

        new_time = None
        if scheduled_for_raw:
            try:
                new_time = datetime.fromisoformat(scheduled_for_raw)
            except ValueError:
                flash("Use a valid date and time for the appointment.", "danger")
                return _redirect_back_to_dashboard("appointments")
        elif use_proposed and appointment.proposed_time:
            new_time = appointment.proposed_time

        if new_time:
            if new_time.tzinfo is None:
                new_time = new_time.replace(tzinfo=UTC)
            appointment.scheduled_for = new_time

        if technician_id_raw is not None:
            technician_id_raw = technician_id_raw.strip()
            if technician_id_raw:
                try:
                    technician_id = int(technician_id_raw)
                except (TypeError, ValueError):
                    flash("Choose a valid technician for the visit.", "danger")
                    return _redirect_back_to_dashboard("appointments")

                new_technician = Technician.query.get(technician_id)
                if not new_technician:
                    flash("Selected technician was not found.", "danger")
                    return _redirect_back_to_dashboard("appointments")
                if not new_technician.is_active:
                    flash("The selected technician is inactive.", "danger")
                    return _redirect_back_to_dashboard("appointments")
                appointment.technician_id = new_technician.id
            else:
                appointment.technician_id = None
                new_technician = None

        appointment.status = status_value
        appointment.notes = notes

        if status_value in {"Confirmed", "Completed", "Declined"}:
            appointment.proposed_time = None
            appointment.client_message = None

        appointment.updated_at = utcnow()
        db.session.commit()

        dispatch_notification(
            appointment.client.email,
            f"Appointment update: {appointment.title}",
            (
                f"Status: {appointment.status}\n"
                f"Scheduled for: {appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}\n"
                + (f"Notes: {appointment.notes}\n" if appointment.notes else "")
            ),
            category="customer",
        )

        if new_technician and new_technician.id != previous_technician_id:
            dispatch_notification(
                new_technician.email,
                f"Updated field visit: {appointment.title}",
                (
                    f"Client: {appointment.client.name}\n"
                    f"Scheduled for: {appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}\n"
                    + (f"Notes: {appointment.notes}\n" if appointment.notes else "")
                ),
                category="install",
            )

        flash("Appointment updated.", "success")
        return _redirect_back_to_dashboard("appointments")

    @app.post("/appointments/<int:appointment_id>/delete")
    @login_required
    def delete_appointment_admin(appointment_id: int):
        appointment = Appointment.query.get_or_404(appointment_id)
        db.session.delete(appointment)
        db.session.commit()
        flash("Appointment removed.", "info")
        return _redirect_back_to_dashboard("appointments")

    @app.post("/technicians")
    @login_required
    def create_technician_admin():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip() or None
        password = request.form.get("password", "").strip()

        if not name or not email:
            flash("Name and email are required for technician accounts.", "danger")
            return _redirect_back_to_dashboard("field")

        if len(password) < 8:
            flash("Technician passwords must be at least 8 characters long.", "danger")
            return _redirect_back_to_dashboard("field")

        technician = Technician(
            name=name,
            email=email,
            phone=phone,
            password_hash=generate_password_hash(password),
        )

        db.session.add(technician)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A technician with that email already exists.", "danger")
            return _redirect_back_to_dashboard("field")

        flash("Technician account created.", "success")
        return _redirect_back_to_dashboard("field")

    @app.post("/install-photo-requirements")
    @login_required
    def create_install_photo_requirement():
        label = request.form.get("label", "").strip()
        position_raw = request.form.get("position", "").strip()

        if not label:
            flash("Provide a name for the photo requirement.", "danger")
            return _redirect_back_to_dashboard("field")

        requirements = get_install_photo_requirements()
        desired_index = len(requirements)
        if position_raw:
            try:
                desired_index = int(position_raw)
            except ValueError:
                flash("Use a whole number for the position.", "danger")
                return _redirect_back_to_dashboard("field")
            desired_index = max(0, min(desired_index, len(requirements)))

        new_requirement = InstallPhotoRequirement(label=label)
        requirements.insert(desired_index, new_requirement)
        resequence_install_photo_requirements(requirements)

        db.session.add(new_requirement)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            flash("A requirement with that name already exists.", "danger")
            return _redirect_back_to_dashboard("field")

        db.session.commit()
        flash("Install photo requirement added.", "success")
        return _redirect_back_to_dashboard("field")

    @app.post("/install-photo-requirements/<int:requirement_id>/update")
    @login_required
    def update_install_photo_requirement(requirement_id: int):
        requirement = InstallPhotoRequirement.query.get_or_404(requirement_id)
        label = request.form.get("label", "").strip()
        position_raw = request.form.get("position", "").strip()

        if not label:
            flash("Provide a name for the photo requirement.", "danger")
            return _redirect_back_to_dashboard("field")

        requirements = get_install_photo_requirements()
        try:
            current_index = next(
                index for index, item in enumerate(requirements) if item.id == requirement.id
            )
        except StopIteration:  # pragma: no cover - defensive
            requirements.append(requirement)
            current_index = len(requirements) - 1

        requirements.pop(current_index)
        new_index = current_index
        if position_raw:
            try:
                new_index = int(position_raw)
            except ValueError:
                flash("Use a whole number for the position.", "danger")
                return _redirect_back_to_dashboard("field")
        max_index = len(requirements)
        new_index = max(0, min(new_index, max_index))
        requirements.insert(new_index, requirement)
        requirement.label = label
        resequence_install_photo_requirements(requirements)

        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            flash("A requirement with that name already exists.", "danger")
            return _redirect_back_to_dashboard("field")

        db.session.commit()
        flash("Install photo requirement updated.", "success")
        return _redirect_back_to_dashboard("field")

    @app.post("/install-photo-requirements/<int:requirement_id>/delete")
    @login_required
    def delete_install_photo_requirement(requirement_id: int):
        requirement = InstallPhotoRequirement.query.get_or_404(requirement_id)
        db.session.delete(requirement)
        db.session.flush()

        remaining = get_install_photo_requirements()
        resequence_install_photo_requirements(remaining)
        db.session.commit()

        flash("Install photo requirement removed.", "info")
        return _redirect_back_to_dashboard("field")

    @app.post("/technicians/<int:technician_id>/update")
    @login_required
    def update_technician_admin(technician_id: int):
        technician = Technician.query.get_or_404(technician_id)

        technician.name = request.form.get("name", technician.name).strip() or technician.name
        technician.email = request.form.get("email", technician.email).strip().lower()
        technician.phone = request.form.get("phone", "").strip() or None
        technician.is_active = request.form.get("is_active") == "on"

        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if new_password or confirm_password:
            if new_password != confirm_password:
                flash("New technician passwords must match.", "danger")
                return _redirect_back_to_dashboard("field")
            if len(new_password) < 8:
                flash("New technician passwords must be at least 8 characters.", "danger")
                return _redirect_back_to_dashboard("field")
            technician.password_hash = generate_password_hash(new_password)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Another technician already uses that email address.", "danger")
            return _redirect_back_to_dashboard("field")

        flash("Technician updated.", "success")
        return _redirect_back_to_dashboard("field")

    @app.post("/technicians/<int:technician_id>/reset-password")
    @login_required
    def reset_technician_password(technician_id: int):
        technician = Technician.query.get_or_404(technician_id)
        temporary_password = generate_portal_password()
        technician.password_hash = generate_password_hash(temporary_password)
        technician.updated_at = utcnow()
        db.session.commit()
        flash(
            f"Temporary password for {technician.email}: {temporary_password}",
            "info",
        )
        return _redirect_back_to_dashboard("field")

    @app.post("/tickets/<int:ticket_id>/update")
    @login_required
    def update_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
        status_value = request.form.get("status", ticket.status).strip() or ticket.status
        resolution_notes = request.form.get("resolution_notes", "").strip() or None
        priority_value = request.form.get("priority", ticket.priority).strip().title()
        if priority_value not in TICKET_PRIORITY_OPTIONS:
            priority_value = ticket.priority

        uploaded_files = [
            file
            for file in request.files.getlist("attachments")
            if file and getattr(file, "filename", "")
        ]

        if uploaded_files:
            ensure_file_surface_enabled("support-ticket-attachments")

        for file in uploaded_files:
            if not allowed_ticket_attachment(file.filename):
                flash(
                    "Upload JPG, PNG, GIF, or HEIC images for ticket attachments.",
                    "danger",
                )
                return _redirect_back_to_dashboard("support")

        if status_value not in TICKET_STATUS_OPTIONS:
            flash("Unknown ticket status.", "danger")
            return _redirect_back_to_dashboard("support")

        ticket.status = status_value
        ticket.resolution_notes = resolution_notes
        ticket.priority = priority_value
        if uploaded_files:
            for file in uploaded_files:
                store_ticket_attachment(current_app, ticket, file)
        ticket.updated_at = utcnow()
        db.session.commit()

        flash("Ticket updated.", "success")
        return _redirect_back_to_dashboard("support")

    @app.post("/tickets/<int:ticket_id>/delete")
    @login_required
    def delete_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
        delete_ticket_attachment_files(current_app, ticket)
        db.session.delete(ticket)
        db.session.commit()
        flash("Ticket removed.", "info")
        return _redirect_back_to_dashboard("support")

    @app.post("/notifications/snmp-email")
    @login_required
    def send_snmp_email_admin():
        recipient = request.form.get("recipient", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        if not recipient or not subject or not body:
            flash(
                "Provide a recipient, subject, and message to dispatch an email notification.",
                "danger",
            )
            return _redirect_back_to_dashboard("notifications")

        sent = dispatch_notification(recipient, subject, body, category="manual")

        if sent:
            flash("Notification email queued for delivery.", "success")
        else:
            flash(
                "Unable to deliver the notification. Verify email settings and try again.",
                "warning",
            )

        return _redirect_back_to_dashboard("notifications")

    @app.post("/snmp-settings")
    @login_required
    def update_snmp_settings():
        host = request.form.get("host", "").strip()
        port_raw = request.form.get("port", "").strip()
        community = request.form.get("community", "").strip() or "public"
        enterprise_oid = request.form.get("enterprise_oid", "").strip() or "1.3.6.1.4.1.8072.9999"
        admin_email = request.form.get("admin_email", "").strip() or None

        port_value = 162
        if port_raw:
            try:
                port_value = max(1, min(65535, int(port_raw)))
            except ValueError:
                flash("Provide a valid SNMP port between 1 and 65535.", "danger")
                return _redirect_back_to_dashboard("notifications")

        config = SNMPConfig.query.first()
        if not config:
            config = SNMPConfig()
            db.session.add(config)

        config.host = host or None
        config.port = port_value
        config.community = community
        config.enterprise_oid = enterprise_oid
        config.admin_email = admin_email
        config.updated_at = utcnow()

        db.session.commit()

        app.config["SNMP_TRAP_HOST"] = config.host
        app.config["SNMP_TRAP_PORT"] = config.port
        app.config["SNMP_COMMUNITY"] = config.community
        app.config["SNMP_ENTERPRISE_OID"] = config.enterprise_oid
        app.config["SNMP_ADMIN_EMAIL"] = config.admin_email

        flash("SNMP settings updated.", "success")
        return _redirect_back_to_dashboard("notifications")

    @app.post("/dashboard/notifications/office365")
    @login_required
    def configure_office365_notifications():
        config = ensure_notification_configuration()

        config.smtp_host = (request.form.get("smtp_host", "") or "smtp.office365.com").strip()
        port_raw = request.form.get("smtp_port", "").strip()
        try:
            config.smtp_port = max(1, min(65535, int(port_raw))) if port_raw else 587
        except ValueError:
            flash("Provide a valid SMTP port between 1 and 65535.", "danger")
            return _redirect_back_to_dashboard("notifications")

        config.use_tls = request.form.get("use_tls") == "on"
        config.from_email = request.form.get("from_email", "").strip() or None
        config.from_name = request.form.get("from_name", "").strip() or None
        config.reply_to_email = request.form.get("reply_to_email", "").strip() or None
        config.reply_to_name = request.form.get("reply_to_name", "").strip() or None
        config.smtp_username = request.form.get("smtp_username", "").strip() or None

        new_password = request.form.get("smtp_password", "")
        if new_password.strip():
            config.smtp_password = new_password.strip()
        elif request.form.get("reset_smtp_password") == "on":
            config.smtp_password = None

        config.tenant_id = request.form.get("tenant_id", "").strip() or None
        config.client_id = request.form.get("client_id", "").strip() or None

        new_client_secret = request.form.get("client_secret", "")
        if new_client_secret.strip():
            config.client_secret = new_client_secret.strip()
        elif request.form.get("reset_client_secret") == "on":
            config.client_secret = None

        unsubscribe_url = request.form.get("list_unsubscribe_url", "").strip()
        config.list_unsubscribe_url = unsubscribe_url or None

        unsubscribe_mailto = request.form.get("list_unsubscribe_mailto", "").strip()
        if unsubscribe_mailto.lower().startswith("mailto:"):
            unsubscribe_mailto = unsubscribe_mailto[len("mailto:") :]
        config.list_unsubscribe_mailto = unsubscribe_mailto or None
        config.updated_at = utcnow()

        db.session.commit()

        if config.office365_ready():
            flash("Office 365 email settings saved and ready for use.", "success")
        else:
            flash(
                "Office 365 settings saved. Provide a username, password, and sender address to enable delivery.",
                "info",
            )

        return _redirect_back_to_dashboard("notifications")

    @app.post("/dashboard/notifications/preferences")
    @login_required
    def update_notification_preferences():
        config = ensure_notification_configuration()

        config.notify_install_activity = request.form.get("notify_installs") == "on"
        config.notify_customer_activity = request.form.get("notify_customers") == "on"
        config.notify_all_account_activity = (
            request.form.get("notify_all_activity") == "on"
        )
        config.updated_at = utcnow()

        db.session.commit()

        flash("Notification preferences updated.", "success")
        return _redirect_back_to_dashboard("notifications")

    @app.post("/dashboard/security/admins")
    @login_required
    def create_admin_user():
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip() or None
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Provide a username and password for the admin account.", "danger")
            return redirect(url_for("dashboard", section="security"))

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter them.", "danger")
            return redirect(url_for("dashboard", section="security"))

        if len(password) < 8:
            flash("Choose an admin password with at least 8 characters.", "danger")
            return redirect(url_for("dashboard", section="security"))

        existing_username = AdminUser.query.filter_by(username=username).first()
        if existing_username:
            flash("That admin username is already in use.", "danger")
            return redirect(url_for("dashboard", section="security"))

        if email:
            existing_email = AdminUser.query.filter_by(email=email).first()
            if existing_email:
                flash("That admin email is already assigned to another user.", "danger")
                return redirect(url_for("dashboard", section="security"))

        admin_user = AdminUser(username=username, email=email)
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()

        flash("Admin account created successfully.", "success")
        return redirect(url_for("dashboard", section="security"))

    @app.post("/dashboard/security/admins/<int:admin_id>/delete")
    @login_required
    def delete_admin_user(admin_id: int):
        admin = AdminUser.query.get_or_404(admin_id)
        total_admins = AdminUser.query.count()
        if total_admins <= 1:
            flash(
                "Add another administrator before removing this account.",
                "warning",
            )
            return redirect(url_for("dashboard", section="security"))

        current_admin_id = session.get("admin_user_id")
        if current_admin_id == admin.id:
            flash(
                "You cannot remove the administrator currently signed in.",
                "warning",
            )
            return redirect(url_for("dashboard", section="security"))

        db.session.delete(admin)
        db.session.commit()

        flash("Administrator removed.", "info")
        return redirect(url_for("dashboard", section="security"))

    @app.post("/dashboard/security/stripe")
    @login_required
    def configure_stripe_settings():
        secret_key = (request.form.get("secret_key", "") or "").strip()
        publishable_key = (request.form.get("publishable_key", "") or "").strip()
        webhook_secret = (request.form.get("webhook_secret", "") or "").strip()

        config = StripeConfig.query.first()
        if config is None:
            config = StripeConfig()
            db.session.add(config)

        config.secret_key = secret_key or None
        config.publishable_key = publishable_key or None
        config.webhook_secret = webhook_secret or None
        config.updated_at = utcnow()

        db.session.commit()

        current_app.config["STRIPE_SECRET_KEY"] = config.secret_key
        current_app.config["STRIPE_PUBLISHABLE_KEY"] = config.publishable_key
        current_app.config["STRIPE_WEBHOOK_SECRET"] = config.webhook_secret

        init_stripe(current_app)

        if config.secret_key and config.publishable_key:
            flash(
                "Stripe configuration saved. Customer payments and autopay are ready.",
                "success",
            )
        else:
            flash(
                "Stripe configuration saved. Provide both API keys to enable card payments.",
                "info",
            )

        return redirect(url_for("dashboard", section="security"))

    @app.post("/dashboard/security/tls")
    @login_required
    def configure_tls():
        tls_config = TLSConfig.query.first()
        if tls_config is None:
            tls_config = TLSConfig(
                challenge_path=current_app.config.get("TLS_CHALLENGE_FOLDER")
            )
            db.session.add(tls_config)

        domain = (request.form.get("domain", "").strip().lower() or None)
        contact_email = request.form.get("contact_email", "").strip() or None
        auto_renew = bool(request.form.get("auto_renew"))
        staging = bool(request.form.get("use_staging"))
        action = request.form.get("action", "save")

        tls_config.domain = domain
        tls_config.contact_email = contact_email
        tls_config.auto_renew = auto_renew
        tls_config.use_staging = staging
        tls_config.challenge_path = current_app.config.get("TLS_CHALLENGE_FOLDER")

        if action == "provision":
            success, error_message, cert_path, key_path = issue_lets_encrypt_certificate(
                current_app, tls_config, staging=staging
            )
            if success:
                tls_config.certificate_path = str(cert_path) if cert_path else None
                tls_config.private_key_path = str(key_path) if key_path else None
                tls_config.status = "active"
                tls_config.last_error = None
                tls_config.last_provisioned_at = utcnow()
                flash(
                    "Certificate issued successfully. Restart the app to serve HTTPS.",
                    "success",
                )
            else:
                tls_config.status = "error"
                tls_config.last_error = error_message
                flash(
                    f"Certificate request failed: {error_message}",
                    "danger",
                )
        else:
            tls_config.last_error = None if tls_config.certificate_ready() else tls_config.last_error
            tls_config.status = (
                "active" if tls_config.certificate_ready() else "pending"
            )
            flash("TLS settings saved.", "success")

        db.session.commit()

        return redirect(url_for("dashboard", section="security"))

    @app.post("/down-detector/config")
    @login_required
    def update_down_detector_config():
        target_url = request.form.get("target_url", "").strip()

        config = DownDetectorConfig.query.first()
        if not config:
            config = DownDetectorConfig()
            db.session.add(config)

        config.target_url = target_url or None
        config.updated_at = utcnow()
        db.session.commit()

        if config.target_url:
            flash("Down detector redirect updated.", "success")
        else:
            flash("Down detector redirect cleared.", "info")

        return _redirect_back_to_dashboard("support")

    @app.post("/service-plans")
    @login_required
    def create_service_plan_admin():
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "Residential").strip()
        price_raw = request.form.get("price", "").strip()
        speed = request.form.get("speed", "").strip() or None
        description = request.form.get("description", "").strip() or None
        features_raw = request.form.get("features", "")

        if not name:
            flash("Service plan name is required.", "danger")
            return _redirect_back_to_dashboard("plans")

        if not price_raw:
            flash("Provide a monthly price for the service plan.", "danger")
            return _redirect_back_to_dashboard("plans")

        normalized_category = category or "Residential"
        normalized_category = normalized_category.strip() or "Residential"
        normalized_category = normalized_category.title()

        normalized_price = price_raw.replace("$", "").replace(",", "")

        try:
            price_decimal = Decimal(normalized_price)
        except InvalidOperation:
            flash("Enter a valid monthly price such as 59.99.", "danger")
            return _redirect_back_to_dashboard("plans")

        price_cents = int(price_decimal * 100)
        if price_cents < 0:
            flash("Plan pricing must be zero or greater.", "danger")
            return _redirect_back_to_dashboard("plans")

        next_position = (
            db.session.query(db.func.max(ServicePlan.position)).scalar() or 0
        ) + 1

        plan = ServicePlan(
            name=name,
            category=normalized_category,
            price_cents=price_cents,
            speed=speed,
            description=description,
            position=next_position,
        )
        plan.set_features_from_text(features_raw)
        db.session.add(plan)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A service plan with that name already exists.", "danger")
            return _redirect_back_to_dashboard("plans")

        flash("Service plan created.", "success")
        return _redirect_back_to_dashboard("plans")

    @app.post("/service-plans/<int:plan_id>/update")
    @login_required
    def update_service_plan_admin(plan_id: int):
        plan = ServicePlan.query.get_or_404(plan_id)

        name = request.form.get("name", "").strip()
        category = request.form.get("category", plan.category).strip()
        price_raw = request.form.get("price", "").strip()
        speed = request.form.get("speed", "").strip() or None
        description = request.form.get("description", "").strip() or None
        features_raw = request.form.get("features", "")

        if not name:
            flash("Service plan name is required.", "danger")
            return _redirect_back_to_dashboard("plans")

        if not price_raw:
            flash("Provide a monthly price for the service plan.", "danger")
            return _redirect_back_to_dashboard("plans")

        normalized_category = category or plan.category
        normalized_category = normalized_category.strip() or plan.category
        normalized_category = normalized_category.title()

        normalized_price = price_raw.replace("$", "").replace(",", "")

        try:
            price_decimal = Decimal(normalized_price)
        except InvalidOperation:
            flash("Enter a valid monthly price such as 59.99.", "danger")
            return _redirect_back_to_dashboard("plans")

        price_cents = int(price_decimal * 100)
        if price_cents < 0:
            flash("Plan pricing must be zero or greater.", "danger")
            return _redirect_back_to_dashboard("plans")

        plan.name = name
        plan.category = normalized_category
        plan.price_cents = price_cents
        plan.speed = speed
        plan.description = description
        plan.set_features_from_text(features_raw)
        plan.updated_at = utcnow()

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("A service plan with that name already exists.", "danger")
            return _redirect_back_to_dashboard("plans")

        flash("Service plan updated.", "success")
        return _redirect_back_to_dashboard("plans")

    @app.post("/service-plans/<int:plan_id>/delete")
    @login_required
    def delete_service_plan_admin(plan_id: int):
        plan = ServicePlan.query.get_or_404(plan_id)
        db.session.delete(plan)
        db.session.commit()
        resequence_service_plan_positions()
        flash("Service plan removed.", "info")
        return _redirect_back_to_dashboard("plans")

    @app.post("/navigation/add")
    @login_required
    def add_navigation_item():
        label = request.form.get("label", "").strip()
        url = request.form.get("url", "").strip()
        open_in_new_tab = request.form.get("open_in_new_tab") == "on"

        if not label or not url:
            flash("Navigation label and URL are required.", "danger")
            return redirect(url_for("dashboard", section="navigation"))

        max_position = db.session.query(db.func.max(NavigationItem.position)).scalar() or 0
        item = NavigationItem(
            label=label,
            url=url,
            position=max_position + 1,
            open_in_new_tab=open_in_new_tab,
        )
        db.session.add(item)
        db.session.commit()
        flash("Navigation link added.", "success")
        return redirect(url_for("dashboard", section="navigation"))

    @app.post("/navigation/<int:item_id>/update")
    @login_required
    def update_navigation_item(item_id: int):
        item = NavigationItem.query.get_or_404(item_id)
        label = request.form.get("label", "").strip()
        url = request.form.get("url", "").strip()
        open_in_new_tab = request.form.get("open_in_new_tab") == "on"

        if not label or not url:
            flash("Navigation label and URL are required.", "danger")
            return redirect(url_for("dashboard", section="navigation"))

        item.label = label
        item.url = url
        item.open_in_new_tab = open_in_new_tab
        db.session.commit()
        flash("Navigation link updated.", "success")
        return redirect(url_for("dashboard", section="navigation"))

    @app.post("/navigation/<int:item_id>/delete")
    @login_required
    def delete_navigation_item(item_id: int):
        item = NavigationItem.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        resequence_navigation_positions()
        flash("Navigation link removed.", "info")
        return redirect(url_for("dashboard", section="navigation"))

    @app.post("/navigation/<int:item_id>/move")
    @login_required
    def move_navigation_item(item_id: int):
        direction = request.form.get("direction")
        if direction not in {"up", "down"}:
            flash("Unknown navigation action.", "danger")
            return redirect(url_for("dashboard", section="navigation"))

        navigation_items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        index_lookup = {item.id: idx for idx, item in enumerate(navigation_items)}

        if item_id not in index_lookup:
            abort(404)

        current_index = index_lookup[item_id]
        target_index = current_index - 1 if direction == "up" else current_index + 1

        if target_index < 0 or target_index >= len(navigation_items):
            flash("Navigation link already at the edge.", "info")
            return redirect(url_for("dashboard", section="navigation"))

        navigation_items[current_index], navigation_items[target_index] = (
            navigation_items[target_index],
            navigation_items[current_index],
        )

        for index, item in enumerate(navigation_items, start=1):
            item.position = index

        db.session.commit()
        flash("Navigation order updated.", "success")
        return redirect(url_for("dashboard", section="navigation"))

    @app.post("/branding/theme")
    @login_required
    def update_site_theme():
        background_color = request.form.get("background_color", "")

        try:
            normalized = normalize_hex_color(background_color)
        except ValueError:
            flash("Please choose a valid background color.", "danger")
            return redirect(url_for("dashboard", section="branding"))

        photo_file = request.files.get("background_photo")
        remove_photo = request.form.get("remove_background_photo") == "1"

        theme = SiteTheme.query.first()
        if theme is None:
            theme = SiteTheme()
            db.session.add(theme)

        upload_folder = Path(app.config["THEME_UPLOAD_FOLDER"])
        os.makedirs(upload_folder, exist_ok=True)

        photo_uploaded = False
        photo_removed = False

        if photo_file and photo_file.filename:
            ensure_file_surface_enabled("theme-background")
            filename = secure_filename(photo_file.filename)
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if extension not in ALLOWED_BRANDING_EXTENSIONS:
                allowed = ", ".join(sorted(ALLOWED_BRANDING_EXTENSIONS))
                flash(
                    f"Unsupported background image type. Allowed formats: {allowed}.",
                    "danger",
                )
                return redirect(url_for("dashboard", section="branding"))

            stored_name = f"theme_bg_{int(utcnow().timestamp())}.{extension}"
            file_path = upload_folder / stored_name
            photo_file.save(file_path)

            if theme.background_image_filename:
                previous_path = upload_folder / theme.background_image_filename
                if previous_path.exists():
                    try:
                        previous_path.unlink()
                    except OSError:
                        pass

            theme.background_image_filename = stored_name
            theme.background_image_original = photo_file.filename
            photo_uploaded = True
            remove_photo = False

        if remove_photo and theme.background_image_filename:
            previous_path = upload_folder / theme.background_image_filename
            if previous_path.exists():
                try:
                    previous_path.unlink()
                except OSError:
                    pass
            theme.background_image_filename = None
            theme.background_image_original = None
            photo_removed = True

        text_color, muted_color = derive_theme_palette(normalized)
        theme.background_color = normalized
        theme.text_color = text_color
        theme.muted_color = muted_color
        db.session.commit()

        if photo_uploaded:
            message = "Updated the site background image and colors."
        elif photo_removed:
            message = "Removed the background photo and refreshed colors."
        else:
            message = "Updated the site background and text colors."

        flash(message, "success")
        return redirect(url_for("dashboard", section="branding"))

    @app.post("/branding/upload")
    @login_required
    def upload_branding():
        ensure_file_surface_enabled("branding-assets")
        asset_type = request.form.get("asset_type", "")
        file = request.files.get("asset")

        if asset_type not in BRANDING_ASSET_TYPES:
            flash("Unknown branding asset type.", "danger")
            return redirect(url_for("dashboard", section="branding"))

        if not file or not file.filename:
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("dashboard", section="branding"))

        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        if extension not in ALLOWED_BRANDING_EXTENSIONS:
            allowed = ", ".join(sorted(ALLOWED_BRANDING_EXTENSIONS))
            flash(f"Unsupported branding file type. Allowed formats: {allowed}.", "danger")
            return redirect(url_for("dashboard", section="branding"))

        upload_folder = Path(app.config["BRANDING_UPLOAD_FOLDER"])
        os.makedirs(upload_folder, exist_ok=True)

        stored_filename = f"{asset_type}_{int(utcnow().timestamp())}.{extension}"
        file_path = upload_folder / stored_filename
        file.save(file_path)

        asset_record = BrandingAsset.query.filter_by(asset_type=asset_type).first()
        if asset_record:
            previous_path = upload_folder / asset_record.stored_filename
            if previous_path.exists():
                previous_path.unlink()
            asset_record.original_filename = file.filename
            asset_record.stored_filename = stored_filename
            asset_record.uploaded_at = utcnow()
        else:
            asset_record = BrandingAsset(
                asset_type=asset_type,
                original_filename=file.filename,
                stored_filename=stored_filename,
            )
            db.session.add(asset_record)

        db.session.commit()
        flash(f"{BRANDING_ASSET_TYPES[asset_type]['label']} updated.", "success")
        return redirect(url_for("dashboard", section="branding"))

    @app.get("/branding/<asset_type>")
    def branding_file(asset_type: str):
        if asset_type not in BRANDING_ASSET_TYPES:
            abort(404)

        asset_record = BrandingAsset.query.filter_by(asset_type=asset_type).first()
        if not asset_record:
            abort(404)

        upload_folder = Path(app.config["BRANDING_UPLOAD_FOLDER"])
        file_path = upload_folder / asset_record.stored_filename

        if not file_path.exists():
            abort(404)

        return send_site_file(
            "branding-assets",
            upload_folder,
            asset_record.stored_filename,
            as_attachment=False,
            download_name=asset_record.original_filename,
        )

    @app.get("/branding/theme-background")
    def theme_background():
        theme = SiteTheme.query.first()
        if not theme or not theme.background_image_filename:
            abort(404)

        upload_folder = Path(app.config["THEME_UPLOAD_FOLDER"])
        file_path = upload_folder / theme.background_image_filename
        if not file_path.exists():
            abort(404)

        return send_site_file(
            "theme-background",
            upload_folder,
            theme.background_image_filename,
            as_attachment=False,
            download_name=theme.background_image_original or "background",
        )

    @app.post("/blog/posts")
    @login_required
    def create_blog_post():
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        content = request.form.get("content", "").strip()
        publish = request.form.get("publish") == "on"

        if not title or not content:
            flash("Title and content are required to publish a blog post.", "danger")
            return redirect(url_for("dashboard", section="blog"))

        slug = generate_unique_slug(title)
        post = BlogPost(
            title=title,
            slug=slug,
            summary=summary or None,
            content=content,
            is_published=publish,
        )

        if publish:
            post.published_at = utcnow()

        db.session.add(post)
        db.session.commit()

        flash("Blog post created.", "success")
        return redirect(url_for("dashboard", section="blog"))

    @app.post("/blog/posts/<int:post_id>")
    @login_required
    def update_blog_post(post_id: int):
        post = BlogPost.query.get_or_404(post_id)

        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        content = request.form.get("content", "").strip()
        publish = request.form.get("publish") == "on"

        if not title or not content:
            flash("Title and content are required to update a blog post.", "danger")
            return redirect(url_for("dashboard", section="blog"))

        if title != post.title:
            post.slug = generate_unique_slug(title, existing_id=post.id)

        post.title = title
        post.summary = summary or None
        post.content = content

        if publish:
            post.is_published = True
            if not post.published_at:
                post.published_at = utcnow()
        else:
            post.is_published = False
            post.published_at = None

        db.session.commit()

        flash("Blog post updated.", "success")
        return redirect(url_for("dashboard", section="blog"))

    @app.post("/team-members")
    @login_required
    def create_team_member_admin():
        name = request.form.get("name", "").strip()
        title = request.form.get("title", "").strip()
        bio = request.form.get("bio", "").strip()
        photo = request.files.get("photo")

        if not name:
            flash("Provide a name for the team member.", "danger")
            return redirect(url_for("dashboard", section="story"))

        next_position = (
            db.session.query(db.func.max(TeamMember.position)).scalar() or 0
        ) + 1

        member = TeamMember(
            name=name,
            title=title or None,
            bio=bio or None,
            position=next_position,
        )
        db.session.add(member)
        db.session.commit()

        if photo and photo.filename:
            ensure_file_surface_enabled("team-member-photo")
            try:
                store_team_member_photo(app, member, photo)
            except ValueError as exc:
                db.session.delete(member)
                db.session.commit()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))
            else:
                db.session.commit()

        flash(f"Added {member.name} to the team.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/team-members/<int:member_id>")
    @login_required
    def update_team_member_admin(member_id: int):
        member = TeamMember.query.get_or_404(member_id)

        name = request.form.get("name", "").strip()
        title = request.form.get("title", "").strip()
        bio = request.form.get("bio", "").strip()
        photo = request.files.get("photo")

        if not name:
            flash("Team member name is required.", "danger")
            return redirect(url_for("dashboard", section="story"))

        member.name = name
        member.title = title or None
        member.bio = bio or None

        if photo and photo.filename:
            ensure_file_surface_enabled("team-member-photo")
            try:
                store_team_member_photo(app, member, photo)
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))

        db.session.commit()
        flash(f"Updated details for {member.name}.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/team-members/<int:member_id>/delete")
    @login_required
    def delete_team_member_admin(member_id: int):
        member = TeamMember.query.get_or_404(member_id)

        delete_team_member_photo(app, member)
        db.session.delete(member)
        db.session.commit()

        flash("Team member removed.", "info")
        return redirect(url_for("dashboard", section="story"))

    @app.get("/team-members/<int:member_id>/photo")
    def team_member_photo(member_id: int):
        member = TeamMember.query.get_or_404(member_id)
        if not member.photo_filename:
            abort(404)

        upload_folder = Path(app.config["TEAM_UPLOAD_FOLDER"])
        file_path = upload_folder / member.photo_filename
        if not file_path.exists():
            abort(404)

        return send_site_file(
            "team-member-photo",
            upload_folder,
            member.photo_filename,
            as_attachment=False,
            download_name=member.photo_original or "team-member",
        )

    @app.post("/trusted-businesses")
    @login_required
    def create_trusted_business_admin():
        name = request.form.get("name", "").strip()
        website_url = request.form.get("website_url", "").strip() or None
        logo = request.files.get("logo")

        if not name:
            flash("Provide a business name to showcase.", "danger")
            return redirect(url_for("dashboard", section="story"))

        next_position = (
            db.session.query(db.func.max(TrustedBusiness.position)).scalar() or 0
        ) + 1

        business = TrustedBusiness(
            name=name,
            website_url=website_url,
            position=next_position,
        )
        db.session.add(business)
        db.session.commit()

        if logo and logo.filename:
            ensure_file_surface_enabled("trusted-business-logo")
            try:
                store_trusted_business_logo(app, business, logo)
            except ValueError as exc:
                db.session.delete(business)
                db.session.commit()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))
            else:
                db.session.commit()

        flash(f"Added {business.name} to your trusted partners.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/trusted-businesses/<int:business_id>")
    @login_required
    def update_trusted_business_admin(business_id: int):
        business = TrustedBusiness.query.get_or_404(business_id)

        name = request.form.get("name", "").strip()
        website_url = request.form.get("website_url", "").strip() or None
        logo = request.files.get("logo")

        if not name:
            flash("Business name is required.", "danger")
            return redirect(url_for("dashboard", section="story"))

        business.name = name
        business.website_url = website_url

        if logo and logo.filename:
            ensure_file_surface_enabled("trusted-business-logo")
            try:
                store_trusted_business_logo(app, business, logo)
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))

        db.session.commit()
        flash(f"Updated {business.name}.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/trusted-businesses/<int:business_id>/delete")
    @login_required
    def delete_trusted_business_admin(business_id: int):
        business = TrustedBusiness.query.get_or_404(business_id)

        delete_trusted_business_logo(app, business)
        db.session.delete(business)
        db.session.commit()

        flash("Business removed from the showcase.", "info")
        return redirect(url_for("dashboard", section="story"))

    @app.get("/trusted-businesses/<int:business_id>/logo")
    def trusted_business_logo(business_id: int):
        business = TrustedBusiness.query.get_or_404(business_id)
        if not business.logo_filename:
            abort(404)

        upload_folder = Path(app.config["TRUSTED_BUSINESS_UPLOAD_FOLDER"])
        file_path = upload_folder / business.logo_filename
        if not file_path.exists():
            abort(404)

        return send_site_file(
            "trusted-business-logo",
            upload_folder,
            business.logo_filename,
            as_attachment=False,
            download_name=business.logo_original or "trusted-business",
        )

    @app.post("/support-partners")
    @login_required
    def create_support_partner_admin():
        name = request.form.get("name", "").strip()
        website_url = request.form.get("website_url", "").strip() or None
        description = request.form.get("description", "").strip() or None
        logo = request.files.get("logo")

        if not name:
            flash("Provide a company name to highlight.", "danger")
            return redirect(url_for("dashboard", section="story"))

        next_position = (
            db.session.query(db.func.max(SupportPartner.position)).scalar() or 0
        ) + 1

        partner = SupportPartner(
            name=name,
            website_url=website_url,
            description=description,
            position=next_position,
        )
        db.session.add(partner)
        db.session.commit()

        if logo and logo.filename:
            ensure_file_surface_enabled("support-partner-logo")
            try:
                store_support_partner_logo(app, partner, logo)
            except ValueError as exc:
                db.session.delete(partner)
                db.session.commit()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))
            else:
                db.session.commit()

        flash(f"Added {partner.name} to your operations allies.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/support-partners/<int:partner_id>")
    @login_required
    def update_support_partner_admin(partner_id: int):
        partner = SupportPartner.query.get_or_404(partner_id)

        name = request.form.get("name", "").strip()
        website_url = request.form.get("website_url", "").strip() or None
        description = request.form.get("description", "").strip() or None
        logo = request.files.get("logo")

        if not name:
            flash("Company name is required.", "danger")
            return redirect(url_for("dashboard", section="story"))

        partner.name = name
        partner.website_url = website_url
        partner.description = description

        if logo and logo.filename:
            ensure_file_surface_enabled("support-partner-logo")
            try:
                store_support_partner_logo(app, partner, logo)
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc), "danger")
                return redirect(url_for("dashboard", section="story"))

        db.session.commit()
        flash(f"Updated {partner.name}.", "success")
        return redirect(url_for("dashboard", section="story"))

    @app.post("/support-partners/<int:partner_id>/delete")
    @login_required
    def delete_support_partner_admin(partner_id: int):
        partner = SupportPartner.query.get_or_404(partner_id)

        delete_support_partner_logo(app, partner)
        db.session.delete(partner)
        db.session.commit()

        flash("Support partner removed.", "info")
        return redirect(url_for("dashboard", section="story"))

    @app.get("/support-partners/<int:partner_id>/logo")
    def support_partner_logo(partner_id: int):
        partner = SupportPartner.query.get_or_404(partner_id)
        if not partner.logo_filename:
            abort(404)

        upload_folder = Path(app.config["SUPPORT_PARTNER_UPLOAD_FOLDER"])
        file_path = upload_folder / partner.logo_filename
        if not file_path.exists():
            abort(404)

        return send_site_file(
            "support-partner-logo",
            upload_folder,
            partner.logo_filename,
            as_attachment=False,
            download_name=partner.logo_original or "support-partner",
        )

    @app.post("/blog/posts/<int:post_id>/delete")
    @login_required
    def delete_blog_post(post_id: int):
        post = BlogPost.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()

        flash("Blog post deleted.", "info")
        return redirect(url_for("dashboard", section="blog"))

    @app.post("/clients/<int:client_id>/update")
    @login_required
    def update_client(client_id: int):
        client = Client.query.get_or_404(client_id)
        status = request.form.get("status")
        notes = request.form.get("notes", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        driver_license_number = request.form.get("driver_license_number", "").strip()
        wifi_router_value = request.form.get("wifi_router_needed")

        if status not in STATUS_OPTIONS:
            abort(400, description="Invalid status value")

        client.status = status
        client.notes = notes or None
        client.phone = phone or None
        client.address = address or None
        client.driver_license_number = driver_license_number or None
        if wifi_router_value is not None:
            client.wifi_router_needed = (
                wifi_router_value.strip().lower() == "yes"
            )
        db.session.commit()
        flash("Client updated successfully.", "success")
        focus_value = request.args.get("focus")
        return redirect(
            url_for(
                "dashboard",
                status=request.args.get("status"),
                section=request.args.get("section", "customers"),
                focus=focus_value,
            )
        )

    @app.post("/clients/<int:client_id>/delete")
    @login_required
    def delete_client(client_id: int):
        client = Client.query.get_or_404(client_id)
        db.session.delete(client)
        db.session.commit()
        flash("Client removed.", "info")
        focus_value = request.args.get("focus")
        if focus_value and focus_value == str(client_id):
            focus_value = None
        return redirect(
            url_for(
                "dashboard",
                status=request.args.get("status"),
                section=request.args.get("section", "customers"),
                focus=focus_value,
            )
        )


def resequence_navigation_positions() -> None:
    items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
    for index, item in enumerate(items, start=1):
        item.position = index
    db.session.commit()


def resequence_service_plan_positions() -> None:
    plans = ServicePlan.query.order_by(ServicePlan.position.asc(), ServicePlan.id.asc()).all()
    for index, plan in enumerate(plans, start=1):
        plan.position = index
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    ssl_context: tuple[str, str] | None = None

    with app.app_context():
        tls_config = TLSConfig.query.first()
        if tls_config and tls_config.certificate_ready():
            ssl_context = (
                str(Path(tls_config.certificate_path)),
                str(Path(tls_config.private_key_path)),
            )

    http_port = 80
    https_port = 443
    extra_http_port: int | None = None
    extra_https_port: int | None = None

    port_env = os.environ.get("PORT")
    if port_env:
        try:
            parsed = int(port_env)
            if parsed != http_port:
                extra_http_port = parsed
        except ValueError:
            app.logger.warning("Ignoring invalid PORT value: %s", port_env)

    https_env = os.environ.get("HTTPS_PORT")
    if https_env:
        try:
            parsed = int(https_env)
            if parsed not in {http_port, https_port}:
                extra_https_port = parsed
        except ValueError:
            app.logger.warning("Ignoring invalid HTTPS_PORT value: %s", https_env)

    servers: list[BaseWSGIServer] = []
    threads: list[threading.Thread] = []

    def start_server(port: int, label: str, ssl: tuple[str, str] | None = None) -> bool:
        try:
            server = make_server(
                host="0.0.0.0",
                port=port,
                app=app,
                ssl_context=ssl,
            )
        except OSError as exc:  # pragma: no cover - exercised in deployment
            if exc.errno == errno.EACCES:
                app.logger.error(
                    "Permission denied starting %s server on port %s. Run as root or grant the Python binary the 'cap_net_bind_service' capability.",
                    label,
                    port,
                )
            else:
                app.logger.error("Unable to start %s server on port %s: %s", label, port, exc)
            raise SystemExit(1) from exc

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
        app.logger.info("%s server listening on port %s", label, port)
        return True

    start_server(http_port, "HTTP")

    if extra_http_port is not None:
        start_server(extra_http_port, "HTTP (PORT override)")

    if ssl_context:
        start_server(https_port, "HTTPS", ssl=ssl_context)

        if extra_https_port is not None:
            start_server(extra_https_port, "HTTPS (env override)", ssl=ssl_context)

    wait_event = threading.Event()
    try:
        while any(thread.is_alive() for thread in threads):
            wait_event.wait(0.5)
    except KeyboardInterrupt:  # pragma: no cover - exercised in deployment
        app.logger.info("Shutting down web servers...")
    finally:
        for server in servers:
            server.shutdown()
        for thread in threads:
            thread.join()
