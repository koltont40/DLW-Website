import os
import secrets
import string
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
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
from werkzeug.utils import secure_filename

from sqlalchemy import inspect, or_, text

load_dotenv()

db = SQLAlchemy()


def utcnow() -> datetime:
    return datetime.now(UTC)


def generate_portal_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def generate_account_reference() -> str:
    return f"DLW-{secrets.token_hex(3).upper()}"


class Client(db.Model):
    __tablename__ = "clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    company = db.Column(db.String(255))
    project_type = db.Column(db.String(120))
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default="New")
    portal_access_code = db.Column(
        db.String(64), nullable=False, unique=True, default=generate_portal_password
    )
    portal_password_hash = db.Column(db.String(255))
    portal_password_updated_at = db.Column(db.DateTime(timezone=True))
    account_reference = db.Column(
        db.String(24), nullable=False, unique=True, default=generate_account_reference
    )
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

    def __repr__(self) -> str:
        return f"<Client {self.email}>"


STATUS_OPTIONS = ["New", "In Review", "Active", "On Hold", "Archived"]

SERVICE_PLANS = [
    {
        "name": "Wireless Internet (WISP)",
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
        "name": "Internet + Phone Bundle",
        "price_cents": 9499,
        "speed": "Up to 150 Mbps + Digital voice",
        "description": "Best value bundle for households that want fast wireless internet and dependable phone service together.",
        "features": [
            "Bundled savings on monthly service",
            "Single invoice with autopay support",
            "Priority repair dispatch",
        ],
    },
]

SERVICE_OFFERINGS = [plan["name"] for plan in SERVICE_PLANS]

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

PORTAL_SESSION_KEY = "client_portal_id"


def get_default_navigation_items() -> list[tuple[str, str, bool]]:
    contact_email = current_app.config.get("CONTACT_EMAIL", "hello@example.com")
    return [
        ("Sign Up", "/signup", False),
        ("Service Plans", "/services", False),
        ("About", "/about", False),
        ("Legal", "/legal", False),
        ("Contact", f"mailto:{contact_email}", False),
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

    client = db.relationship("Client", back_populates="invoices")

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


class SupportTicket(db.Model):
    __tablename__ = "support_tickets"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Open")
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client = db.relationship("Client", back_populates="tickets")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<SupportTicket {self.id} for client {self.client_id}>"


class Appointment(db.Model):
    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("clients.id"), nullable=False)
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


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

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
        "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", "admin"),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "admin123"),
        "LEGAL_UPLOAD_FOLDER": str(instance_path / "legal"),
        "BRANDING_UPLOAD_FOLDER": str(instance_path / "branding"),
        "CONTACT_EMAIL": os.environ.get("CONTACT_EMAIL", "hello@example.com"),
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

    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    register_routes(app)

    with app.app_context():
        db.create_all()
        ensure_client_portal_fields()
        ensure_default_navigation()
        ensure_snmp_configuration()

    return app


def init_db() -> None:
    """Initialize the database tables if they do not exist."""

    app = create_app()
    with app.app_context():
        db.create_all()
        ensure_client_portal_fields()
        ensure_default_navigation()


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


def login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
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
            flash("Please log in to access your account.", "warning")
            return redirect(url_for("portal_login", next=request.path))

        client = Client.query.get(client_id)
        if not client:
            session.pop(PORTAL_SESSION_KEY, None)
            flash("We couldn't find that account. Please log in again.", "danger")
            return redirect(url_for("portal_login"))

        g.portal_client = client
        return func(client, *args, **kwargs)

    return wrapper


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

    def notify_via_snmp(recipient: str, subject: str, body: str) -> bool:
        if not recipient:
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

    @app.context_processor
    def inject_status_options():
        navigation_items = (
            NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        )
        branding_assets = {asset.asset_type: asset for asset in BrandingAsset.query.all()}

        return {
            "status_options": STATUS_OPTIONS,
            "current_year": utcnow().year,
            "legal_document_types": LEGAL_DOCUMENT_TYPES,
            "navigation_items": navigation_items,
            "branding_assets": branding_assets,
            "branding_asset_types": BRANDING_ASSET_TYPES,
            "invoice_status_options": INVOICE_STATUS_OPTIONS,
            "ticket_status_options": TICKET_STATUS_OPTIONS,
            "service_offerings": SERVICE_OFFERINGS,
            "appointment_status_options": APPOINTMENT_STATUS_OPTIONS,
            "contact_email": app.config.get("CONTACT_EMAIL", "hello@example.com"),
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/services")
    def service_plans():
        return render_template("service_plans.html", plans=SERVICE_PLANS)

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        selected_plan = request.args.get("plan", "").strip()
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            company = request.form.get("company", "").strip()
            service_plan = request.form.get("service_plan", "").strip()
            notes = request.form.get("notes", "").strip()
            password = request.form.get("password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()

            if not name or not email:
                flash("Name and email are required.", "danger")
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

            existing = Client.query.filter_by(email=email).first()
            if existing:
                flash("This email address has already been registered.", "warning")
                return redirect(url_for("signup"))

            client = Client(
                name=name,
                email=email,
                company=company or None,
                project_type=service_plan or None,
                notes=notes or None,
            )
            client.portal_password_hash = generate_password_hash(password)
            client.portal_password_updated_at = utcnow()
            db.session.add(client)
            db.session.commit()

            session[PORTAL_SESSION_KEY] = client.id
            session["portal_authenticated_at"] = utcnow().isoformat()

            flash("Account created! You're signed in to the customer portal.", "success")
            return redirect(url_for("portal_dashboard"))

        return render_template("signup.html", preselected_plan=selected_plan)

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
        )

    @app.post("/portal/tickets")
    @client_login_required
    def portal_create_ticket(client: Client):
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("Please provide both a subject and description for your ticket.", "danger")
            return redirect(url_for("portal_dashboard"))

        ticket = SupportTicket(
            client_id=client.id,
            subject=subject,
            message=message,
        )
        db.session.add(ticket)
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
            notify_via_snmp(
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
            )

        flash(confirmation_text, "success")
        return redirect(url_for("portal_dashboard"))

    @app.route("/legal")
    def legal():
        documents = {key: None for key in LEGAL_DOCUMENT_TYPES}
        for document in Document.query.all():
            documents[document.doc_type] = document

        return render_template("legal.html", documents=documents)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if (
                username == app.config["ADMIN_USERNAME"]
                and password == app.config["ADMIN_PASSWORD"]
            ):
                session["admin_authenticated"] = True
                session["admin_logged_in_at"] = utcnow().isoformat()
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
            "portal",
            "billing",
            "network",
            "support",
            "appointments",
            "navigation",
            "branding",
            "legal",
        }
        if active_section not in valid_sections:
            active_section = "overview"

        status_filter = request.args.get("status")
        if status_filter not in STATUS_OPTIONS:
            status_filter = None

        clients: list[Client] = []
        if active_section in {
            "customers",
            "portal",
            "billing",
            "network",
            "support",
            "appointments",
        }:
            query = Client.query.order_by(Client.created_at.desc())
            if status_filter:
                query = query.filter_by(status=status_filter)
            clients = query.all()

        appointments: list[Appointment] = []
        if active_section == "appointments":
            appointments = (
                Appointment.query.order_by(Appointment.scheduled_for.asc()).all()
            )

        total_clients = Client.query.count()
        start_of_week = utcnow() - timedelta(days=7)
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
            Client.query.filter(Client.status.in_(["New", "In Review"])).count()
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
            Appointment.query.filter(
                Appointment.status.in_(upcoming_statuses)
            )
            .order_by(Appointment.scheduled_for.asc())
            .limit(5)
            .all()
        )
        recent_appointments = (
            Appointment.query.order_by(Appointment.updated_at.desc()).limit(5).all()
        )

        recent_clients = (
            Client.query.order_by(Client.created_at.desc()).limit(5).all()
        )
        recent_invoices = (
            Invoice.query.order_by(Invoice.created_at.desc()).limit(5).all()
        )
        recent_equipment = (
            Equipment.query.order_by(Equipment.created_at.desc()).limit(5).all()
        )
        recent_tickets = (
            SupportTicket.query.order_by(SupportTicket.created_at.desc()).limit(5).all()
        )

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

        snmp_settings = get_effective_snmp_settings(app)
        snmp_enabled = bool(snmp_settings.get("host") or app.config.get("SNMP_EMAIL_SENDER"))
        snmp_config = SNMPConfig.query.first()

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
            status_filter=status_filter,
            legal_documents=documents,
            navigation_items=navigation_items,
            branding_assets=branding_records,
            appointments=appointments,
            appointments_total=appointments_total,
            pending_appointments=pending_appointments,
            upcoming_appointments=upcoming_appointments_list,
            recent_appointments=recent_appointments,
            snmp_enabled=snmp_enabled,
            snmp_config=snmp_config,
            snmp_settings=snmp_settings,
        )

    @app.post("/documents/upload")
    @login_required
    def upload_document():
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

        return send_from_directory(
            str(upload_folder),
            document.stored_filename,
            mimetype=mimetype,
            as_attachment=False,
            download_name=document.original_filename,
        )

    @app.get("/documents/<doc_type>")
    def download_document(doc_type: str):
        document, upload_folder, _ = _resolve_document(doc_type)

        return send_from_directory(
            str(upload_folder),
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
        return _redirect_back_to_dashboard("portal")

    @app.post("/clients/<int:client_id>/portal/set-password")
    @login_required
    def set_portal_password(client_id: int):
        client = Client.query.get_or_404(client_id)
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not password:
            flash("Please provide a password for the client portal.", "danger")
            return _redirect_back_to_dashboard("portal")

        if password != confirm:
            flash("Passwords do not match. Please try again.", "danger")
            return _redirect_back_to_dashboard("portal")

        if len(password) < 8:
            flash("Portal passwords must be at least 8 characters long.", "danger")
            return _redirect_back_to_dashboard("portal")

        client.portal_password_hash = generate_password_hash(password)
        client.portal_password_updated_at = utcnow()
        client.portal_access_code = secrets.token_hex(16)
        db.session.commit()
        flash(f"Portal password updated for {client.email}.", "success")
        return _redirect_back_to_dashboard("portal")

    def _redirect_back_to_dashboard(default_section: str = "overview"):
        params: dict[str, str] = {}
        status_value = request.args.get("status")
        if status_value:
            params["status"] = status_value
        section_value = request.args.get("section") or default_section
        if section_value:
            params["section"] = section_value
        return redirect(url_for("dashboard", **params))

    @app.post("/clients")
    @login_required
    def create_client_admin():
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        company = request.form.get("company", "").strip()
        service_plan = request.form.get("service_plan", "").strip()
        status_value = request.form.get("status", "New").strip() or "New"
        notes = request.form.get("notes", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

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

        client = Client(
            name=name,
            email=email,
            company=company or None,
            project_type=service_plan or None,
            notes=notes or None,
            status=status_value,
        )

        if password:
            client.portal_password_hash = generate_password_hash(password)
            client.portal_password_updated_at = utcnow()

        db.session.add(client)
        db.session.commit()

        flash(f"Customer {client.name} added.", "success")
        return _redirect_back_to_dashboard("customers")

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
        db.session.add(invoice)
        db.session.commit()

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
        db.session.commit()

        flash("Invoice updated.", "success")
        return _redirect_back_to_dashboard("billing")

    @app.post("/invoices/<int:invoice_id>/delete")
    @login_required
    def delete_invoice(invoice_id: int):
        invoice = Invoice.query.get_or_404(invoice_id)
        db.session.delete(invoice)
        db.session.commit()
        flash("Invoice removed.", "info")
        return _redirect_back_to_dashboard("billing")

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

        appointment = Appointment(
            client_id=client.id,
            title=title,
            scheduled_for=scheduled_for_value,
            status="Pending",
            notes=notes,
        )

        db.session.add(appointment)
        db.session.commit()

        notify_via_snmp(
            client.email,
            f"New appointment scheduled: {title}",
            (
                f"Hello {client.name},\n\n"
                f"An appointment titled '{title}' has been scheduled for "
                f"{appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}.\n"
                + (f"Notes: {appointment.notes}\n\n" if appointment.notes else "\n")
                + "Reply from your portal to confirm or request changes."
            ),
        )

        flash("Appointment scheduled.", "success")
        return _redirect_back_to_dashboard("appointments")

    @app.post("/appointments/<int:appointment_id>/update")
    @login_required
    def update_appointment_admin(appointment_id: int):
        appointment = Appointment.query.get_or_404(appointment_id)
        status_value = (
            request.form.get("status", appointment.status).strip() or appointment.status
        )
        scheduled_for_raw = request.form.get("scheduled_for", "").strip()
        use_proposed = request.form.get("use_proposed") == "on"
        notes = request.form.get("notes", "").strip() or None

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

        appointment.status = status_value
        appointment.notes = notes

        if status_value in {"Confirmed", "Completed", "Declined"}:
            appointment.proposed_time = None
            appointment.client_message = None

        appointment.updated_at = utcnow()
        db.session.commit()

        notify_via_snmp(
            appointment.client.email,
            f"Appointment update: {appointment.title}",
            (
                f"Status: {appointment.status}\n"
                f"Scheduled for: {appointment.scheduled_for.strftime('%Y-%m-%d %H:%M %Z')}\n"
                + (f"Notes: {appointment.notes}\n" if appointment.notes else "")
            ),
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

    @app.post("/tickets/<int:ticket_id>/update")
    @login_required
    def update_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
        status_value = request.form.get("status", ticket.status).strip() or ticket.status
        resolution_notes = request.form.get("resolution_notes", "").strip() or None

        if status_value not in TICKET_STATUS_OPTIONS:
            flash("Unknown ticket status.", "danger")
            return _redirect_back_to_dashboard("support")

        ticket.status = status_value
        ticket.resolution_notes = resolution_notes
        ticket.updated_at = utcnow()
        db.session.commit()

        flash("Ticket updated.", "success")
        return _redirect_back_to_dashboard("support")

    @app.post("/tickets/<int:ticket_id>/delete")
    @login_required
    def delete_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
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
                "Provide a recipient, subject, and message to dispatch an SNMP email.",
                "danger",
            )
            return _redirect_back_to_dashboard("support")

        sent = notify_via_snmp(recipient, subject, body)

        if sent:
            flash("SNMP email notification queued for delivery.", "success")
        else:
            flash(
                "Unable to deliver SNMP email. Verify trap settings and try again.",
                "warning",
            )

        return _redirect_back_to_dashboard("support")

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
                return _redirect_back_to_dashboard("support")

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
        return _redirect_back_to_dashboard("support")

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

    @app.post("/branding/upload")
    @login_required
    def upload_branding():
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

        return send_from_directory(
            str(upload_folder),
            asset_record.stored_filename,
            as_attachment=False,
            download_name=asset_record.original_filename,
        )

    @app.post("/clients/<int:client_id>/update")
    @login_required
    def update_client(client_id: int):
        client = Client.query.get_or_404(client_id)
        status = request.form.get("status")
        notes = request.form.get("notes", "").strip()

        if status not in STATUS_OPTIONS:
            abort(400, description="Invalid status value")

        client.status = status
        client.notes = notes or None
        db.session.commit()
        flash("Client updated successfully.", "success")
        return redirect(
            url_for(
                "dashboard",
                status=request.args.get("status"),
                section=request.args.get("section", "customers"),
            )
        )

    @app.post("/clients/<int:client_id>/delete")
    @login_required
    def delete_client(client_id: int):
        client = Client.query.get_or_404(client_id)
        db.session.delete(client)
        db.session.commit()
        flash("Client removed.", "info")
        return redirect(
            url_for(
                "dashboard",
                status=request.args.get("status"),
                section=request.args.get("section", "customers"),
            )
        )


def resequence_navigation_positions() -> None:
    items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
    for index, item in enumerate(items, start=1):
        item.position = index
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
