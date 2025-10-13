import os
import secrets
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
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

from sqlalchemy import inspect, or_, text

load_dotenv()

db = SQLAlchemy()


def utcnow() -> datetime:
    return datetime.now(UTC)


def generate_portal_code() -> str:
    return secrets.token_urlsafe(8)


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
        db.String(64), nullable=False, unique=True, default=generate_portal_code
    )
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

    def __repr__(self) -> str:
        return f"<Client {self.email}>"


STATUS_OPTIONS = ["New", "In Review", "Active", "On Hold", "Archived"]

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


DEFAULT_NAVIGATION_ITEMS = [
    ("Sign Up", "/signup", False),
    ("Legal", "/legal", False),
    ("Contact", "mailto:hello@example.com", False),
    ("Client Portal", "/portal/login", False),
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


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    instance_path = Path(app.instance_path)
    db_path = instance_path / "clients.db"
    os.makedirs(instance_path, exist_ok=True)

    secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(16)

    default_config = {
        "SECRET_KEY": secret_key,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "ADMIN_USERNAME": os.environ.get("ADMIN_USERNAME", "admin"),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "admin123"),
        "LEGAL_UPLOAD_FOLDER": str(instance_path / "legal"),
        "BRANDING_UPLOAD_FOLDER": str(instance_path / "branding"),
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

    return app


def init_db() -> None:
    """Initialize the database tables if they do not exist."""

    app = create_app()
    with app.app_context():
        db.create_all()
        ensure_client_portal_fields()
        ensure_default_navigation()


def ensure_default_navigation() -> None:
    max_position = db.session.query(db.func.max(NavigationItem.position)).scalar() or 0
    changed = False

    for label, url, new_tab in DEFAULT_NAVIGATION_ITEMS:
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
        if "account_reference" not in columns:
            connection.execute(
                text("ALTER TABLE clients ADD COLUMN account_reference VARCHAR(24)")
            )

    clients_to_update = (
        Client.query.filter(
            or_(Client.portal_access_code.is_(None), Client.account_reference.is_(None))
        ).all()
    )

    updated = False
    for client in clients_to_update:
        if not client.portal_access_code:
            client.portal_access_code = generate_portal_code()
            updated = True
        if not client.account_reference:
            client.account_reference = generate_account_reference()
            updated = True

    if updated:
        db.session.commit()


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
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            company = request.form.get("company", "").strip()
            project_type = request.form.get("project_type", "").strip()
            notes = request.form.get("notes", "").strip()

            if not name or not email:
                flash("Name and email are required.", "danger")
                return redirect(url_for("signup"))

            existing = Client.query.filter_by(email=email).first()
            if existing:
                flash("This email address has already been registered.", "warning")
                return redirect(url_for("signup"))

            client = Client(
                name=name,
                email=email,
                company=company or None,
                project_type=project_type or None,
                notes=notes or None,
            )
            db.session.add(client)
            db.session.commit()

            flash("Thanks for signing up! We'll be in touch shortly.", "success")
            return redirect(url_for("thank_you"))

        return render_template("signup.html")

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
            access_code = request.form.get("access_code", "").strip()

            client_record = Client.query.filter_by(email=email).first()
            if (
                client_record
                and access_code
                and secrets.compare_digest(client_record.portal_access_code, access_code)
            ):
                session[PORTAL_SESSION_KEY] = client_record.id
                session["portal_authenticated_at"] = utcnow().isoformat()
                flash("Welcome to your customer portal!", "success")
                redirect_target = request.args.get("next") or url_for("portal_dashboard")
                return redirect(redirect_target)

            flash("Invalid email or access code. Please try again.", "danger")

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
        status_filter = request.args.get("status")
        query = Client.query.order_by(Client.created_at.desc())
        if status_filter and status_filter in STATUS_OPTIONS:
            query = query.filter_by(status=status_filter)

        clients = query.all()

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

        documents = {key: None for key in LEGAL_DOCUMENT_TYPES}
        for document in Document.query.all():
            documents[document.doc_type] = document

        navigation_items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        branding_records = {asset.asset_type: asset for asset in BrandingAsset.query.all()}

        return render_template(
            "dashboard.html",
            clients=clients,
            total_clients=total_clients,
            new_this_week=new_this_week,
            outstanding_amount_cents=outstanding_amount_cents,
            open_ticket_total=open_ticket_total,
            status_filter=status_filter,
            legal_documents=documents,
            navigation_items=navigation_items,
            branding_assets=branding_records,
        )

    @app.post("/documents/upload")
    @login_required
    def upload_document():
        doc_type = request.form.get("doc_type", "")
        file = request.files.get("document")

        if doc_type not in LEGAL_DOCUMENT_TYPES:
            flash("Invalid document category.", "danger")
            return redirect(url_for("dashboard"))

        if not file or not file.filename:
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("dashboard"))

        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
            allowed_list = ", ".join(sorted(ALLOWED_DOCUMENT_EXTENSIONS))
            flash(f"Unsupported file type. Allowed formats: {allowed_list}.", "danger")
            return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard"))

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

    @app.post("/clients/<int:client_id>/portal/reset-code")
    @login_required
    def reset_portal_code(client_id: int):
        client = Client.query.get_or_404(client_id)
        client.portal_access_code = generate_portal_code()
        db.session.commit()
        flash(
            f"Portal access code regenerated for {client.name}. Share the new code securely.",
            "info",
        )
        return redirect(url_for("dashboard", status=request.args.get("status")))

    def _redirect_back_to_dashboard():
        return redirect(url_for("dashboard", status=request.args.get("status")))

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
            return _redirect_back_to_dashboard()

        try:
            amount_decimal = Decimal(amount_raw).quantize(Decimal("0.01"))
        except (InvalidOperation, TypeError):
            flash("Please provide a valid invoice amount.", "danger")
            return _redirect_back_to_dashboard()

        amount_cents = int(amount_decimal * 100)
        if amount_cents < 0:
            flash("Invoice amounts must be positive.", "danger")
            return _redirect_back_to_dashboard()

        due_date_value = None
        if due_date_raw:
            try:
                due_date_value = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for due dates.", "danger")
                return _redirect_back_to_dashboard()

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
        return _redirect_back_to_dashboard()

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
            return _redirect_back_to_dashboard()

        try:
            amount_decimal = Decimal(amount_raw).quantize(Decimal("0.01"))
        except (InvalidOperation, TypeError):
            flash("Please provide a valid invoice amount.", "danger")
            return _redirect_back_to_dashboard()

        amount_cents = int(amount_decimal * 100)
        if amount_cents < 0:
            flash("Invoice amounts must be positive.", "danger")
            return _redirect_back_to_dashboard()

        due_date_value = None
        if due_date_raw:
            try:
                due_date_value = datetime.strptime(due_date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for due dates.", "danger")
                return _redirect_back_to_dashboard()

        if status_value not in INVOICE_STATUS_OPTIONS:
            flash("Unknown invoice status.", "danger")
            return _redirect_back_to_dashboard()

        invoice.description = description
        invoice.amount_cents = amount_cents
        invoice.due_date = due_date_value
        invoice.status = status_value
        invoice.updated_at = utcnow()
        db.session.commit()

        flash("Invoice updated.", "success")
        return _redirect_back_to_dashboard()

    @app.post("/invoices/<int:invoice_id>/delete")
    @login_required
    def delete_invoice(invoice_id: int):
        invoice = Invoice.query.get_or_404(invoice_id)
        db.session.delete(invoice)
        db.session.commit()
        flash("Invoice removed.", "info")
        return _redirect_back_to_dashboard()

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
            return _redirect_back_to_dashboard()

        installed_on_value = None
        if installed_on_raw:
            try:
                installed_on_value = datetime.strptime(installed_on_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for install dates.", "danger")
                return _redirect_back_to_dashboard()

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
        return _redirect_back_to_dashboard()

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
            return _redirect_back_to_dashboard()

        installed_on_value = None
        if installed_on_raw:
            try:
                installed_on_value = datetime.strptime(installed_on_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Please use the YYYY-MM-DD format for install dates.", "danger")
                return _redirect_back_to_dashboard()

        equipment.name = name
        equipment.model = model
        equipment.serial_number = serial_number
        equipment.installed_on = installed_on_value
        equipment.notes = notes
        db.session.commit()

        flash("Equipment updated.", "success")
        return _redirect_back_to_dashboard()

    @app.post("/equipment/<int:equipment_id>/delete")
    @login_required
    def delete_equipment(equipment_id: int):
        equipment = Equipment.query.get_or_404(equipment_id)
        db.session.delete(equipment)
        db.session.commit()
        flash("Equipment removed.", "info")
        return _redirect_back_to_dashboard()

    @app.post("/tickets/<int:ticket_id>/update")
    @login_required
    def update_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
        status_value = request.form.get("status", ticket.status).strip() or ticket.status
        resolution_notes = request.form.get("resolution_notes", "").strip() or None

        if status_value not in TICKET_STATUS_OPTIONS:
            flash("Unknown ticket status.", "danger")
            return _redirect_back_to_dashboard()

        ticket.status = status_value
        ticket.resolution_notes = resolution_notes
        ticket.updated_at = utcnow()
        db.session.commit()

        flash("Ticket updated.", "success")
        return _redirect_back_to_dashboard()

    @app.post("/tickets/<int:ticket_id>/delete")
    @login_required
    def delete_ticket(ticket_id: int):
        ticket = SupportTicket.query.get_or_404(ticket_id)
        db.session.delete(ticket)
        db.session.commit()
        flash("Ticket removed.", "info")
        return _redirect_back_to_dashboard()

    @app.post("/navigation/add")
    @login_required
    def add_navigation_item():
        label = request.form.get("label", "").strip()
        url = request.form.get("url", "").strip()
        open_in_new_tab = request.form.get("open_in_new_tab") == "on"

        if not label or not url:
            flash("Navigation label and URL are required.", "danger")
            return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard"))

    @app.post("/navigation/<int:item_id>/update")
    @login_required
    def update_navigation_item(item_id: int):
        item = NavigationItem.query.get_or_404(item_id)
        label = request.form.get("label", "").strip()
        url = request.form.get("url", "").strip()
        open_in_new_tab = request.form.get("open_in_new_tab") == "on"

        if not label or not url:
            flash("Navigation label and URL are required.", "danger")
            return redirect(url_for("dashboard"))

        item.label = label
        item.url = url
        item.open_in_new_tab = open_in_new_tab
        db.session.commit()
        flash("Navigation link updated.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/navigation/<int:item_id>/delete")
    @login_required
    def delete_navigation_item(item_id: int):
        item = NavigationItem.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        resequence_navigation_positions()
        flash("Navigation link removed.", "info")
        return redirect(url_for("dashboard"))

    @app.post("/navigation/<int:item_id>/move")
    @login_required
    def move_navigation_item(item_id: int):
        direction = request.form.get("direction")
        if direction not in {"up", "down"}:
            flash("Unknown navigation action.", "danger")
            return redirect(url_for("dashboard"))

        navigation_items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        index_lookup = {item.id: idx for idx, item in enumerate(navigation_items)}

        if item_id not in index_lookup:
            abort(404)

        current_index = index_lookup[item_id]
        target_index = current_index - 1 if direction == "up" else current_index + 1

        if target_index < 0 or target_index >= len(navigation_items):
            flash("Navigation link already at the edge.", "info")
            return redirect(url_for("dashboard"))

        navigation_items[current_index], navigation_items[target_index] = (
            navigation_items[target_index],
            navigation_items[current_index],
        )

        for index, item in enumerate(navigation_items, start=1):
            item.position = index

        db.session.commit()
        flash("Navigation order updated.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/branding/upload")
    @login_required
    def upload_branding():
        asset_type = request.form.get("asset_type", "")
        file = request.files.get("asset")

        if asset_type not in BRANDING_ASSET_TYPES:
            flash("Unknown branding asset type.", "danger")
            return redirect(url_for("dashboard"))

        if not file or not file.filename:
            flash("Please choose a file to upload.", "warning")
            return redirect(url_for("dashboard"))

        filename = secure_filename(file.filename)
        extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        if extension not in ALLOWED_BRANDING_EXTENSIONS:
            allowed = ", ".join(sorted(ALLOWED_BRANDING_EXTENSIONS))
            flash(f"Unsupported branding file type. Allowed formats: {allowed}.", "danger")
            return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard", status=request.args.get("status")))

    @app.post("/clients/<int:client_id>/delete")
    @login_required
    def delete_client(client_id: int):
        client = Client.query.get_or_404(client_id)
        db.session.delete(client)
        db.session.commit()
        flash("Client removed.", "info")
        return redirect(url_for("dashboard", status=request.args.get("status")))


def resequence_navigation_positions() -> None:
    items = NavigationItem.query.order_by(NavigationItem.position.asc()).all()
    for index, item in enumerate(items, start=1):
        item.position = index
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
