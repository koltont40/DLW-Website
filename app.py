import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

load_dotenv()

db = SQLAlchemy()


def utcnow() -> datetime:
    return datetime.now(UTC)


class Client(db.Model):
    __tablename__ = "clients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    company = db.Column(db.String(255))
    project_type = db.Column(db.String(120))
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default="New")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

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


DEFAULT_NAVIGATION_ITEMS = [
    ("Sign Up", "/signup", False),
    ("Legal", "/legal", False),
    (
        "Client Portal",
        "https://dixielandwireless.uisp.com/crm/login",
        True,
    ),
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
        ensure_default_navigation()

    return app


def init_db() -> None:
    """Initialize the database tables if they do not exist."""

    app = create_app()
    with app.app_context():
        db.create_all()
        ensure_default_navigation()


def ensure_default_navigation() -> None:
    if NavigationItem.query.count():
        return

    for index, (label, url, new_tab) in enumerate(DEFAULT_NAVIGATION_ITEMS, start=1):
        item = NavigationItem(
            label=label,
            url=url,
            position=index,
            open_in_new_tab=new_tab,
        )
        db.session.add(item)

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


def register_routes(app: Flask) -> None:
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

    @app.get("/documents/<doc_type>")
    def download_document(doc_type: str):
        if doc_type not in LEGAL_DOCUMENT_TYPES:
            abort(404)

        document = Document.query.filter_by(doc_type=doc_type).first()
        if not document:
            abort(404)

        upload_folder = Path(app.config["LEGAL_UPLOAD_FOLDER"])
        file_path = upload_folder / document.stored_filename

        if not file_path.exists():
            abort(404)

        return send_from_directory(
            str(upload_folder),
            document.stored_filename,
            as_attachment=True,
            download_name=document.original_filename,
        )

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
