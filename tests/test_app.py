import io
from datetime import date

import pytest

from app import (
    BrandingAsset,
    Client,
    Document,
    Equipment,
    Invoice,
    NavigationItem,
    SupportTicket,
    create_app,
    db,
    utcnow,
)
from werkzeug.security import generate_password_hash


@pytest.fixture
def app(tmp_path):
    test_db_path = tmp_path / "test.db"
    legal_folder = tmp_path / "legal"
    branding_folder = tmp_path / "branding"

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{test_db_path}",
            "LEGAL_UPLOAD_FOLDER": str(legal_folder),
            "BRANDING_UPLOAD_FOLDER": str(branding_folder),
        }
    )

    yield app

    with app.app_context():
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


def test_index_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Wireless Internet" in response.data


def test_legal_page_lists_documents(client):
    response = client.get("/legal")
    assert response.status_code == 200
    assert b"Legal Policies" in response.data
    assert b"Acceptable Use Policy" in response.data


def test_signup_creates_client_record(app, client):
    form_data = {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "company": "Acme",
        "project_type": "Website redesign",
        "notes": "Interested in onboarding next month.",
    }

    response = client.post("/signup", data=form_data, follow_redirects=True)

    assert response.status_code == 200
    assert b"Thanks for signing up" in response.data

    with app.app_context():
        client_record = Client.query.filter_by(email="alice@example.com").first()
        assert client_record is not None
        assert client_record.name == "Alice Smith"


def test_dashboard_requires_login(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Please log in to access the dashboard." in response.data


def test_admin_can_login_and_view_dashboard(client):
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    assert login_response.status_code == 200
    assert b"Welcome back!" in login_response.data
    assert b"Admin Control Center" in login_response.data
    assert b"Operations Snapshot" in login_response.data
    assert b"Header Navigation" in login_response.data
    assert b"Branding Assets" in login_response.data


def test_admin_can_upload_and_download_documents(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    upload_response = client.post(
        "/documents/upload",
        data={
            "doc_type": "aup",
            "document": (io.BytesIO(b"policy"), "aup.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert upload_response.status_code == 200
    assert b"Acceptable Use Policy uploaded successfully" in upload_response.data

    with app.app_context():
        document = Document.query.filter_by(doc_type="aup").first()
        assert document is not None
        assert document.original_filename == "aup.pdf"

    download_response = client.get("/documents/aup")
    assert download_response.status_code == 200
    assert download_response.data == b"policy"

    inline_response = client.get("/documents/aup/file")
    assert inline_response.status_code == 200
    content_disposition = inline_response.headers.get("Content-Disposition", "")
    assert "attachment" not in content_disposition.lower()


def test_admin_can_add_navigation_item(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    response = client.post(
        "/navigation/add",
        data={
            "label": "Support",
            "url": "https://support.example.com",
            "open_in_new_tab": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Navigation link added." in response.data

    with app.app_context():
        item = NavigationItem.query.filter_by(label="Support").first()
        assert item is not None
        assert item.open_in_new_tab is True


def test_admin_can_upload_branding_asset(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    response = client.post(
        "/branding/upload",
        data={
            "asset_type": "logo",
            "asset": (io.BytesIO(b"logo-bytes"), "logo.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Primary Logo updated." in response.data

    with app.app_context():
        asset = BrandingAsset.query.filter_by(asset_type="logo").first()
        assert asset is not None
        assert asset.original_filename == "logo.png"


def test_default_navigation_includes_contact(app):
    with app.app_context():
        labels = [
            item.label
            for item in NavigationItem.query.order_by(NavigationItem.position.asc()).all()
        ]
        assert "Contact" in labels


def test_document_viewer_renders_pdf_inline(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    client.post(
        "/documents/upload",
        data={
            "doc_type": "privacy",
            "document": (io.BytesIO(b"pdf-bytes"), "privacy.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    response = client.get("/documents/privacy/view")
    assert response.status_code == 200
    assert b"iframe" in response.data
    assert b"privacy.pdf" in response.data or b"Privacy Policy" in response.data


def test_document_viewer_uses_office_embed_for_word(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    client.post(
        "/documents/upload",
        data={
            "doc_type": "tos",
            "document": (io.BytesIO(b"word-bytes"), "terms.docx"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    response = client.get("/documents/tos/view")
    assert response.status_code == 200
    assert b"view.officeapps.live.com" in response.data


def test_admin_can_manage_billing_equipment_and_tickets(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    signup_response = client.post(
        "/signup",
        data={
            "name": "Billing Tester",
            "email": "billing@example.com",
            "company": "Example Co",
            "project_type": "Installation",
        },
        follow_redirects=True,
    )

    assert signup_response.status_code == 200

    with app.app_context():
        customer = Client.query.filter_by(email="billing@example.com").one()
        assert customer.portal_password_hash is None
        customer_id = customer.id

    invoice_create = client.post(
        f"/clients/{customer_id}/invoices",
        data={
            "description": "Wireless service",
            "amount": "129.99",
            "due_date": "2024-09-01",
            "status": "Pending",
        },
        follow_redirects=True,
    )

    assert invoice_create.status_code == 200

    with app.app_context():
        invoice = Invoice.query.filter_by(client_id=customer_id).one()
        assert invoice.amount_cents == 12999

    invoice_update = client.post(
        f"/invoices/{invoice.id}/update",
        data={
            "description": "Wireless service",
            "amount": "129.99",
            "due_date": "2024-09-01",
            "status": "Paid",
        },
        follow_redirects=True,
    )

    assert invoice_update.status_code == 200

    with app.app_context():
        refreshed_invoice = Invoice.query.get(invoice.id)
        assert refreshed_invoice.status == "Paid"

    equipment_create = client.post(
        f"/clients/{customer_id}/equipment",
        data={
            "name": "Subscriber Gateway",
            "model": "UISP Wave",
            "serial_number": "SN-123",
            "installed_on": "2024-08-01",
            "notes": "Mounted on roof",
        },
        follow_redirects=True,
    )

    assert equipment_create.status_code == 200

    with app.app_context():
        equipment = Equipment.query.filter_by(client_id=customer_id).one()

    equipment_update = client.post(
        f"/equipment/{equipment.id}/update",
        data={
            "name": "Subscriber Gateway",
            "model": "UISP Wave Pro",
            "serial_number": "SN-123",
            "installed_on": "2024-08-01",
            "notes": "Firmware updated",
        },
        follow_redirects=True,
    )

    assert equipment_update.status_code == 200

    with app.app_context():
        updated_equipment = Equipment.query.get(equipment.id)
        assert updated_equipment.model == "UISP Wave Pro"

    with app.app_context():
        ticket = SupportTicket(
            client_id=customer_id,
            subject="Slow speeds",
            message="Evenings are slow.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    ticket_update = client.post(
        f"/tickets/{ticket_id}/update",
        data={"status": "In Progress", "resolution_notes": "Technician scheduled."},
        follow_redirects=True,
    )

    assert ticket_update.status_code == 200

    with app.app_context():
        refreshed_ticket = SupportTicket.query.get(ticket_id)
        assert refreshed_ticket.status == "In Progress"
        assert refreshed_ticket.resolution_notes == "Technician scheduled."

    reset_response = client.post(
        f"/clients/{customer_id}/portal/reset-password",
        follow_redirects=True,
    )

    assert reset_response.status_code == 200
    assert b"Temporary portal password" in reset_response.data

    with app.app_context():
        updated_client = Client.query.get(customer_id)
        assert updated_client.portal_password_hash is not None
        assert updated_client.portal_password_updated_at is not None

    delete_invoice = client.post(
        f"/invoices/{invoice.id}/delete",
        follow_redirects=True,
    )

    assert delete_invoice.status_code == 200

    delete_equipment = client.post(
        f"/equipment/{equipment.id}/delete",
        follow_redirects=True,
    )

    assert delete_equipment.status_code == 200

    delete_ticket = client.post(
        f"/tickets/{ticket_id}/delete",
        follow_redirects=True,
    )

    assert delete_ticket.status_code == 200

    with app.app_context():
        assert Invoice.query.filter_by(client_id=customer_id).count() == 0
        assert Equipment.query.filter_by(client_id=customer_id).count() == 0
        assert SupportTicket.query.filter_by(client_id=customer_id).count() == 0


def test_client_portal_login_and_ticket_creation(app, client):
    with app.app_context():
        portal_client = Client(
            name="Daisy Duke",
            email="daisy@example.com",
            status="Active",
        )
        db.session.add(portal_client)
        db.session.commit()
        password = "TempPass123"
        portal_client.portal_password_hash = generate_password_hash(password)
        portal_client.portal_password_updated_at = utcnow()
        db.session.commit()
        portal_client_id = portal_client.id

        invoice = Invoice(
            client_id=portal_client_id,
            description="Wireless Internet",
            amount_cents=8500,
            due_date=date(2024, 9, 1),
            status="Pending",
        )
        equipment = Equipment(
            client_id=portal_client_id,
            name="Roof Antenna",
            model="UISP AirFiber",
            serial_number="ANT-001",
            installed_on=date(2024, 8, 15),
            notes="Mounted on chimney",
        )
        db.session.add_all([invoice, equipment])
        db.session.commit()

    login_response = client.post(
        "/portal/login",
        data={"email": "daisy@example.com", "password": password},
        follow_redirects=True,
    )

    assert login_response.status_code == 200
    assert b"Billing History" in login_response.data
    assert b"Wireless Internet" in login_response.data

    ticket_response = client.post(
        "/portal/tickets",
        data={"subject": "Need help", "message": "Please check signal."},
        follow_redirects=True,
    )

    assert ticket_response.status_code == 200
    assert b"support request has been submitted" in ticket_response.data

    portal_view = client.get("/portal")
    assert portal_view.status_code == 200
    assert b"Need help" in portal_view.data

    with app.app_context():
        tickets = SupportTicket.query.filter_by(client_id=portal_client_id).all()
        assert len(tickets) == 1
        assert tickets[0].subject == "Need help"
