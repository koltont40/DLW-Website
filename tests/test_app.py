import io
from datetime import date, timedelta

import pytest

from app import (
    BrandingAsset,
    Client,
    Document,
    Equipment,
    Invoice,
    Appointment,
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
        "service_plan": "Wireless Internet (WISP)",
        "notes": "Interested in onboarding next month.",
        "password": "SecurePass123",
        "confirm_password": "SecurePass123",
    }

    response = client.post("/signup", data=form_data, follow_redirects=True)

    assert response.status_code == 200
    assert b"Account created!" in response.data
    assert b"Billing History" in response.data

    with app.app_context():
        client_record = Client.query.filter_by(email="alice@example.com").first()
        assert client_record is not None
        assert client_record.name == "Alice Smith"
        assert client_record.project_type == "Wireless Internet (WISP)"
        assert client_record.portal_password_hash is not None


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

    navigation_response = client.get("/dashboard?section=navigation", follow_redirects=True)
    assert navigation_response.status_code == 200
    assert b"Header Navigation" in navigation_response.data

    branding_response = client.get("/dashboard?section=branding", follow_redirects=True)
    assert branding_response.status_code == 200
    assert b"Branding Assets" in branding_response.data


def test_admin_can_add_customer_via_dashboard(app, client):
    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    response = client.post(
        "/clients",
        query_string={"section": "customers"},
        data={
            "name": "Portal Admin",
            "email": "portaladmin@example.com",
            "company": "Portal Test Co",
            "service_plan": "Phone Service",
            "status": "Active",
            "notes": "Added from admin dashboard.",
            "password": "AdminPass123",
            "confirm_password": "AdminPass123",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Customer Portal Admin added." in response.data

    with app.app_context():
        admin_client = Client.query.filter_by(email="portaladmin@example.com").one()
        assert admin_client.status == "Active"
        assert admin_client.project_type == "Phone Service"
        assert admin_client.portal_password_hash is not None


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
            "service_plan": "Internet + Phone Bundle",
            "password": "BundlePass123",
            "confirm_password": "BundlePass123",
        },
        follow_redirects=True,
    )

    assert signup_response.status_code == 200

    with app.app_context():
        customer = Client.query.filter_by(email="billing@example.com").one()
        assert customer.portal_password_hash is not None
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


def test_portal_highlights_missing_service_plan(app, client):
    app.config["CONTACT_EMAIL"] = "activate@example.com"
    with app.app_context():
        portal_client = Client(
            name="No Plan Customer",
            email="noplan@example.com",
            status="Active",
        )
        portal_client.portal_password_hash = generate_password_hash("PortalPass123")
        db.session.add(portal_client)
        db.session.commit()

    login_response = client.post(
        "/portal/login",
        data={"email": "noplan@example.com", "password": "PortalPass123"},
        follow_redirects=True,
    )

    assert login_response.status_code == 200
    assert b"No service plan on file" in login_response.data
    assert b"Contact us to set up your service" in login_response.data
    assert b"mailto:activate@example.com" in login_response.data


def test_client_can_request_reschedule_and_notify_admin(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_ADMIN_EMAIL"] = "ops@example.com"
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    with app.app_context():
        portal_client = Client(
            name="Schedule Tester",
            email="schedule@example.com",
            status="Active",
            project_type="Wireless Internet (WISP)",
        )
        portal_client.portal_password_hash = generate_password_hash("PortalPass123")
        db.session.add(portal_client)
        db.session.flush()

        appointment = Appointment(
            client_id=portal_client.id,
            title="Initial Install",
            scheduled_for=utcnow(),
            notes="Bring ladder",
        )
        db.session.add(appointment)
        db.session.commit()
        appointment_id = appointment.id

    client.post(
        "/portal/login",
        data={"email": "schedule@example.com", "password": "PortalPass123"},
        follow_redirects=True,
    )

    new_time = (utcnow() + timedelta(days=2)).replace(microsecond=0)

    reschedule_response = client.post(
        f"/portal/appointments/{appointment_id}/action",
        data={
            "action": "reschedule",
            "scheduled_for": new_time.strftime("%Y-%m-%dT%H:%M"),
            "message": "Need afternoon slot",
        },
        follow_redirects=True,
    )

    assert reschedule_response.status_code == 200
    assert b"Reschedule request submitted" in reschedule_response.data

    with app.app_context():
        updated = Appointment.query.get(appointment_id)
        assert updated.status == "Reschedule Requested"
        assert updated.proposed_time is not None
        assert updated.client_message == "Need afternoon slot"

    assert notifications
    recipient, subject, body = notifications[-1]
    assert recipient == "ops@example.com"
    assert "requested a new appointment" in subject
    assert "Need afternoon slot" in body

    notifications.clear()

    approve_response = client.post(
        f"/portal/appointments/{appointment_id}/action",
        data={"action": "approve"},
        follow_redirects=True,
    )

    assert approve_response.status_code == 200
    assert b"Appointment confirmed" in approve_response.data

    with app.app_context():
        approved = Appointment.query.get(appointment_id)
        assert approved.status == "Confirmed"
        assert approved.proposed_time is None

    assert notifications
    approve_recipient, approve_subject, approve_body = notifications[-1]
    assert approve_recipient == "ops@example.com"
    assert "Appointment confirmed" in approve_subject
    assert "Status: Confirmed" in approve_body


def test_admin_can_schedule_appointment(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    with app.app_context():
        customer = Client(
            name="Field Visit Client",
            email="field@example.com",
            status="Active",
            project_type="Phone Service",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    scheduled_for = (utcnow() + timedelta(days=1)).replace(microsecond=0)

    response = client.post(
        "/appointments",
        query_string={"section": "appointments"},
        data={
            "client_id": str(customer_id),
            "title": "Roof install",
            "scheduled_for": scheduled_for.strftime("%Y-%m-%dT%H:%M"),
            "notes": "Coordinate with tower crew",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Appointment scheduled" in response.data

    with app.app_context():
        appointment = Appointment.query.filter_by(client_id=customer_id).one()
        assert appointment.title == "Roof install"
        assert appointment.status == "Pending"

    assert notifications
    notify_recipient, notify_subject, notify_body = notifications[-1]
    assert notify_recipient == "field@example.com"
    assert "Roof install" in notify_subject
    assert "appointment" in notify_body.lower()


def test_admin_can_send_manual_snmp_email(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=True,
    )

    response = client.post(
        "/notifications/snmp-email",
        data={
            "recipient": "alert@example.com",
            "subject": "Maintenance window",
            "body": "Expect brief downtime at midnight.",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"SNMP email notification queued" in response.data
    assert notifications == [
        ("alert@example.com", "Maintenance window", "Expect brief downtime at midnight."),
    ]
