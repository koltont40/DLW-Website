import io
from pathlib import Path
from datetime import date, datetime, timedelta, timezone
from html import escape
from io import BytesIO

import pytest

from app import (
    AdminUser,
    BrandingAsset,
    Client,
    Document,
    Equipment,
    Invoice,
    Appointment,
    InstallPhoto,
    InstallAcknowledgement,
    ServicePlan,
    SNMPConfig,
    Technician,
    DownDetectorConfig,
    TLSConfig,
    NavigationItem,
    BlogPost,
    SupportTicket,
    SupportTicketAttachment,
    PaymentMethod,
    AutopayEvent,
    SiteTheme,
    TeamMember,
    TrustedBusiness,
    REQUIRED_INSTALL_PHOTO_CATEGORIES,
    create_app,
    db,
    utcnow,
)
from werkzeug.security import generate_password_hash


TEST_ADMIN_USERNAME = "sys-admin"
TEST_ADMIN_PASSWORD = "SecurePass123!"


@pytest.fixture
def app(tmp_path):
    test_db_path = tmp_path / "test.db"
    legal_folder = tmp_path / "legal"
    branding_folder = tmp_path / "branding"
    theme_folder = tmp_path / "theme"
    team_folder = tmp_path / "team"
    trusted_folder = tmp_path / "trusted_businesses"
    install_folder = tmp_path / "install_photos"
    signature_folder = tmp_path / "install_signatures"
    verification_folder = tmp_path / "verification"
    ticket_attachment_folder = tmp_path / "ticket_attachments"
    tls_challenge_folder = tmp_path / "acme-challenges"
    tls_config_folder = tmp_path / "letsencrypt"
    tls_work_folder = tmp_path / "letsencrypt-work"
    tls_log_folder = tmp_path / "letsencrypt-logs"

    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{test_db_path}",
            "ADMIN_USERNAME": TEST_ADMIN_USERNAME,
            "ADMIN_PASSWORD": TEST_ADMIN_PASSWORD,
            "ADMIN_EMAIL": "ops@example.com",
            "LEGAL_UPLOAD_FOLDER": str(legal_folder),
            "BRANDING_UPLOAD_FOLDER": str(branding_folder),
            "THEME_UPLOAD_FOLDER": str(theme_folder),
            "TEAM_UPLOAD_FOLDER": str(team_folder),
            "TRUSTED_BUSINESS_UPLOAD_FOLDER": str(trusted_folder),
            "INSTALL_PHOTOS_FOLDER": str(install_folder),
            "INSTALL_SIGNATURE_FOLDER": str(signature_folder),
            "CLIENT_VERIFICATION_FOLDER": str(verification_folder),
            "SUPPORT_TICKET_ATTACHMENT_FOLDER": str(ticket_attachment_folder),
            "TLS_CHALLENGE_FOLDER": str(tls_challenge_folder),
            "TLS_CONFIG_FOLDER": str(tls_config_folder),
            "TLS_WORK_FOLDER": str(tls_work_folder),
            "TLS_LOG_FOLDER": str(tls_log_folder),
        }
    )

    yield app

    with app.app_context():
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


def login_admin(client, follow_redirects: bool = True):
    return client.post(
        "/login",
        data={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD},
        follow_redirects=follow_redirects,
    )


def create_detailed_customer_record(app):
    with app.app_context():
        technician = Technician.query.filter_by(email="lead@example.com").first()
        if technician is None:
            technician = Technician(
                name="Field Lead",
                email="lead@example.com",
                phone="205-555-0000",
                password_hash=generate_password_hash("LeadPass123!"),
                is_active=True,
            )
            db.session.add(technician)
            db.session.commit()

        customer = Client(
            name="Focus Customer",
            email="focus@example.com",
            phone="205-555-0101",
            address="100 Install Way, Prattville, AL",
            status="Active",
            residential_plan="Wireless Internet (WISP)",
            business_plan="Business Wireless Pro",
            wifi_router_needed=True,
            driver_license_number="AL-0000001",
            notes="Requires attic run for drop.",
        )
        db.session.add(customer)
        db.session.commit()

        invoice = Invoice(
            client_id=customer.id,
            description="Monthly Service",
            amount_cents=6999,
            status="Pending",
        )
        equipment = Equipment(
            client_id=customer.id,
            name="Subscriber Antenna",
            model="LTU-Rocket",
            serial_number="SN123456",
        )
        ticket = SupportTicket(
            client_id=customer.id,
            subject="Initial Setup",
            message="Confirm install documentation.",
            status="Open",
            priority="High",
        )
        appointment = Appointment(
            client_id=customer.id,
            technician_id=technician.id,
            title="On-site Activation",
            scheduled_for=(utcnow() + timedelta(days=2)).replace(microsecond=0),
            status="Confirmed",
            notes="Arrive 15 minutes early for attic access.",
        )

        db.session.add_all([invoice, equipment, ticket, appointment])
        db.session.commit()

        install_folder = Path(app.config["INSTALL_PHOTOS_FOLDER"])
        install_folder.mkdir(parents=True, exist_ok=True)
        stored_filename = f"client_{customer.id}_detail.jpg"
        (install_folder / stored_filename).write_bytes(b"photo-bytes")

        photo = InstallPhoto(
            client_id=customer.id,
            technician_id=technician.id,
            category=REQUIRED_INSTALL_PHOTO_CATEGORIES[0],
            original_filename="detail.jpg",
            stored_filename=stored_filename,
        )
        db.session.add(photo)
        db.session.commit()

        attachments_folder = Path(app.config["SUPPORT_TICKET_ATTACHMENT_FOLDER"])
        attachments_folder.mkdir(parents=True, exist_ok=True)
        ticket_folder = attachments_folder / f"ticket_{ticket.id}"
        ticket_folder.mkdir(parents=True, exist_ok=True)
        attachment_name = "diagnostic.log"
        (ticket_folder / attachment_name).write_bytes(b"log-data")

        attachment = SupportTicketAttachment(
            ticket_id=ticket.id,
            original_filename=attachment_name,
            stored_filename=f"ticket_{ticket.id}/{attachment_name}",
        )
        db.session.add(attachment)
        db.session.commit()

        return customer.id


def test_index_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Wireless Internet" in response.data
    assert b"/services#plans-phone-service" in response.data
    assert b"Businesses that trust us" in response.data
    assert b"Showcase the businesses you support" in response.data


def test_index_page_lists_trusted_businesses(app, client):
    with app.app_context():
        partner = TrustedBusiness(
            name="Main Street Market",
            website_url="https://market.example.com",
            position=1,
        )
        db.session.add(partner)
        db.session.commit()

    response = client.get("/")
    assert response.status_code == 200
    assert b"Main Street Market" in response.data
    assert b"https://market.example.com" in response.data


def test_service_plans_page_lists_offerings(client):
    response = client.get("/services")
    assert response.status_code == 200
    assert b"Residential Plans" in response.data
    assert b"Phone Service Plans" in response.data
    assert b'id="plans-phone-service"' in response.data
    assert b"Wireless Internet (WISP)" in response.data
    assert b"Internet + Phone Bundle" in response.data
    assert b"Business Wireless Pro" in response.data
    assert b"Business Voice Essentials" in response.data


def test_phone_service_page_lists_offerings(client):
    response = client.get("/phone-service")
    assert response.status_code == 200
    assert b"Phone Service Plans" in response.data
    assert b"Phone Service" in response.data
    assert b"Business Voice Essentials" in response.data


def test_about_page_highlights_mission(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"Our Mission" in response.data
    assert b"local experts" in response.data


def test_about_page_lists_team_members(app, client):
    with app.app_context():
        member = TeamMember(
            name="Jordan Williams",
            title="Network Ops Manager",
            bio="Keeps towers tuned for peak performance.",
            position=1,
        )
        db.session.add(member)
        db.session.commit()

    response = client.get("/about")
    assert response.status_code == 200
    assert b"Jordan Williams" in response.data
    assert b"Network Ops Manager" in response.data
    assert b"Keeps towers tuned for peak performance." in response.data


def test_support_page_offers_resources(client):
    response = client.get("/support")
    assert response.status_code == 200
    assert b"Support center" in response.data
    assert b"Email support" in response.data


def test_uptime_page_displays_metrics(client):
    response = client.get("/uptime")
    assert response.status_code == 200
    assert b"Network uptime" in response.data
    assert b"30-day uptime" in response.data


def test_service_cancellation_page_outlines_steps(client):
    response = client.get("/cancellation")
    assert response.status_code == 200
    assert b"Service cancellation" in response.data
    assert b"Submit your request" in response.data


def test_down_detector_placeholder_when_missing(client):
    response = client.get("/status/down-detector")
    assert response.status_code == 200
    assert b"live outage feed" in response.data


def test_down_detector_redirects_when_configured(app, client):
    with app.app_context():
        config = DownDetectorConfig.query.first()
        config.target_url = "https://status.example.com"
        db.session.commit()

    response = client.get("/status/down-detector")
    assert response.status_code == 302
    assert response.headers["Location"] == "https://status.example.com"


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
        "phone": "334-555-1212",
        "address": "123 Main Street, Tallassee, AL 36078",
        "wants_residential": "yes",
        "wants_phone": "yes",
        "residential_plan": "Wireless Internet (WISP)",
        "phone_plan": "Phone Service",
        "business_plan": "",
        "notes": "Interested in onboarding next month.",
        "driver_license_number": "AL-1234567",
        "password": "SecurePass123",
        "confirm_password": "SecurePass123",
        "wifi_router_needed": "yes",
        "verification_photo": (BytesIO(b"fake-id-data"), "id-card.jpg"),
    }

    response = client.post(
        "/signup",
        data=form_data,
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Account created!" in response.data
    assert b"Billing History" in response.data

    with app.app_context():
        client_record = Client.query.filter_by(email="alice@example.com").first()
        assert client_record is not None
        assert client_record.name == "Alice Smith"
        assert client_record.project_type == "Wireless Internet (WISP), Phone Service"
        assert client_record.residential_plan == "Wireless Internet (WISP)"
        assert client_record.phone_plan == "Phone Service"
        assert client_record.business_plan is None
        assert client_record.service_summary == "Wireless Internet (WISP), Phone Service"
        assert client_record.portal_password_hash is not None
        assert client_record.phone == "334-555-1212"
        assert client_record.address == "123 Main Street, Tallassee, AL 36078"
        assert client_record.driver_license_number == "AL-1234567"
        assert client_record.verification_photo_filename is not None
        assert client_record.verification_photo_uploaded_at is not None
        assert client_record.wifi_router_needed is True

    photo_response = client.get(
        f"/clients/{client_record.id}/verification-photo"
    )
    assert photo_response.status_code == 200
    assert photo_response.data == b"fake-id-data"


def test_dashboard_requires_login(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Please log in to access the dashboard." in response.data


def test_admin_can_login_and_view_dashboard(client):
    login_response = login_admin(client)

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


def test_admin_can_create_team_member_with_photo(app, client):
    login_admin(client)

    response = client.post(
        "/team-members",
        data={
            "name": "Jordan Williams",
            "title": "Network Ops Manager",
            "bio": "Keeps towers tuned for peak performance.",
            "photo": (BytesIO(b"fake-image"), "headshot.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Added Jordan Williams to the team." in response.data

    with app.app_context():
        member = TeamMember.query.filter_by(name="Jordan Williams").first()
        assert member is not None
        assert member.title == "Network Ops Manager"
        assert member.bio == "Keeps towers tuned for peak performance."
        assert member.photo_filename is not None
        member_id = member.id
        photo_path = Path(app.config["TEAM_UPLOAD_FOLDER"]) / member.photo_filename
        assert photo_path.exists()

    photo_response = client.get(f"/team-members/{member_id}/photo")
    assert photo_response.status_code == 200
    assert b"fake-image" in photo_response.data


def test_admin_can_create_trusted_business_with_logo(app, client):
    login_admin(client)

    response = client.post(
        "/trusted-businesses",
        data={
            "name": "Main Street Market",
            "website_url": "https://market.example.com",
            "logo": (BytesIO(b"<svg></svg>"), "logo.svg"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Added Main Street Market to your trusted partners." in response.data

    with app.app_context():
        business = TrustedBusiness.query.filter_by(name="Main Street Market").first()
        assert business is not None
        assert business.website_url == "https://market.example.com"
        assert business.logo_filename is not None
        business_id = business.id
        logo_path = Path(app.config["TRUSTED_BUSINESS_UPLOAD_FOLDER"]) / business.logo_filename
        assert logo_path.exists()

    logo_response = client.get(f"/trusted-businesses/{business_id}/logo")
    assert logo_response.status_code == 200
    assert b"<svg" in logo_response.data


def test_admin_can_view_security_settings(client):
    login_admin(client)

    response = client.get("/dashboard?section=security", follow_redirects=True)

    assert response.status_code == 200
    assert b"HTTPS &amp; Certificates" in response.data
    assert b"Request certificate" in response.data
    assert b"Portal administrators" in response.data
    assert b"Add administrator" in response.data
    assert b"Add another admin to enable removal." in response.data


def test_admin_cannot_remove_last_admin(app, client):
    login_admin(client)

    with app.app_context():
        last_admin = AdminUser.query.first()
        assert last_admin is not None
        admin_id = last_admin.id

    response = client.post(
        f"/dashboard/security/admins/{admin_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Add another administrator before removing this account." in response.data


def test_admin_can_remove_other_admin(app, client):
    login_admin(client)

    with app.app_context():
        current_admin = AdminUser.query.first()
        assert current_admin is not None
        removable_admin = AdminUser(username="ops-two", email="ops2@example.com")
        removable_admin.set_password("AnotherPass123!")
        db.session.add(removable_admin)
        db.session.commit()
        removable_id = removable_admin.id

    # still signed in as the first admin; removing the second should succeed
    response = client.post(
        f"/dashboard/security/admins/{removable_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Administrator removed." in response.data

    with app.app_context():
        assert AdminUser.query.get(removable_id) is None


def test_admin_cannot_remove_current_admin(app, client):
    login_admin(client)

    with app.app_context():
        current_admin = AdminUser.query.first()
        assert current_admin is not None
        other_admin = AdminUser(username="ops-three", email="ops3@example.com")
        other_admin.set_password("ThirdPass123!")
        db.session.add(other_admin)
        db.session.commit()
        current_admin_id = current_admin.id

    response = client.post(
        f"/dashboard/security/admins/{current_admin_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"You cannot remove the administrator currently signed in." in response.data


def test_admin_can_save_tls_settings(app, client):
    login_admin(client)

    response = client.post(
        "/dashboard/security/tls",
        data={
            "domain": "secure.example.com",
            "contact_email": "admin@example.com",
            "auto_renew": "on",
            "action": "save",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"TLS settings saved." in response.data

    with app.app_context():
        tls_config = TLSConfig.query.first()
        assert tls_config is not None
        assert tls_config.domain == "secure.example.com"
        assert tls_config.contact_email == "admin@example.com"
        assert tls_config.auto_renew is True
        assert tls_config.status == "pending"


def test_tls_provision_records_error_when_certbot_missing(app, client, monkeypatch):
    login_admin(client)

    monkeypatch.setattr("app.shutil.which", lambda _: None)

    response = client.post(
        "/dashboard/security/tls",
        data={
            "domain": "secure.example.com",
            "contact_email": "admin@example.com",
            "action": "provision",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Certificate request failed" in response.data

    with app.app_context():
        tls_config = TLSConfig.query.first()
        assert tls_config is not None
    assert tls_config.status == "error"
    assert tls_config.last_error is not None
    assert "certbot" in tls_config.last_error.lower()


def test_admin_can_create_additional_admin_user(app, client):
    login_admin(client)

    response = client.post(
        "/dashboard/security/admins",
        data={
            "username": "opslead",
            "email": "opslead@example.com",
            "password": "StrongPass!2",
            "confirm_password": "StrongPass!2",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Admin account created successfully." in response.data

    with app.app_context():
        new_admin = AdminUser.query.filter_by(username="opslead").one()
        assert new_admin.email == "opslead@example.com"
        assert new_admin.check_password("StrongPass!2")


def test_admin_can_add_customer_via_dashboard(app, client):
    login_admin(client)

    response = client.post(
        "/clients",
        query_string={"section": "customers"},
        data={
            "name": "Portal Admin",
            "email": "portaladmin@example.com",
            "company": "Portal Test Co",
            "phone": "205-555-8899",
            "address": "500 Service Lane, Montgomery, AL",
            "residential_plan": "",
            "phone_plan": "Phone Service",
            "business_plan": "Business Wireless Pro",
            "status": "Active",
            "notes": "Added from admin dashboard.",
            "driver_license_number": "AL-7654321",
            "password": "AdminPass123",
            "confirm_password": "AdminPass123",
            "wifi_router_needed": "yes",
            "verification_photo": (BytesIO(b"admin-id"), "admin-id.png"),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Customer Portal Admin added." in response.data

    with app.app_context():
        admin_client = Client.query.filter_by(email="portaladmin@example.com").one()
        assert admin_client.status == "Active"
        assert admin_client.project_type == "Phone Service, Business Wireless Pro"
        assert admin_client.phone_plan == "Phone Service"
        assert admin_client.business_plan == "Business Wireless Pro"
        assert admin_client.residential_plan is None
        assert admin_client.portal_password_hash is not None
        assert admin_client.phone == "205-555-8899"
        assert admin_client.address == "500 Service Lane, Montgomery, AL"
        assert admin_client.driver_license_number == "AL-7654321"
        assert admin_client.verification_photo_filename is not None
        assert admin_client.wifi_router_needed is True

    admin_photo_response = client.get(
        f"/clients/{admin_client.id}/verification-photo"
    )
    assert admin_photo_response.status_code == 200
    assert admin_photo_response.data == b"admin-id"


def test_customer_focus_view_surfaces_account_summary(app, client):
    login_admin(client)

    focus_id = create_detailed_customer_record(app)

    response = client.get(
        "/dashboard",
        query_string={"section": "customers", "focus": focus_id},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Focus Customer" in response.data
    assert b"Install documentation" in response.data
    assert b"Monthly Service" in response.data
    assert b"Subscriber Antenna" in response.data
    assert b"Initial Setup" in response.data
    assert b"On-site Activation" in response.data
    assert escape(REQUIRED_INSTALL_PHOTO_CATEGORIES[0]).encode() in response.data
    assert escape(REQUIRED_INSTALL_PHOTO_CATEGORIES[1]).encode() in response.data


def test_customer_directory_links_to_admin_account_view(app, client):
    login_admin(client)

    customer_id = create_detailed_customer_record(app)

    response = client.get(
        "/dashboard",
        query_string={"section": "customers"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert f"/dashboard/customers/{customer_id}".encode() in response.data
    assert b"Focus Customer" in response.data


def test_admin_customer_account_view_shows_details(app, client):
    login_admin(client)

    customer_id = create_detailed_customer_record(app)

    response = client.get(f"/dashboard/customers/{customer_id}", follow_redirects=True)

    assert response.status_code == 200
    assert b"Customer Account" in response.data
    assert b"Focus Customer" in response.data
    assert b"Monthly Service" in response.data
    assert b"Subscriber Antenna" in response.data
    assert b"Initial Setup" in response.data
    assert b"diagnostic.log" in response.data
    assert b"On-site Activation" in response.data
    assert b"Install documentation" in response.data


def test_admin_updates_service_plans_from_account_view(app, client):
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Plan Update",
            email="planupdate@example.com",
            status="New",
        )
        db.session.add(customer)
        db.session.flush()

        plans = [
            ServicePlan(
                name="Fiber Home 100",
                category="Residential",
                price_cents=10999,
            ),
            ServicePlan(
                name="VoIP Essential",
                category="Phone Service",
                price_cents=3999,
            ),
            ServicePlan(
                name="Business Wave",
                category="Business",
                price_cents=18999,
            ),
        ]
        db.session.add_all(plans)
        db.session.commit()
        customer_id = customer.id

    next_url = f"/dashboard/customers/{customer_id}"
    response = client.post(
        f"/clients/{customer_id}/service-plans",
        data={
            "residential_plan": "Fiber Home 100",
            "phone_plan": "VoIP Essential",
            "business_plan": "",
            "status": "Active",
            "wifi_router_needed": "yes",
            "next": next_url,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(next_url)

    with app.app_context():
        updated = Client.query.get(customer_id)
        assert updated.status == "Active"
        assert updated.residential_plan == "Fiber Home 100"
        assert updated.phone_plan == "VoIP Essential"
        assert updated.business_plan is None
        assert updated.wifi_router_needed is True
        assert updated.project_type == "Fiber Home 100, VoIP Essential"


def test_admin_adds_invoice_from_account_view(app, client):
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Billing Target",
            email="billing@example.com",
            status="Active",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    next_url = f"/dashboard/customers/{customer_id}"
    response = client.post(
        f"/clients/{customer_id}/invoices",
        data={
            "description": "Monthly service",
            "amount": "79.99",
            "due_date": "2024-12-01",
            "status": "Pending",
            "next": next_url,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(next_url)

    with app.app_context():
        invoices = Invoice.query.filter_by(client_id=customer_id).all()
        assert len(invoices) == 1
        assert invoices[0].description == "Monthly service"
        assert invoices[0].amount_cents == 7999


def test_autopay_run_pays_due_invoices(app, client):
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Autopay Success",
            email="auto-success@example.com",
            status="Active",
            autopay_enabled=True,
        )
        db.session.add(customer)
        db.session.commit()

        method = PaymentMethod(
            client_id=customer.id,
            nickname="Primary",
            brand="Visa",
            last4="1111",
            exp_month=12,
            exp_year=date.today().year + 1,
            token="tok-success",
            is_default=True,
        )
        invoice = Invoice(
            client_id=customer.id,
            description="Internet service",
            amount_cents=5000,
            status="Pending",
            due_date=date.today(),
        )
        db.session.add_all([method, invoice])
        db.session.commit()
        customer_id = customer.id

    response = client.post("/autopay/run", follow_redirects=True)
    assert response.status_code == 200
    assert b"Autopay processed" in response.data

    with app.app_context():
        invoice = Invoice.query.filter_by(client_id=customer_id).one()
        assert invoice.status == "Paid"
        assert invoice.paid_via.startswith("Autopay")
        customer = Client.query.get(customer_id)
        assert customer.billing_status == "Good Standing"
        assert customer.service_suspended is False
        events = AutopayEvent.query.filter_by(client_id=customer_id).all()
        assert len(events) == 1
        assert events[0].status == "success"


def test_autopay_run_suspends_when_no_method(app, client):
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Autopay Failure",
            email="auto-fail@example.com",
            status="Active",
            autopay_enabled=True,
        )
        db.session.add(customer)
        db.session.commit()

        invoice = Invoice(
            client_id=customer.id,
            description="Managed service",
            amount_cents=4200,
            status="Pending",
            due_date=date.today(),
        )
        db.session.add(invoice)
        db.session.commit()
        customer_id = customer.id

    response = client.post("/autopay/run", follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        invoice = Invoice.query.filter_by(client_id=customer_id).one()
        assert invoice.status == "Pending"
        assert invoice.autopay_status == "Missing Method"
        customer = Client.query.get(customer_id)
        assert customer.service_suspended is True
        assert customer.billing_status == "Delinquent"
        events = AutopayEvent.query.filter_by(client_id=customer_id).all()
        assert any(event.status == "failed" for event in events)


def test_admin_adds_equipment_from_account_view(app, client):
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Equipment Owner",
            email="equip@example.com",
            status="Active",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    next_url = f"/dashboard/customers/{customer_id}"
    response = client.post(
        f"/clients/{customer_id}/equipment",
        data={
            "name": "Subscriber Router",
            "model": "UISP Express",
            "serial_number": "SR-001",
            "installed_on": "2024-08-01",
            "notes": "Mounted in living room closet",
            "next": next_url,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(next_url)

    with app.app_context():
        devices = Equipment.query.filter_by(client_id=customer_id).all()
        assert len(devices) == 1
        assert devices[0].name == "Subscriber Router"
        assert str(devices[0].installed_on) == "2024-08-01"


def test_admin_schedules_appointment_from_account_view(app, client):
    login_admin(client)

    with app.app_context():
        technician = Technician(
            name="Account Tech",
            email="account-tech@example.com",
            password_hash=generate_password_hash("TechPass123"),
            is_active=True,
        )
        customer = Client(
            name="Schedule Customer",
            email="schedule-admin@example.com",
            status="Active",
        )
        db.session.add_all([technician, customer])
        db.session.commit()
        technician_id = technician.id
        customer_id = customer.id

    scheduled_for = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)
    next_url = f"/dashboard/customers/{customer_id}"
    app.config["SNMP_EMAIL_SENDER"] = lambda *args, **kwargs: True

    response = client.post(
        "/appointments",
        data={
            "client_id": customer_id,
            "title": "Service visit",
            "scheduled_for": scheduled_for.isoformat(timespec="minutes"),
            "technician_id": technician_id,
            "notes": "Bring replacement router",
            "next": next_url,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(next_url)

    with app.app_context():
        appointments = Appointment.query.filter_by(client_id=customer_id).all()
        assert len(appointments) == 1
        assert appointments[0].title == "Service visit"
        assert appointments[0].technician_id == technician_id


def test_admin_customer_account_view_requires_login(client):
    response = client.get("/dashboard/customers/1", follow_redirects=False)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_admin_can_manage_service_plans(app, client):
    login_admin(client)

    create_response = client.post(
        "/service-plans",
        data={
            "name": "Business Fiber Elite",
            "category": "Business",
            "price": "209.99",
            "speed": "Up to 1 Gbps",
            "description": "Symmetric fiber-backed wireless for enterprises.",
            "features": "24/7 monitoring\nStatic IPs\nPriority install",
        },
        follow_redirects=True,
        query_string={"section": "plans"},
    )

    assert create_response.status_code == 200
    assert b"Service plan created." in create_response.data

    with app.app_context():
        plan = ServicePlan.query.filter_by(name="Business Fiber Elite").one()
        assert plan.category == "Business"
        assert plan.price_cents == 20999
        assert "Static IPs" in plan.feature_list

    update_response = client.post(
        f"/service-plans/{plan.id}/update",
        data={
            "name": "Business Fiber Elite",
            "category": "Business",
            "price": "219.99",
            "speed": "Up to 1 Gbps",
            "description": "Updated description",
            "features": "24/7 monitoring\nStatic IPs\nDedicated account team",
        },
        follow_redirects=True,
        query_string={"section": "plans"},
    )

    assert update_response.status_code == 200
    assert b"Service plan updated." in update_response.data

    delete_response = client.post(
        f"/service-plans/{plan.id}/delete",
        follow_redirects=True,
        query_string={"section": "plans"},
    )

    assert delete_response.status_code == 200
    assert b"Service plan removed." in delete_response.data

    with app.app_context():
        assert ServicePlan.query.filter_by(name="Business Fiber Elite").first() is None


def test_admin_can_upload_and_download_documents(app, client):
    login_admin(client)

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
    login_admin(client)

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
    login_admin(client)

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


def test_admin_can_update_site_theme(app, client):
    login_admin(client)

    response = client.post(
        "/branding/theme",
        data={"background_color": "#ffffff"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Updated the site background and text colors." in response.data

    with app.app_context():
        theme = SiteTheme.query.first()
        assert theme is not None
        assert theme.background_color == "#ffffff"
        assert theme.text_color == "#111827"
        assert theme.muted_color == "#475569"


def test_admin_can_manage_theme_background_image(app, client):
    login_admin(client)

    image_bytes = b"fake-image-bytes"
    response = client.post(
        "/branding/theme",
        data={
            "background_color": "#123456",
            "background_photo": (io.BytesIO(image_bytes), "skyline.jpg"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Updated the site background image and colors." in response.data

    with app.app_context():
        theme = SiteTheme.query.first()
        assert theme is not None
        assert theme.background_color == "#123456"
        assert theme.background_image_filename is not None
        upload_folder = Path(app.config["THEME_UPLOAD_FOLDER"])
        stored_path = upload_folder / theme.background_image_filename
        assert stored_path.exists()

    background_response = client.get("/branding/theme-background")
    assert background_response.status_code == 200
    assert background_response.data == image_bytes

    response = client.post(
        "/branding/theme",
        data={"background_color": "#654321", "remove_background_photo": "1"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Removed the background photo and refreshed colors." in response.data

    with app.app_context():
        theme = SiteTheme.query.first()
        assert theme is not None
        assert theme.background_color == "#654321"
        assert theme.background_image_filename is None
        upload_folder = Path(app.config["THEME_UPLOAD_FOLDER"])
        assert not any(upload_folder.iterdir())

def test_default_navigation_excludes_support_dropdown_links(app):
    with app.app_context():
        navigation_items = NavigationItem.query.order_by(
            NavigationItem.position.asc()
        ).all()
        urls = {item.url for item in navigation_items}

        assert "/support" not in urls
        assert "/uptime" not in urls
        assert "/cancellation" not in urls
        assert "/status/down-detector" not in urls
        assert "/phone-service" not in urls

        labels = {item.label for item in navigation_items}
        assert "Sign Up" in labels
        assert "Service Plans" in labels
        assert "Phone Service" not in labels


def test_admin_can_create_blog_post_and_publish(app, client):
    login_admin(client)

    response = client.post(
        "/blog/posts",
        data={
            "title": "Tower Expansion",
            "summary": "We are lighting up new coverage north of town.",
            "content": "Crews completed a new sector to boost speeds across the county.",
            "publish": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Blog post created." in response.data

    with app.app_context():
        post = BlogPost.query.filter_by(title="Tower Expansion").one()
        assert post.is_published is True
        assert post.slug
        slug = post.slug

    list_response = client.get("/blog")
    assert list_response.status_code == 200
    assert b"Tower Expansion" in list_response.data

    detail_response = client.get(f"/blog/{slug}")
    assert detail_response.status_code == 200
    assert b"Crews completed a new sector" in detail_response.data


def test_blog_draft_hidden_from_public(app, client):
    login_admin(client)

    client.post(
        "/blog/posts",
        data={
            "title": "Draft Update",
            "summary": "Behind-the-scenes prep.",
            "content": "Technicians are preparing for the next deployment.",
        },
        follow_redirects=True,
    )

    client.get("/logout", follow_redirects=True)

    with app.app_context():
        draft = BlogPost.query.filter_by(title="Draft Update").one()
        slug = draft.slug
        assert draft.is_published is False

    list_response = client.get("/blog")
    assert list_response.status_code == 200
    assert b"Draft Update" not in list_response.data

    detail_response = client.get(f"/blog/{slug}")
    assert detail_response.status_code == 404


def test_admin_can_update_blog_post_status(app, client):
    login_admin(client)

    client.post(
        "/blog/posts",
        data={
            "title": "Status Check",
            "summary": "Initial summary",
            "content": "Initial content",
            "publish": "on",
        },
        follow_redirects=True,
    )

    with app.app_context():
        post = BlogPost.query.filter_by(title="Status Check").one()
        post_id = post.id
        original_slug = post.slug

    update_response = client.post(
        f"/blog/posts/{post_id}",
        data={
            "title": "Status Check Updated",
            "summary": "Revised summary",
            "content": "Revised content",
        },
        follow_redirects=True,
    )

    assert update_response.status_code == 200
    assert b"Blog post updated." in update_response.data

    with app.app_context():
        updated = BlogPost.query.get(post_id)
        assert updated.title == "Status Check Updated"
        assert updated.is_published is False
        assert updated.published_at is None
        assert updated.slug != original_slug

    client.get("/logout", follow_redirects=True)

    detail_response = client.get(f"/blog/{updated.slug}")
    assert detail_response.status_code == 404


def test_document_viewer_renders_pdf_inline(app, client):
    login_admin(client)

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
    login_admin(client)

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
    login_admin(client)

    signup_response = client.post(
        "/signup",
        data={
            "name": "Billing Tester",
            "email": "billing@example.com",
            "company": "Example Co",
            "phone": "205-555-0100",
            "address": "900 Commerce Rd, Tallassee, AL",
            "service_plan": "Internet + Phone Bundle",
            "driver_license_number": "AL-4455667",
            "password": "BundlePass123",
            "confirm_password": "BundlePass123",
            "verification_photo": (io.BytesIO(b"billing-id"), "billing-id.jpg"),
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
        data={
            "subject": "Need help",
            "message": "Please check signal.",
            "priority": "High",
            "attachments": (BytesIO(b"image-bytes"), "outage.jpg"),
        },
        follow_redirects=True,
        content_type="multipart/form-data",
    )

    assert ticket_response.status_code == 200
    assert b"support request has been submitted" in ticket_response.data

    portal_view = client.get("/portal")
    assert portal_view.status_code == 200
    assert b"Need help" in portal_view.data
    assert b"Priority: High" in portal_view.data

    with app.app_context():
        tickets = SupportTicket.query.filter_by(client_id=portal_client_id).all()
        assert len(tickets) == 1
        assert tickets[0].subject == "Need help"
        assert tickets[0].priority == "High"
        attachments = SupportTicketAttachment.query.filter_by(ticket_id=tickets[0].id).all()
        assert len(attachments) == 1
        stored_path = Path(app.config["SUPPORT_TICKET_ATTACHMENT_FOLDER"]) / attachments[0].stored_filename
        assert stored_path.exists()


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

    login_admin(client)

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

    login_admin(client)

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


def test_admin_can_update_snmp_settings(app, client):
    login_admin(client)

    response = client.post(
        "/snmp-settings",
        data={
            "host": "trap.dixie.local",
            "port": "1162",
            "community": "dlw-community",
            "enterprise_oid": "1.3.6.1.4.1.9999",
            "admin_email": "noc@dixielandwireless.com",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"SNMP settings updated" in response.data

    with app.app_context():
        config = SNMPConfig.query.first()
        assert config is not None
        assert config.host == "trap.dixie.local"
        assert config.port == 1162
        assert config.community == "dlw-community"
        assert config.enterprise_oid == "1.3.6.1.4.1.9999"
        assert config.admin_email == "noc@dixielandwireless.com"
        assert app.config["SNMP_TRAP_HOST"] == "trap.dixie.local"
        assert app.config["SNMP_TRAP_PORT"] == 1162
        assert app.config["SNMP_COMMUNITY"] == "dlw-community"
        assert app.config["SNMP_ADMIN_EMAIL"] == "noc@dixielandwireless.com"


def test_technician_portal_login_and_dashboard(app, client):
    with app.app_context():
        technician = Technician(
            name="Taylor Reed",
            email="tech@example.com",
            password_hash=generate_password_hash("Install123"),
            is_active=True,
        )
        customer = Client(
            name="Dakota Lane",
            email="dakota@example.com",
            project_type="Wireless Internet (WISP)",
            status="Active",
        )
        appointment = Appointment(
            client=customer,
            technician=technician,
            title="Tower install",
            scheduled_for=utcnow() + timedelta(hours=2),
            status="Pending",
        )
        db.session.add_all([technician, customer, appointment])
        db.session.commit()

    response = client.post(
        "/tech/login",
        data={"email": "tech@example.com", "password": "Install123"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Welcome, Taylor Reed" in response.data
    assert b"Upcoming visits" in response.data


def test_technician_uploads_install_photo(app, client):
    with app.app_context():
        technician = Technician(
            name="Sky Nguyen",
            email="field@example.com",
            password_hash=generate_password_hash("StrongPass!"),
            is_active=True,
        )
        customer = Client(
            name="Jordan Fields",
            email="jordan@example.com",
            project_type="Phone Service",
            status="Active",
        )
        appointment = Appointment(
            client=customer,
            technician=technician,
            title="Phone ATA install",
            scheduled_for=utcnow() + timedelta(hours=1),
            status="Pending",
        )
        db.session.add_all([technician, customer, appointment])
        db.session.commit()
        appointment_id = appointment.id
        client_id = customer.id

    login_response = client.post(
        "/tech/login",
        data={"email": "field@example.com", "password": "StrongPass!"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    detail_response = client.get(f"/tech/appointments/{appointment_id}")
    assert detail_response.status_code == 200

    upload_data = {
        "appointment_id": str(appointment_id),
        "category": REQUIRED_INSTALL_PHOTO_CATEGORIES[0],
        "notes": "Mounted to west gable.",
        "next": f"/tech/appointments/{appointment_id}",
        "photo": (io.BytesIO(b"fake image bytes"), "install.jpg"),
    }

    response = client.post(
        f"/tech/clients/{client_id}/photos",
        data=upload_data,
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Photo uploaded" in response.data

    with app.app_context():
        photos = InstallPhoto.query.filter_by(client_id=client_id).all()
        assert len(photos) == 1
        stored_path = Path(app.config["INSTALL_PHOTOS_FOLDER"]) / photos[0].stored_filename
        assert stored_path.exists()


def test_technician_captures_install_acknowledgement(app, client):
    with app.app_context():
        technician = Technician(
            name="Signature Tech",
            email="signature@example.com",
            password_hash=generate_password_hash("Signature123"),
            is_active=True,
        )
        customer = Client(
            name="Signature Customer",
            email="signature-customer@example.com",
            status="Active",
        )
        appointment = Appointment(
            client=customer,
            technician=technician,
            title="Signature walkthrough",
            scheduled_for=utcnow() + timedelta(hours=3),
            status="Pending",
        )
        db.session.add_all([technician, customer, appointment])
        db.session.commit()
        appointment_id = appointment.id
        client_id = customer.id
        technician_id = technician.id

    login_response = client.post(
        "/tech/login",
        data={"email": "signature@example.com", "password": "Signature123"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    signature_data = (
        "data:image/png;base64,"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAukB9XY3YoAAAAAASUVORK5CYII="
    )

    response = client.post(
        f"/tech/appointments/{appointment_id}/acknowledgements",
        data={
            "signed_name": "Signature Customer",
            "signature_data": signature_data,
            "accept_aup": "on",
            "accept_privacy": "on",
            "accept_tos": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Customer acknowledgement captured" in response.data

    with app.app_context():
        acknowledgement = InstallAcknowledgement.query.filter_by(appointment_id=appointment_id).one()
        assert acknowledgement.signed_name == "Signature Customer"
        assert acknowledgement.technician_id == technician_id
        signature_path = Path(app.config["INSTALL_SIGNATURE_FOLDER"]) / acknowledgement.signature_filename
        assert signature_path.exists()
