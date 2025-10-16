import io
from pathlib import Path
from datetime import date, datetime, timedelta, timezone
from html import escape
from io import BytesIO
from types import SimpleNamespace

import pytest

import app as app_module
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
    InstallPhotoRequirement,
    ServicePlan,
    SNMPConfig,
    Technician,
    TechnicianSchedule,
    DownDetectorConfig,
    TLSConfig,
    NavigationItem,
    BlogPost,
    SupportTicket,
    SupportTicketMessage,
    SupportTicketAttachment,
    PaymentMethod,
    AutopayEvent,
    SiteTheme,
    TeamMember,
    TrustedBusiness,
    SupportPartner,
    StripeConfig,
    NotificationConfig,
    UispDevice,
    UispConfig,
    NetworkTower,
    create_app,
    db,
    get_stripe_publishable_key,
    apply_stripe_config_from_database,
    get_install_photo_category_choices,
    get_required_install_photo_categories,
    utcnow,
)
from werkzeug.security import generate_password_hash


class StripeStub:
    class Customer:
        @staticmethod
        def create(**kwargs):
            return SimpleNamespace(id="cus_test")

        @staticmethod
        def modify(customer_id, **kwargs):
            return SimpleNamespace(id=customer_id)

    class PaymentMethod:
        @staticmethod
        def retrieve(payment_method_id):
            return SimpleNamespace(
                type="card",
                card=SimpleNamespace(
                    brand="Visa",
                    last4="4242",
                    exp_month=12,
                    exp_year=date.today().year + 2,
                ),
                billing_details=SimpleNamespace(
                    name="Test User",
                    address=SimpleNamespace(postal_code="12345"),
                ),
                customer=None,
            )

        @staticmethod
        def attach(payment_method_id, customer=None):
            return SimpleNamespace(id=payment_method_id, customer=customer)

    class PaymentIntent:
        created: list[dict] = []
        retrieve_map: dict[str, SimpleNamespace] = {}

        @classmethod
        def create(cls, **kwargs):
            cls.created.append(kwargs)
            intent_id = f"pi_{len(cls.created)}"
            intent = SimpleNamespace(
                id=intent_id,
                client_secret=f"{intent_id}_secret",
                status=kwargs.get("status", "requires_payment_method"),
                charges=SimpleNamespace(data=[]),
                metadata=kwargs.get("metadata", {}),
                payment_method=kwargs.get("payment_method"),
            )
            cls.retrieve_map[intent_id] = intent
            return intent

        @staticmethod
        def retrieve(intent_id):
            return StripeStub.PaymentIntent.retrieve_map.get(
                intent_id,
                SimpleNamespace(
                    id=intent_id,
                    status="requires_payment_method",
                    metadata={},
                    charges=SimpleNamespace(data=[]),
                ),
            )

        @staticmethod
        def confirm(intent_id, payment_method=None):
            return SimpleNamespace(
                id=intent_id,
                status="succeeded",
                charges=SimpleNamespace(data=[]),
                metadata={},
            )

    class SetupIntent:
        retrieve_map: dict[str, SimpleNamespace] = {}

        @classmethod
        def create(cls, **kwargs):
            intent_id = f"seti_{len(cls.retrieve_map) + 1}"
            intent = SimpleNamespace(
                id=intent_id,
                client_secret="seti_secret",
                payment_method="pm_new",
                status=kwargs.get("status", "requires_confirmation"),
                metadata=kwargs.get("metadata", {}),
                customer=kwargs.get("customer"),
            )
            cls.retrieve_map[intent_id] = intent
            return intent

        @staticmethod
        def retrieve(intent_id):
            return StripeStub.SetupIntent.retrieve_map.get(
                intent_id,
                SimpleNamespace(
                    id=intent_id,
                    status="requires_payment_method",
                    payment_method=None,
                    metadata={},
                ),
            )

    class Refund:
        @staticmethod
        def create(**kwargs):
            return SimpleNamespace(id="re_123")

    class Event:
        next_event = None

        @classmethod
        def construct_from(cls, payload, api_key):
            return cls.next_event

    class Webhook:
        @staticmethod
        def construct_event(payload, sig_header, secret):
            raise NotImplementedError

    http_client = SimpleNamespace(RequestsClient=lambda: None)
    api_key = None
    default_http_client = None

    @staticmethod
    def reset():
        StripeStub.PaymentIntent.created = []
        StripeStub.PaymentIntent.retrieve_map = {}
        StripeStub.SetupIntent.retrieve_map = {}


def install_stripe_stub(flask_app, monkeypatch, stub=None):
    stub = stub or StripeStub()
    stub.reset()
    monkeypatch.setattr(app_module, "stripe", stub, raising=False)
    monkeypatch.setattr(app_module, "StripeError", Exception, raising=False)
    monkeypatch.setattr(app_module, "SignatureVerificationError", Exception, raising=False)
    flask_app.config["STRIPE_SECRET_KEY"] = "sk_test"
    flask_app.config["STRIPE_PUBLISHABLE_KEY"] = "pk_test"
    return stub


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
    support_partner_folder = tmp_path / "support_partners"
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
            "SUPPORT_PARTNER_UPLOAD_FOLDER": str(support_partner_folder),
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


def login_technician(client, email: str, password: str, follow_redirects: bool = True):
    return client.post(
        "/tech/login",
        data={"email": email, "password": password},
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

        category_choices = get_install_photo_category_choices()
        photo_category = category_choices[0] if category_choices else "Additional Detail"
        photo = InstallPhoto(
            client_id=customer.id,
            technician_id=technician.id,
            category=photo_category,
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


def test_admin_can_create_support_partner_with_logo(app, client):
    login_admin(client)

    response = client.post(
        "/support-partners",
        data={
            "name": "River Region Fiber Crew",
            "website_url": "https://fibercrew.example.com",
            "description": "Handles aerial fiber runs for our backhaul.",
            "logo": (BytesIO(b"binary-image"), "logo.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Added River Region Fiber Crew to your operations allies." in response.data

    with app.app_context():
        partner = SupportPartner.query.filter_by(name="River Region Fiber Crew").first()
        assert partner is not None
        assert partner.website_url == "https://fibercrew.example.com"
        assert partner.description == "Handles aerial fiber runs for our backhaul."
        assert partner.logo_filename is not None
        partner_id = partner.id
        logo_path = Path(app.config["SUPPORT_PARTNER_UPLOAD_FOLDER"]) / partner.logo_filename
        assert logo_path.exists()

    logo_response = client.get(f"/support-partners/{partner_id}/logo")
    assert logo_response.status_code == 200
    assert b"binary-image" in logo_response.data


def test_dashboard_overview_lists_support_partners(app, client):
    with app.app_context():
        partner = SupportPartner(
            name="Tower Guard LLC",
            description="24/7 monitoring, tower climbs, and emergency repairs.",
            website_url="https://towerguard.example.com",
            position=1,
        )
        db.session.add(partner)
        db.session.commit()

    login_admin(client)

    response = client.get("/dashboard", follow_redirects=True)

    assert response.status_code == 200
    assert b"Operations Allies" in response.data
    assert b"Tower Guard LLC" in response.data
    assert b"24/7 monitoring, tower climbs, and emergency repairs." in response.data
    assert b"Manage partners" in response.data


def test_homepage_lists_support_partners(app, client):
    with app.app_context():
        partner = SupportPartner(
            name="Backhaul Brothers",
            description="Fiber construction crew keeping our backbone online.",
            website_url="https://backhaul.example.com",
            position=1,
        )
        db.session.add(partner)
        db.session.commit()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Operations allies" in response.data
    assert b"Backhaul Brothers" in response.data
    assert b"Fiber construction crew keeping our backbone online." in response.data
    assert b"Visit site" in response.data


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


def test_admin_can_save_stripe_configuration(app, client):
    login_admin(client)

    response = client.post(
        "/dashboard/security/stripe",
        data={
            "secret_key": "sk_live_configured",
            "publishable_key": "pk_live_configured",
            "webhook_secret": "whsec_configured",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Stripe configuration saved." in response.data

    with app.app_context():
        config = StripeConfig.query.first()
        assert config is not None
        assert config.secret_key == "sk_live_configured"
        assert config.publishable_key == "pk_live_configured"
        assert config.webhook_secret == "whsec_configured"
        assert app.config["STRIPE_SECRET_KEY"] == "sk_live_configured"
        assert app.config["STRIPE_PUBLISHABLE_KEY"] == "pk_live_configured"
        assert app.config["STRIPE_WEBHOOK_SECRET"] == "whsec_configured"


def test_admin_can_disable_stripe_configuration(app, client):
    login_admin(client)

    client.post(
        "/dashboard/security/stripe",
        data={
            "secret_key": "sk_live_enabled",
            "publishable_key": "pk_live_enabled",
            "webhook_secret": "whsec_enabled",
        },
        follow_redirects=True,
    )

    response = client.post(
        "/dashboard/security/stripe",
        data={
            "secret_key": "",
            "publishable_key": "",
            "webhook_secret": "",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Provide both API keys" in response.data

    with app.app_context():
        config = StripeConfig.query.first()
        assert config is not None
        assert config.secret_key is None
        assert config.publishable_key is None
        assert config.webhook_secret is None
        assert app.config["STRIPE_SECRET_KEY"] is None
        assert app.config["STRIPE_PUBLISHABLE_KEY"] is None
        assert app.config["STRIPE_WEBHOOK_SECRET"] is None


def test_get_stripe_publishable_key_uses_env_alias(app):
    with app.app_context():
        StripeConfig.query.delete()
        db.session.commit()

        app.config["STRIPE_PUBLISHABLE_KEY"] = None
        app.config["STRIPE_PUBLIC_KEY"] = "pk_alias_env"
        app.config["STRIPE_PK"] = None

        value = get_stripe_publishable_key(app)

        assert value == "pk_alias_env"
        assert app.config["STRIPE_PUBLISHABLE_KEY"] == "pk_alias_env"


def test_get_stripe_publishable_key_reads_database_when_missing(app):
    with app.app_context():
        StripeConfig.query.delete()
        db.session.commit()

        config = StripeConfig(
            secret_key="sk_saved",
            publishable_key="pk_saved",
            webhook_secret=None,
        )
        db.session.add(config)
        db.session.commit()

        app.config["STRIPE_PUBLISHABLE_KEY"] = None
        app.config["STRIPE_PUBLIC_KEY"] = None
        app.config["STRIPE_PK"] = None

        value = get_stripe_publishable_key(app)

        assert value == "pk_saved"
        assert app.config["STRIPE_PUBLISHABLE_KEY"] == "pk_saved"


def test_apply_stripe_config_uses_publishable_fallback(app):
    with app.app_context():
        StripeConfig.query.delete()
        db.session.commit()

        app.config["STRIPE_SECRET_KEY"] = "sk_env"
        app.config["STRIPE_PUBLISHABLE_KEY"] = None
        app.config["STRIPE_PUBLIC_KEY"] = "pk_env_public"
        app.config["STRIPE_PK"] = None

        config = apply_stripe_config_from_database(app)

        assert config.publishable_key == "pk_env_public"
        assert app.config["STRIPE_PUBLISHABLE_KEY"] == "pk_env_public"

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
    with app.app_context():
        categories = get_required_install_photo_categories()
    assert categories
    assert escape(categories[0]).encode() in response.data
    if len(categories) > 1:
        assert escape(categories[1]).encode() in response.data


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


def test_admin_manages_install_photo_requirements(app, client):
    login_admin(client)

    response = client.post(
        "/install-photo-requirements",
        data={"label": "Roof Anchor Detail", "position": "0"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        requirement = InstallPhotoRequirement.query.filter_by(
            label="Roof Anchor Detail"
        ).first()
        assert requirement is not None
        assert requirement.position == 0
        total = InstallPhotoRequirement.query.count()

    response = client.post(
        f"/install-photo-requirements/{requirement.id}/update",
        data={"label": "Roof Anchor Photo", "position": "5"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        updated = InstallPhotoRequirement.query.get(requirement.id)
        assert updated is not None
        assert updated.label == "Roof Anchor Photo"
        expected_position = min(5, total - 1)
        assert updated.position == expected_position

    response = client.post(
        f"/install-photo-requirements/{requirement.id}/delete",
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        assert (
            InstallPhotoRequirement.query.filter_by(id=requirement.id).first()
            is None
        )


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


def test_autopay_run_submits_payment_intents(app, client, monkeypatch):
    install_stripe_stub(app, monkeypatch)
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
            token="pm_success",
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
        assert invoice.status == "Pending"
        assert invoice.autopay_status == "Processing"
        assert invoice.stripe_payment_intent_id is not None
        assert invoice.paid_at is None
        customer = Client.query.get(customer_id)
        assert customer.billing_status in {"Good Standing", "Pending"}
        events = AutopayEvent.query.filter_by(client_id=customer_id).all()
        assert len(events) == 1
        assert events[0].status == "pending"


def test_autopay_run_defers_until_scheduled_day(app, client, monkeypatch):
    install_stripe_stub(app, monkeypatch)
    login_admin(client)

    today_day = date.today().day
    scheduled_day = today_day + 1 if today_day < 28 else 1

    with app.app_context():
        customer = Client(
            name="Autopay Scheduled",
            email="scheduled@example.com",
            status="Active",
            autopay_enabled=True,
            autopay_day=scheduled_day,
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
            token="pm_success",
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
        invoice_id = invoice.id

    response = client.post("/autopay/run", follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        invoice = Invoice.query.get(invoice_id)
        assert invoice.autopay_status is None
        events = AutopayEvent.query.filter_by(client_id=customer_id).all()
        assert events
        assert events[0].status == "scheduled"
        assert str(scheduled_day) in (events[0].message or "")


def test_autopay_run_suspends_when_no_method(app, client, monkeypatch):
    install_stripe_stub(app, monkeypatch)
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


def test_autopay_schedule_request_and_approval(app, client, monkeypatch):
    sent_notifications: list[tuple[str, str, str]] = []

    def fake_send_email(app_obj, recipient, subject, body):
        sent_notifications.append((recipient, subject, body))
        return True

    monkeypatch.setattr(app_module, "send_email_via_office365", fake_send_email)

    password = "PortalPass123!"
    app.config["ADMIN_EMAIL"] = "billing@example.com"

    with app.app_context():
        customer = Client(
            name="Schedule Customer",
            email="schedule@example.com",
            status="Active",
            autopay_enabled=True,
        )
        customer.portal_password_hash = generate_password_hash(password)
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    login_response = client.post(
        "/portal/login",
        data={"email": "schedule@example.com", "password": password},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    request_response = client.post(
        "/portal/autopay/schedule",
        data={"requested_day": "15"},
        follow_redirects=True,
    )
    assert request_response.status_code == 200

    with app.app_context():
        customer = Client.query.get(customer_id)
        assert customer.autopay_day_pending == 15
        assert customer.autopay_day is None

    assert any(
        recipient == "billing@example.com" and "Autopay schedule request" in subject
        for recipient, subject, _ in sent_notifications
    )

    login_admin(client)

    approve_response = client.post(
        f"/clients/{customer_id}/autopay/schedule",
        data={"action": "approve"},
        follow_redirects=True,
    )
    assert approve_response.status_code == 200

    with app.app_context():
        customer = Client.query.get(customer_id)
        assert customer.autopay_day == 15
        assert customer.autopay_day_pending is None

    assert any(
        recipient == "schedule@example.com" and "Autopay schedule approved" in subject
        for recipient, subject, _ in sent_notifications
    )


def test_stripe_webhook_marks_invoice_paid(app, client, monkeypatch):
    stub = install_stripe_stub(app, monkeypatch)

    with app.app_context():
        customer = Client(
            name="Webhook Client",
            email="webhook@example.com",
            status="Active",
            autopay_enabled=True,
        )
        db.session.add(customer)
        db.session.commit()

        method = PaymentMethod(
            client_id=customer.id,
            nickname="Autopay",
            brand="Visa",
            last4="4242",
            exp_month=1,
            exp_year=date.today().year + 2,
            token="pm_webhook",
            is_default=True,
        )
        invoice = Invoice(
            client_id=customer.id,
            description="Monthly service",
            amount_cents=7500,
            status="Pending",
            due_date=date.today(),
            autopay_status="Processing",
            stripe_payment_intent_id="pi_webhook",
        )
        db.session.add_all([method, invoice])
        db.session.commit()
        invoice_id = invoice.id

    event_payload = SimpleNamespace(
        type="payment_intent.succeeded",
        id="evt_1",
        data=SimpleNamespace(
            object=SimpleNamespace(
                id="pi_webhook",
                metadata={
                    "invoice_id": str(invoice_id),
                    "autopay": "true",
                },
                payment_method="pm_webhook",
                charges=SimpleNamespace(data=[SimpleNamespace(id="ch_123")]),
            )
        ),
    )
    stub.Event.next_event = event_payload

    response = client.post(
        "/stripe/webhook",
        data="{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200

    with app.app_context():
        invoice = Invoice.query.get(invoice_id)
        assert invoice.status == "Paid"
        assert invoice.autopay_status == "Paid"
        assert invoice.paid_via.startswith("Stripe")
        assert invoice.stripe_charge_id == "ch_123"
        events = AutopayEvent.query.filter_by(client_id=invoice.client_id).all()
        assert events
        assert events[0].status == "success"


def test_admin_can_refund_paid_invoice(app, client, monkeypatch):
    install_stripe_stub(app, monkeypatch)
    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Refund Client",
            email="refund@example.com",
            status="Active",
        )
        db.session.add(customer)
        db.session.commit()

        customer_id = customer.id

        invoice = Invoice(
            client_id=customer.id,
            description="Service",
            amount_cents=3000,
            status="Paid",
            paid_at=utcnow(),
            paid_via="Stripe",
            autopay_status="Paid",
            stripe_payment_intent_id="pi_refund",
            stripe_charge_id="ch_refund",
        )
        db.session.add(invoice)
        db.session.commit()
        invoice_id = invoice.id

    response = client.post(
        f"/invoices/{invoice_id}/refund",
        data={"next": f"/dashboard/customers/{customer_id}"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Refund initiated" in response.data

    with app.app_context():
        invoice = Invoice.query.get(invoice_id)
        assert invoice.status == "Refunded"
        assert invoice.autopay_status == "Refunded"
        events = AutopayEvent.query.filter_by(invoice_id=invoice_id).all()
        assert events
        assert any(event.status == "refunded" for event in events)


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


def test_admin_syncs_uisp_devices_and_assigns_to_customer(app, client, monkeypatch):
    login_admin(client)

    sent_notifications: list[tuple[str, str, str]] = []

    def fake_send_email(app_obj, recipient, subject, body):
        sent_notifications.append((recipient, subject, body))
        return True

    monkeypatch.setattr(app_module, "send_email_via_office365", fake_send_email)

    payload_pages = [
        {
            "items": [
                {
                    "id": "device-1",
                    "identification": {"name": "North Sector", "model": "UISP Wave"},
                    "site": {"name": "North Tower"},
                    "status": {"value": "online", "lastSeen": "2024-05-01T12:00:00Z"},
                    "ipAddress": "10.0.0.10",
                    "macAddress": "AA:BB:CC:DD:EE:01",
                    "firmware": {"version": "1.2.3"},
                }
            ],
            "_links": {"next": "/nms/api/v2.1/devices?page=2"},
            "pagination": {"page": 1, "perPage": 200, "totalPages": 2},
        },
        {
            "data": [
                {
                    "id": "device-2",
                    "identification": {"name": "Backhaul Link", "model": "UISP Wave"},
                    "site": {"name": "Backhaul Ridge"},
                    "status": {"value": "offline", "lastSeen": "2024-05-01T11:45:00Z"},
                    "ipAddress": "10.0.0.11",
                    "macAddress": "AA:BB:CC:DD:EE:02",
                    "firmware": {"version": "1.2.3"},
                }
            ],
            "pagination": {"page": 2, "perPage": 200, "totalPages": 2},
        },
    ]

    class DummyResponse:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

        @property
        def text(self):
            return "ok"

    def fake_get(url, headers=None, params=None, timeout=None):
        request_page = 1
        if params and "page" in params:
            try:
                request_page = int(params["page"])
            except (TypeError, ValueError):
                request_page = 1
        elif "page=2" in url:
            request_page = 2

        index = max(1, request_page) - 1
        index = min(index, len(payload_pages) - 1)
        return DummyResponse(payload_pages[index])

    monkeypatch.setattr(app_module.requests, "get", fake_get)

    with app.app_context():
        config = UispConfig(base_url="https://uisp.example.com", api_token="token")
        north_tower = NetworkTower(name="North Tower", location="Hilltop bluff")
        lake_tower = NetworkTower(name="Lake Tower", location="Reservoir access road")
        customer = Client(name="Managed Customer", email="managed@example.com", status="Active")
        db.session.add_all([config, north_tower, lake_tower, customer])
        technician = Technician(
            name="Network Tech",
            email="tech@example.com",
            password_hash=generate_password_hash("TechPass123!"),
            is_active=True,
        )
        db.session.add(technician)
        db.session.commit()
        customer_id = customer.id
        north_tower_id = north_tower.id
        lake_tower_id = lake_tower.id

    response = client.post("/uisp/devices/import", follow_redirects=True)
    assert response.status_code == 200
    assert sent_notifications

    with app.app_context():
        config = UispConfig.query.first()
        assert config is not None
        assert config.last_synced_at is not None
        devices = UispDevice.query.order_by(UispDevice.uisp_id.asc()).all()
        assert len(devices) == 2
        online_device = next(device for device in devices if device.uisp_id == "device-1")
        assert online_device.tower_id == north_tower_id
        offline_device = next(device for device in devices if device.uisp_id == "device-2")
        assert offline_device.status == "offline"
        assert offline_device.outage_notified_at is not None
        offline_id = offline_device.id

    recipients = {entry[0] for entry in sent_notifications}
    assert "ops@example.com" in recipients
    assert "tech@example.com" in recipients

    sent_notifications.clear()

    account_url = f"/dashboard/customers/{customer_id}"
    assign_response = client.post(
        f"/uisp/devices/{offline_id}/assign",
        data={
            "client_id": str(customer_id),
            "nickname": "Backhaul",
            "notes": "Feeds subdivision",
            "tower_id": str(lake_tower_id),
            "next": account_url,
        },
        follow_redirects=True,
    )
    assert assign_response.status_code == 200

    with app.app_context():
        device = UispDevice.query.get(offline_id)
        assert device.client_id == customer_id
        assert device.nickname == "Backhaul"
        assert device.notes == "Feeds subdivision"
        assert device.tower_id == lake_tower_id

    payload_pages[1]["data"][0]["status"] = {
        "value": "online",
        "lastSeen": "2024-05-01T12:30:00Z",
    }
    client.post("/uisp/devices/import", follow_redirects=True)
    assert not sent_notifications

    payload_pages[1]["data"][0]["status"] = {
        "value": "offline",
        "lastSeen": "2024-05-01T12:45:00Z",
    }
    sent_notifications.clear()
    client.post("/uisp/devices/import", follow_redirects=True)

    recipients = {entry[0] for entry in sent_notifications}
    assert "managed@example.com" in recipients
    assert "ops@example.com" in recipients
    assert "tech@example.com" in recipients

    account_view = client.get(account_url)
    assert account_view.status_code == 200
    assert b"Backhaul" in account_view.data
    assert b"Lake Tower" in account_view.data

    unassign_response = client.post(
        f"/uisp/devices/{offline_id}/assign",
        data={"client_id": "", "tower_id": "", "next": account_url},
        follow_redirects=True,
    )
    assert unassign_response.status_code == 200

    with app.app_context():
        device = UispDevice.query.get(offline_id)
        assert device.client_id is None
        assert device.tower_id is None


def test_admin_manages_uisp_settings_and_towers(app, client):
    login_admin(client)

    settings_response = client.post(
        "/uisp/config",
        data={
            "base_url": "https://uisp.ops",
            "api_token": "secret-token",
            "auto_sync_enabled": "on",
            "auto_sync_interval": "90",
        },
        follow_redirects=True,
    )
    assert settings_response.status_code == 200

    create_response = client.post(
        "/network/towers",
        data={
            "name": "River Tower",
            "location": "Bayou Road",
            "notes": "Primary uplink",
        },
        follow_redirects=True,
    )
    assert create_response.status_code == 200

    with app.app_context():
        config = UispConfig.query.first()
        assert config is not None
        assert config.base_url == "https://uisp.ops"
        assert config.api_token == "secret-token"
        assert config.auto_sync_enabled is True
        assert config.auto_sync_interval_minutes == 90

        tower = NetworkTower.query.filter_by(name="River Tower").first()
        assert tower is not None
        tower_id = tower.id

        device = UispDevice(uisp_id="tower-test", name="Tower Device", tower=tower)
        db.session.add(device)
        db.session.commit()
        device_id = device.id

    update_response = client.post(
        f"/network/towers/{tower_id}/update",
        data={
            "name": "Riverfront Tower",
            "location": "Bayou Road",
            "notes": "Updated notes",
        },
        follow_redirects=True,
    )
    assert update_response.status_code == 200

    with app.app_context():
        tower = NetworkTower.query.get(tower_id)
        assert tower is not None
        assert tower.name == "Riverfront Tower"
        assert tower.notes == "Updated notes"

    delete_response = client.post(
        f"/network/towers/{tower_id}/delete",
        follow_redirects=True,
    )
    assert delete_response.status_code == 200

    with app.app_context():
        assert NetworkTower.query.get(tower_id) is None
        device = UispDevice.query.get(device_id)
        assert device is not None
        assert device.tower_id is None


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


def test_technician_manages_schedule_and_views_jobs(app, client):
    with app.app_context():
        technician = Technician(
            name="Schedule Tech",
            email="schedule-tech@example.com",
            password_hash=generate_password_hash("TechSchedule123!"),
            is_active=True,
        )
        db.session.add(technician)
        db.session.commit()
        technician_id = technician.id

        now = utcnow()
        today_client = Client(
            name="Today Client",
            email="today-client@example.com",
            status="Active",
        )
        future_client = Client(
            name="Future Client",
            email="future-client@example.com",
            status="Active",
        )
        past_client = Client(
            name="Past Client",
            email="past-client@example.com",
            status="Active",
        )
        db.session.add_all([today_client, future_client, past_client])
        db.session.commit()

        today_time = now.replace(hour=10, minute=0, second=0, microsecond=0)
        future_time = now + timedelta(days=2)
        past_time = now - timedelta(days=2)

        appointments = [
            Appointment(
                client_id=today_client.id,
                technician_id=technician_id,
                title="Install gateway",
                scheduled_for=today_time,
            ),
            Appointment(
                client_id=future_client.id,
                technician_id=technician_id,
                title="Tower inspection",
                scheduled_for=future_time,
            ),
            Appointment(
                client_id=past_client.id,
                technician_id=technician_id,
                title="Service follow-up",
                scheduled_for=past_time,
            ),
        ]
        db.session.add_all(appointments)
        db.session.commit()

    login_response = login_technician(
        client,
        email="schedule-tech@example.com",
        password="TechSchedule123!",
    )
    assert login_response.status_code == 200
    assert b"Calendar overview" in login_response.data
    assert b"Current jobs" in login_response.data
    assert b"Upcoming jobs" in login_response.data
    assert b"Completed jobs" in login_response.data
    assert b"Today Client" in login_response.data
    assert b"Future Client" in login_response.data
    assert b"Past Client" in login_response.data

    schedule_date = (utcnow() + timedelta(days=3)).date().isoformat()
    schedule_response = client.post(
        "/tech/schedule",
        data={
            "date": schedule_date,
            "start_time": "09:00",
            "end_time": "17:00",
            "note": "Warehouse coverage",
        },
        follow_redirects=True,
    )
    assert schedule_response.status_code == 200
    assert b"Shift submitted for manager approval" in schedule_response.data
    assert b"Requests awaiting approval" in schedule_response.data
    assert b"Warehouse coverage" in schedule_response.data

    with app.app_context():
        schedule_blocks = TechnicianSchedule.query.filter_by(
            technician_id=technician_id
        ).all()
        assert len(schedule_blocks) == 1
        block = schedule_blocks[0]
        assert block.end_at > block.start_at
        assert block.note == "Warehouse coverage"
        assert block.status == "pending"
        block_id = block.id

    client.get("/tech/logout", follow_redirects=True)
    login_admin(client)

    field_page = client.get("/dashboard?section=field")
    assert field_page.status_code == 200
    assert b"Technician schedule approvals" in field_page.data
    assert b"New availability" in field_page.data

    approve_response = client.post(
        f"/dashboard/field/schedule/{block_id}/approve",
        data={"next": "/dashboard?section=field", "note": "Approved"},
        follow_redirects=True,
    )
    assert approve_response.status_code == 200
    assert b"shift was removed" not in approve_response.data
    assert b"shift approved" in approve_response.data or b"Shift on" in approve_response.data

    with app.app_context():
        block = TechnicianSchedule.query.get(block_id)
        assert block is not None
        assert block.status == "approved"
        assert block.review_note == "Approved"

    client.get("/logout", follow_redirects=True)
    login_response = login_technician(
        client,
        email="schedule-tech@example.com",
        password="TechSchedule123!",
    )
    assert login_response.status_code == 200
    assert b"Approved shift" in login_response.data
    assert b"Request cancellation" in login_response.data

    cancel_request = client.post(
        f"/tech/schedule/{block_id}/delete",
        follow_redirects=True,
    )
    assert cancel_request.status_code == 200
    assert b"Cancellation request sent" in cancel_request.data

    with app.app_context():
        block = TechnicianSchedule.query.get(block_id)
        assert block.status == "cancel_pending"
        assert block.cancel_requested_at is not None

    client.get("/tech/logout", follow_redirects=True)
    login_admin(client)

    cancel_approve = client.post(
        f"/dashboard/field/schedule/{block_id}/approve",
        data={"next": "/dashboard?section=field"},
        follow_redirects=True,
    )
    assert cancel_approve.status_code == 200
    assert b"Cancellation approved" in cancel_approve.data

    with app.app_context():
        block = TechnicianSchedule.query.get(block_id)
        assert block is not None
        assert block.status == "cancelled"


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


def test_document_upload_blocked_when_surface_disabled(app, client):
    login_admin(client)

    app.config["ALLOWED_FILE_TRANSFER_SURFACES"] = {
        surface
        for surface in app.config["ALLOWED_FILE_TRANSFER_SURFACES"]
        if surface != "legal-documents"
    }

    response = client.post(
        "/documents/upload",
        data={
            "doc_type": "aup",
            "document": (BytesIO(b"policy"), "aup.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 403


def test_document_download_blocked_when_surface_disabled(app, client):
    login_admin(client)

    with app.app_context():
        upload_folder = Path(app.config["LEGAL_UPLOAD_FOLDER"])
        upload_folder.mkdir(parents=True, exist_ok=True)
        stored_filename = "aup.pdf"
        (upload_folder / stored_filename).write_bytes(b"policy")
        document = Document(
            doc_type="aup",
            original_filename="aup.pdf",
            stored_filename=stored_filename,
        )
        db.session.add(document)
        db.session.commit()

    app.config["ALLOWED_FILE_TRANSFER_SURFACES"] = {
        surface
        for surface in app.config["ALLOWED_FILE_TRANSFER_SURFACES"]
        if surface != "legal-documents"
    }

    response = client.get("/documents/aup")
    assert response.status_code == 403


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


def test_portal_customer_adds_card_via_stripe(app, client, monkeypatch):
    password = "PortalPass123!"
    install_stripe_stub(app, monkeypatch)

    with app.app_context():
        portal_client = Client(
            name="Portal Cardholder",
            email="cardholder@example.com",
            status="Active",
        )
        portal_client.portal_password_hash = generate_password_hash(password)
        portal_client.portal_password_updated_at = utcnow()
        db.session.add(portal_client)
        db.session.commit()
        portal_client_id = portal_client.id

    login_response = client.post(
        "/portal/login",
        data={"email": "cardholder@example.com", "password": password},
        follow_redirects=True,
    )
    assert login_response.status_code == 200
    assert b"Saved cards" in login_response.data

    setup_response = client.get("/portal/payment-methods/setup-intent")
    assert setup_response.status_code == 200
    setup_payload = setup_response.get_json()
    assert setup_payload["client_secret"] == "seti_secret"

    save_response = client.post(
        "/portal/payment-methods",
        json={"payment_method_id": "pm_new", "set_default": True},
    )
    assert save_response.status_code == 200
    result = save_response.get_json()
    assert result["status"] == "ok"

    with app.app_context():
        stored_method = PaymentMethod.query.filter_by(
            client_id=portal_client_id
        ).one()
        assert stored_method.brand == "Visa"
        assert stored_method.last4 == "4242"
        assert stored_method.cardholder_name == "Test User"
        assert stored_method.is_default is True
        assert stored_method.token == "pm_new"
        refreshed_client = Client.query.get(portal_client_id)
        assert refreshed_client.stripe_customer_id == "cus_test"


def test_ticket_messaging_allows_replies_with_attachments(app, client, monkeypatch):
    sent_notifications: list[tuple[str, str, str]] = []

    def fake_send_email(app_obj, recipient, subject, body):
        sent_notifications.append((recipient, subject, body))
        return True

    monkeypatch.setattr(app_module, "send_email_via_office365", fake_send_email)

    app.config["ADMIN_EMAIL"] = "support@example.com"
    password = "PortalPass123!"

    with app.app_context():
        portal_client = Client(
            name="Messaging Customer",
            email="messaging@example.com",
            status="Active",
        )
        portal_client.portal_password_hash = generate_password_hash(password)
        db.session.add(portal_client)
        db.session.commit()
        client_id = portal_client.id

    client.post(
        "/portal/login",
        data={"email": "messaging@example.com", "password": password},
        follow_redirects=True,
    )

    client.post(
        "/portal/tickets",
        data={
            "subject": "Connectivity issue",
            "message": "Our radios reboot each night.",
            "priority": "High",
            "attachments": (BytesIO(b"initial"), "signal.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        ticket = SupportTicket.query.filter_by(client_id=client_id).one()
        assert ticket.messages
        assert ticket.messages[0].body == "Our radios reboot each night."
        attachments = SupportTicketAttachment.query.filter_by(ticket_id=ticket.id).all()
        assert attachments[0].message_id == ticket.messages[0].id
        ticket_id = ticket.id

    client.post(
        f"/portal/tickets/{ticket_id}/messages",
        data={
            "message": "Here are additional logs.",
            "attachments": (BytesIO(b"log-data"), "logs.txt"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    login_admin(client)

    client.post(
        f"/tickets/{ticket_id}/messages",
        data={
            "message": "We pushed a firmware update.",
            "attachments": (BytesIO(b"patch-notes"), "notes.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        ticket = SupportTicket.query.get(ticket_id)
        assert len(ticket.messages) == 3
        assert ticket.messages[1].sender == "client"
        assert ticket.messages[2].sender == "admin"
        admin_attachment = next(
            attachment
            for attachment in ticket.attachments
            if attachment.original_filename == "notes.pdf"
        )
        assert admin_attachment.message_id == ticket.messages[2].id

    assert any(
        recipient == "support@example.com" and "ticket" in subject.lower()
        for recipient, subject, _ in sent_notifications
    )
    assert any(
        recipient == "messaging@example.com" and "Support ticket update" in subject
        for recipient, subject, _ in sent_notifications
    )


def test_portal_dashboard_processes_setup_intent_query(app, client, monkeypatch):
    password = "PortalPass123!"
    stub = install_stripe_stub(app, monkeypatch)

    with app.app_context():
        portal_client = Client(
            name="Setup Intent Customer",
            email="setup@example.com",
            status="Active",
        )
        portal_client.portal_password_hash = generate_password_hash(password)
        portal_client.portal_password_updated_at = utcnow()
        db.session.add(portal_client)
        db.session.commit()
        portal_client_id = portal_client.id

    login_response = client.post(
        "/portal/login",
        data={"email": "setup@example.com", "password": password},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    stub.SetupIntent.retrieve_map["seti_success"] = SimpleNamespace(
        id="seti_success",
        status="succeeded",
        payment_method="pm_new",
        metadata={"client_id": str(portal_client_id)},
        customer="cus_test",
    )

    response = client.get(
        "/portal?setup_intent=seti_success",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Card saved" in response.data

    with app.app_context():
        stored_method = PaymentMethod.query.filter_by(
            client_id=portal_client_id
        ).one()
        assert stored_method.token == "pm_new"
        assert stored_method.is_default is True


def test_portal_dashboard_processes_payment_intent_query(app, client, monkeypatch):
    password = "PortalPass123!"
    stub = install_stripe_stub(app, monkeypatch)

    with app.app_context():
        portal_client = Client(
            name="Invoice Payer",
            email="payer@example.com",
            status="Active",
        )
        portal_client.portal_password_hash = generate_password_hash(password)
        portal_client.portal_password_updated_at = utcnow()
        db.session.add(portal_client)
        db.session.commit()
        portal_client_id = portal_client.id

        invoice = Invoice(
            client_id=portal_client_id,
            description="Monthly service",
            amount_cents=6500,
            status="Pending",
        )
        db.session.add(invoice)
        db.session.commit()
        invoice_id = invoice.id

    login_response = client.post(
        "/portal/login",
        data={"email": "payer@example.com", "password": password},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    stub.PaymentIntent.retrieve_map["pi_success"] = SimpleNamespace(
        id="pi_success",
        status="succeeded",
        metadata={
            "invoice_id": str(invoice_id),
            "client_id": str(portal_client_id),
            app_module.STRIPE_AUTOPAY_METADATA_FLAG: "false",
        },
        payment_method="pm_card_visa",
        charges=SimpleNamespace(data=[SimpleNamespace(id="ch_123")]),
    )

    response = client.get(
        "/portal?payment_intent=pi_success",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Payment received. Thank you!" in response.data

    with app.app_context():
        refreshed_invoice = Invoice.query.get(invoice_id)
        assert refreshed_invoice.status == "Paid"
        assert refreshed_invoice.stripe_payment_intent_id == "pi_success"


def test_admin_adds_card_via_stripe(app, client, monkeypatch):
    install_stripe_stub(app, monkeypatch)
    login_admin(client)

    with app.app_context():
        account = Client(
            name="Admin Managed Account",
            email="managed@example.com",
            status="Active",
        )
        db.session.add(account)
        db.session.commit()
        account_id = account.id

    setup_response = client.get(
        f"/clients/{account_id}/payment-methods/setup-intent"
    )
    assert setup_response.status_code == 200
    setup_payload = setup_response.get_json()
    assert setup_payload["client_secret"] == "seti_secret"

    save_response = client.post(
        f"/clients/{account_id}/payment-methods",
        json={"payment_method_id": "pm_new", "set_default": True},
    )
    assert save_response.status_code == 200
    result = save_response.get_json()
    assert result["status"] == "ok"

    with app.app_context():
        stored_method = PaymentMethod.query.filter_by(client_id=account_id).one()
        assert stored_method.is_default is True
        assert stored_method.brand == "Visa"
        assert stored_method.last4 == "4242"
        assert stored_method.cardholder_name == "Test User"
        refreshed = Client.query.get(account_id)
        assert refreshed.stripe_customer_id == "cus_test"


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
    assert b"Notification email queued for delivery." in response.data
    assert notifications == [
        ("alert@example.com", "Maintenance window", "Expect brief downtime at midnight."),
    ]


def test_invoice_notifications_sent_on_create_and_update(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Billing Notice",
            email="billing@example.com",
            status="Active",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    response = client.post(
        f"/clients/{customer_id}/invoices",
        data={
            "description": "Installation deposit",
            "amount": "150.00",
            "due_date": "2024-02-01",
            "status": "Pending",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert notifications
    recipient, subject, body = notifications[-1]
    assert recipient == "billing@example.com"
    assert subject.startswith("Invoice posted: Installation deposit")
    assert "new invoice" in body.lower()
    assert "$150.00" in body
    assert "Due date: 2024-02-01" in body

    with app.app_context():
        invoice = Invoice.query.filter_by(client_id=customer_id).one()
        invoice_id = invoice.id

    notifications.clear()

    response = client.post(
        f"/invoices/{invoice_id}/update",
        data={
            "description": "Installation deposit",
            "amount": "175.00",
            "due_date": "2024-02-15",
            "status": "Pending",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert notifications
    recipient, subject, body = notifications[-1]
    assert recipient == "billing@example.com"
    assert subject.startswith("Invoice updated: Installation deposit")
    assert "updated your invoice" in body
    assert "$175.00" in body
    assert "Due date: 2024-02-15" in body


def test_equipment_notifications_sent_on_create_and_update(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    login_admin(client)

    with app.app_context():
        customer = Client(
            name="Equipment Notice",
            email="gear@example.com",
            status="Active",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    response = client.post(
        f"/clients/{customer_id}/equipment",
        data={
            "name": "Customer Router",
            "model": "XR500",
            "serial_number": "SN-100",
            "notes": "Initial install",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert notifications
    recipient, subject, body = notifications[-1]
    assert recipient == "gear@example.com"
    assert subject.startswith("Equipment added: Customer Router")
    assert "new equipment" in body.lower()
    assert "Customer Router" in body

    with app.app_context():
        equipment = Equipment.query.filter_by(client_id=customer_id).one()
        equipment_id = equipment.id

    notifications.clear()

    response = client.post(
        f"/equipment/{equipment_id}/update",
        data={
            "name": "Customer Router",
            "model": "XR500",
            "serial_number": "SN-100",
            "installed_on": date(2024, 1, 15).strftime("%Y-%m-%d"),
            "notes": "Mounted in hallway",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert notifications
    recipient, subject, body = notifications[-1]
    assert recipient == "gear@example.com"
    assert subject.startswith("Equipment updated: Customer Router")
    assert "mounted in hallway" in body.lower()
    assert "Installed on: 2024-01-15" in body


def test_appointment_update_uses_all_activity_flag(app, client):
    notifications: list[tuple[str, str, str]] = []
    app.config["SNMP_EMAIL_SENDER"] = lambda recipient, subject, body: notifications.append(
        (recipient, subject, body)
    ) or True

    login_admin(client)

    with app.app_context():
        config = app_module.ensure_notification_configuration()
        config.notify_customer_activity = False
        config.notify_all_account_activity = True
        db.session.commit()

        customer = Client(
            name="All Activity Customer",
            email="notify-all@example.com",
            status="Active",
        )
        appointment = Appointment(
            client=customer,
            title="Follow-up visit",
            scheduled_for=utcnow() + timedelta(days=1),
            status="Pending",
        )
        db.session.add_all([customer, appointment])
        db.session.commit()
        appointment_id = appointment.id

    response = client.post(
        f"/appointments/{appointment_id}/update",
        data={"status": "Completed"},
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        updated = Appointment.query.get(appointment_id)
        assert updated.status == "Completed"

    assert notifications, "Expected an appointment notification when all-activity flag is enabled"
    recipient, subject, body = notifications[-1]
    assert recipient == "notify-all@example.com"
    assert subject.startswith("Appointment update: Follow-up visit")
    assert "completed" in body.lower()


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


def test_admin_can_configure_office365_notifications(app, client):
    login_admin(client)

    response = client.post(
        "/dashboard/notifications/office365",
        data={
            "from_name": "DixieLand Wireless",
            "from_email": "info@dixielandwireless.com",
            "reply_to_name": "Customer Success",
            "reply_to_email": "support@dixielandwireless.com",
            "smtp_host": "smtp.office365.com",
            "smtp_port": "587",
            "smtp_username": "alerts@dixielandwireless.com",
            "smtp_password": "SuperSecret!",
            "use_tls": "on",
            "tenant_id": "tenant-123",
            "client_id": "client-abc",
            "client_secret": "graph-secret",
            "list_unsubscribe_url": "https://dixielandwireless.com/unsubscribe",
            "list_unsubscribe_mailto": "mailto:unsubscribe@dixielandwireless.com",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Office 365 email settings saved" in response.data

    with app.app_context():
        config = NotificationConfig.query.first()
        assert config is not None
        assert config.from_email == "info@dixielandwireless.com"
        assert config.from_name == "DixieLand Wireless"
        assert config.smtp_host == "smtp.office365.com"
        assert config.smtp_port == 587
        assert config.smtp_username == "alerts@dixielandwireless.com"
        assert config.smtp_password == "SuperSecret!"
        assert config.use_tls is True
        assert config.tenant_id == "tenant-123"
        assert config.client_id == "client-abc"
        assert config.client_secret == "graph-secret"
        assert config.reply_to_name == "Customer Success"
        assert config.reply_to_email == "support@dixielandwireless.com"
        assert config.list_unsubscribe_url == "https://dixielandwireless.com/unsubscribe"
        assert config.list_unsubscribe_mailto == "unsubscribe@dixielandwireless.com"
        assert config.office365_ready() is True


def test_office365_password_retained_when_blank(app, client):
    with app.app_context():
        config = app_module.ensure_notification_configuration()
        config.smtp_username = "ops@dixielandwireless.com"
        config.smtp_password = "keep-me"
        config.from_email = "ops@dixielandwireless.com"
        config.use_tls = True
        db.session.commit()

    login_admin(client)

    response = client.post(
        "/dashboard/notifications/office365",
        data={
            "from_email": "ops@dixielandwireless.com",
            "smtp_host": "smtp.office365.com",
            "smtp_port": "2525",
            "smtp_username": "ops@dixielandwireless.com",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        config = NotificationConfig.query.first()
        assert config.smtp_port == 2525
        assert config.smtp_password == "keep-me"


def test_office365_email_includes_deliverability_headers(app, monkeypatch):
    sent_messages = []

    class DummySMTP:
        def __init__(self, host, port, timeout=10):
            self.host = host
            self.port = port
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, username, password):
            assert username == "alerts@dixielandwireless.com"
            assert password == "keep-me"

        def send_message(self, message):
            sent_messages.append(message)

    monkeypatch.setattr(app_module.smtplib, "SMTP", DummySMTP)

    with app.app_context():
        config = app_module.ensure_notification_configuration()
        config.smtp_host = "smtp.office365.com"
        config.smtp_port = 587
        config.use_tls = True
        config.from_email = "info@dixielandwireless.com"
        config.from_name = "DixieLand Wireless"
        config.reply_to_email = "support@dixielandwireless.com"
        config.reply_to_name = "Support Desk"
        config.list_unsubscribe_url = "https://dixielandwireless.com/unsubscribe"
        config.list_unsubscribe_mailto = "unsubscribe@dixielandwireless.com"
        config.smtp_username = "alerts@dixielandwireless.com"
        config.smtp_password = "keep-me"
        db.session.commit()

        result = app_module.send_email_via_office365(
            app, "customer@example.com", "Welcome to DixieLand Wireless", "Hello there!"
        )

    assert result is True
    assert sent_messages, "Expected one email to be queued"
    message = sent_messages[0]
    assert message["Reply-To"] == "Support Desk <support@dixielandwireless.com>"
    assert (
        message["List-Unsubscribe"]
        == "<mailto:unsubscribe@dixielandwireless.com>, <https://dixielandwireless.com/unsubscribe>"
    )
    assert message["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert message["Message-ID"].endswith("@dixielandwireless.com>")
    assert message["Date"]


def test_admin_can_update_notification_preferences(app, client):
    login_admin(client)

    response = client.post(
        "/dashboard/notifications/preferences",
        data={"notify_installs": "on"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Notification preferences updated" in response.data

    with app.app_context():
        config = NotificationConfig.query.first()
        assert config.notify_install_activity is True
        assert config.notify_customer_activity is False
        assert config.notify_all_account_activity is False

    response = client.post(
        "/dashboard/notifications/preferences",
        data={
            "notify_installs": "on",
            "notify_customers": "on",
            "notify_all_activity": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        config = NotificationConfig.query.first()
        assert config.notify_install_activity is True
        assert config.notify_customer_activity is True
        assert config.notify_all_account_activity is True


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
    assert b"Calendar overview" in response.data
    assert b"My schedule" in response.data
    assert b"Current jobs" in response.data
    assert b"Upcoming jobs" in response.data


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
        category_choices = get_install_photo_category_choices()
        first_category = category_choices[0] if category_choices else "Additional Detail"

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
        "category": first_category,
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

def test_technician_appointment_page_shows_availability_calendar(app, client):
    with app.app_context():
        technician = Technician(
            name="Calendar Tech",
            email="calendar-tech@example.com",
            password_hash=generate_password_hash("CalendarPass123!"),
            is_active=True,
        )
        db.session.add(technician)
        db.session.commit()

        subscriber = Client(
            name="Calendar Client",
            email="calendar-client@example.com",
            status="Active",
        )
        db.session.add(subscriber)
        db.session.commit()

        appointment_time = (
            utcnow().replace(minute=0, second=0, microsecond=0) + timedelta(days=1)
        )
        appointment = Appointment(
            client_id=subscriber.id,
            technician_id=technician.id,
            title="Pole mount install",
            status="Scheduled",
            scheduled_for=appointment_time,
        )
        block = TechnicianSchedule(
            technician_id=technician.id,
            start_at=appointment_time.replace(hour=9),
            end_at=appointment_time.replace(hour=12),
            note="Morning availability",
            status="approved",
        )
        db.session.add_all([appointment, block])
        db.session.commit()
        appointment_id = appointment.id

    login_response = login_technician(
        client,
        email="calendar-tech@example.com",
        password="CalendarPass123!",
    )
    assert login_response.status_code == 200

    response = client.get(f"/tech/appointments/{appointment_id}")
    assert response.status_code == 200
    assert b"Availability calendar" in response.data
    assert b"Morning availability" in response.data
    assert b"Pole mount install" in response.data

