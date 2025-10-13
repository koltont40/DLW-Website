import io

import pytest

from app import (
    BrandingAsset,
    Client,
    Document,
    NavigationItem,
    create_app,
    db,
)


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
    assert b"Client Dashboard" in login_response.data
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
