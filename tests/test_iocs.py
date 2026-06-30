import pytest
from fastapi import status
from unittest.mock import patch
from io import BytesIO
from src.models.ioc import IOC, IOCMetadata, IOCFingerprint
import datetime

@pytest.fixture
def sample_ioc(db_session):
    ioc = IOC(
        id=10,
        indicator_value="8.8.8.8",
        indicator_type="IP",
        confidence_score=90,
        severity="HIGH",
        status="ACTIVE",
        normalized_indicator="8.8.8.8",
        search_text="8.8.8.8",
        source_feed_id=1,
        created_at=datetime.datetime.utcnow()
    )
    meta = IOCMetadata(
        ioc_id=10,
        country="US",
        asn="AS15169",
        organization="Google LLC",
        tags=["dns", "google"],
        raw_data={}
    )
    db_session.add(ioc)
    db_session.add(meta)
    db_session.commit()
    return ioc

def test_search_iocs_no_filter(client, viewer_token, sample_ioc):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/iocs", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 1
    assert response.json()[0]["indicator_value"] == "8.8.8.8"

def test_search_iocs_filter_type(client, viewer_token, sample_ioc):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/iocs?type=ip", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 1

    response = client.get("/api/v1/iocs?type=domain", headers=headers)
    assert len(response.json()) == 0

def test_search_iocs_filter_severity(client, viewer_token, sample_ioc):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/iocs?severity=high", headers=headers)
    assert len(response.json()) == 1

    response = client.get("/api/v1/iocs?severity=low", headers=headers)
    assert len(response.json()) == 0

def test_search_iocs_text_query(client, viewer_token, sample_ioc):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    # Exact
    response = client.get("/api/v1/iocs?query=8.8.8.8", headers=headers)
    assert len(response.json()) == 1

    # Prefix
    response = client.get("/api/v1/iocs?query=8.8.", headers=headers)
    assert len(response.json()) == 1

    # Contains
    response = client.get("/api/v1/iocs?query=.8.8", headers=headers)
    assert len(response.json()) == 1

    # Miss
    response = client.get("/api/v1/iocs?query=9.9.9", headers=headers)
    assert len(response.json()) == 0

def test_get_ioc_by_id(client, viewer_token, sample_ioc):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/iocs/10", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["indicator_value"] == "8.8.8.8"
    assert response.json()["metadata"]["country"] == "US"

def test_get_ioc_not_found(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/iocs/9999", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND

def test_upload_iocs_file_success(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    file_content = "indicator_value,indicator_type,confidence_score,severity\n1.1.1.1,IP,85,HIGH"
    f = BytesIO(file_content.encode("utf-8"))

    with patch("src.routes.iocs.bulk_upload_iocs.delay") as mock_delay:
        mock_delay.return_value.id = "mock-upload-job"
        response = client.post(
            "/api/v1/iocs/upload",
            headers=headers,
            files={"file": ("test.csv", f, "text/csv")}
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.json()["job_id"] == "mock-upload-job"
        mock_delay.assert_called_once()

def test_upload_iocs_invalid_extension(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    f = BytesIO(b"some content")
    response = client.post(
        "/api/v1/iocs/upload",
        headers=headers,
        files={"file": ("test.txt", f, "text/plain")}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Only CSV and JSON uploads are allowed" in response.json()["detail"]

def test_upload_iocs_file_too_large(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    # Create large payload > 50MB
    large_payload = b"a" * (51 * 1024 * 1024)
    f = BytesIO(large_payload)
    response = client.post(
        "/api/v1/iocs/upload",
        headers=headers,
        files={"file": ("test.csv", f, "text/csv")}
    )
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
