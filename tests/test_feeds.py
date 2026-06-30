import pytest
from fastapi import status
from unittest.mock import patch
from src.models.feed import ThreatFeed

def test_list_feeds_authenticated(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/feeds", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) >= 2

def test_list_feeds_unauthenticated(client):
    response = client.get("/api/v1/feeds")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_create_feed_admin(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(
        "/api/v1/feeds",
        headers=headers,
        json={"name": "NewAdminFeed", "source_url": "http://admin.com/feed", "provider": "Admin", "feed_type": "TXT"}
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["name"] == "NewAdminFeed"

def test_create_feed_analyst_forbidden(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.post(
        "/api/v1/feeds",
        headers=headers,
        json={"name": "AnalystFeed", "source_url": "http://analyst.com", "provider": "Analyst", "feed_type": "TXT"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_create_duplicate_feed(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(
        "/api/v1/feeds",
        headers=headers,
        json={"name": "DupFeed", "source_url": "http://dup.com", "provider": "Test", "feed_type": "TXT"}
    )
    response = client.post(
        "/api/v1/feeds",
        headers=headers,
        json={"name": "DupFeed", "source_url": "http://dup.com", "provider": "Test", "feed_type": "TXT"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_get_feed_details(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/feeds/1", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "OpenPhish"

def test_get_feed_not_found(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.get("/api/v1/feeds/999", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND

def test_update_feed_analyst(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.patch(
        "/api/v1/feeds/1",
        headers=headers,
        json={"enabled": False}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["enabled"] is False

def test_trigger_ingest_success(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    with patch("src.routes.feeds.ingest_feed.delay") as mock_delay:
        mock_delay.return_value.id = "mock-task-uuid"
        response = client.post("/api/v1/feeds/1/ingest", headers=headers)
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert response.json()["job_id"] == "mock-task-uuid"
        mock_delay.assert_called_once_with(1)

def test_trigger_ingest_disabled_feed(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.post("/api/v1/feeds/3/ingest", headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_trigger_ingest_not_found(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    response = client.post("/api/v1/feeds/999/ingest", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
