import pytest
from fastapi import status
from src.models.user import User

def test_register_user_success(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "newuser@ctip.io", "password": "securepassword", "role": "VIEWER"}
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "newuser@ctip.io"
    assert data["role"] == "VIEWER"
    assert "id" in data

def test_register_user_duplicate_email(client, db_session):
    # Register first
    client.post(
        "/api/v1/auth/register",
        json={"email": "dup@ctip.io", "password": "securepassword", "role": "VIEWER"}
    )
    # Register second
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "dup@ctip.io", "password": "securepassword", "role": "VIEWER"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "The user with this email already exists in the system."

def test_register_invalid_email(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "securepassword", "role": "VIEWER"}
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

def test_login_success(client):
    # First, register user
    client.post(
        "/api/v1/auth/register",
        json={"email": "loginuser@ctip.io", "password": "mypassword", "role": "VIEWER"}
    )
    # Login
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "loginuser@ctip.io", "password": "mypassword"}
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_wrong_password(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "wrongpass@ctip.io", "password": "mypassword", "role": "VIEWER"}
    )
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "wrongpass@ctip.io", "password": "incorrectpassword"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Incorrect email or password"

def test_login_non_existent_user(client):
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "notexist@ctip.io", "password": "somepassword"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_rbac_admin_allowed(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/feeds", headers=headers)
    assert response.status_code == status.HTTP_200_OK

def test_rbac_viewer_denied_post_feed(client, viewer_token):
    headers = {"Authorization": f"Bearer {viewer_token}"}
    response = client.post(
        "/api/v1/feeds",
        headers=headers,
        json={"name": "NewFeed", "source_url": "http://new.com", "provider": "Test", "feed_type": "TXT"}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_invalid_token_header(client):
    headers = {"Authorization": "Bearer invalidtokenhere"}
    response = client.get("/api/v1/feeds", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
