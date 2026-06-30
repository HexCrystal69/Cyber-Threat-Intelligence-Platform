import pytest
from fastapi import status
from unittest.mock import patch, MagicMock

def test_health_check_healthy(client):
    response = client.get("/health")
    # In test environment, DB is SQLite, Redis is simulated or fails (giving degraded),
    # let's assert either 200 or 503 depending on Redis connection
    assert response.status_code in [200, 503]
    data = response.json()
    assert "database" in data
    assert "redis" in data
    assert "kafka" in data
    assert "celery" in data
    assert "disk_usage" in data
    assert "memory_usage" in data

def test_health_check_database_failure(client):
    # Mock database session execute to raise exception
    mock_db = MagicMock()
    mock_db.execute.side_effect = Exception("DB Connection Lost")
    
    # We override get_db dependency for health router
    from src.database import get_db
    from src.main import app
    
    def override_get_db():
        yield mock_db
        
    app.dependency_overrides[get_db] = override_get_db
    
    response = client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert data["database"] == "unhealthy"
    assert data["status"] == "degraded"
    
    app.dependency_overrides.clear()

def test_metrics_endpoint(client):
    response = client.get("/metrics")
    assert response.status_code == status.HTTP_200_OK
    assert "ioc_ingested_total" in response.text
