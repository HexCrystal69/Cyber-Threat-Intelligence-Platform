import os
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database import Base, get_db
from src.main import app
from src.config import settings
from src.security.auth import create_access_token, hash_password
from src.models.user import User
from src.models.feed import ThreatFeed
from src.kafka_client import kafka_producer
import asyncio

from src.database import Base, get_db, engine, SessionLocal

@pytest.fixture(scope="session", autouse=True)
def configure_celery():
    from src.celery_app import celery_app
    celery_app.conf.update(
        task_always_eager=True,
        task_eager_propagates=True
    )

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    try:
        # Graceful remove to avoid Windows file locks on session exit
        import time
        time.sleep(0.5)
        if os.path.exists("./test.db"):
            os.remove("./test.db")
    except Exception:
        pass

@pytest.fixture(autouse=True)
def db_session():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    
    # Pre-seed feeds
    openphish_feed = ThreatFeed(
        id=1,
        name="OpenPhish",
        source_url="https://openphish.com/feed.txt",
        provider="OpenPhish",
        feed_type="TXT",
        enabled=True
    )
    abuseipdb_feed = ThreatFeed(
        id=2,
        name="AbuseIPDB",
        source_url="https://api.abuseipdb.com/api/v2/blacklist",
        provider="AbuseIPDB",
        feed_type="JSON",
        enabled=True
    )
    disabled_feed = ThreatFeed(
        id=3,
        name="DisabledFeed",
        source_url="https://example.com/disabled",
        provider="Test",
        feed_type="TXT",
        enabled=False
    )
    session.add_all([openphish_feed, abuseipdb_feed, disabled_feed])
    session.commit()

    yield session
    session.close()

@pytest.fixture(autouse=True)
def mock_kafka(monkeypatch):
    """
    Mock Kafka producer calls during testing.
    """
    class MockProducer:
        def __init__(self):
            self.published = []

        async def send_and_wait(self, topic, message):
            self.published.append((topic, message))

        async def start(self):
            pass

        async def stop(self):
            pass

    mock_prod = MockProducer()
    monkeypatch.setattr(kafka_producer, "producer", mock_prod)
    monkeypatch.setattr(kafka_producer, "enabled", True)
    
    async def mock_start():
        pass
    async def mock_stop():
        pass
        
    monkeypatch.setattr(kafka_producer, "start", mock_start)
    monkeypatch.setattr(kafka_producer, "stop", mock_stop)
    return mock_prod

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

# Helpers to generate tokens
@pytest.fixture
def admin_token(db_session):
    user = User(
        email="admin@ctip.io",
        hashed_password=hash_password("adminpass"),
        role="ADMIN"
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    return token

@pytest.fixture
def analyst_token(db_session):
    user = User(
        email="analyst@ctip.io",
        hashed_password=hash_password("analystpass"),
        role="ANALYST"
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    return token

@pytest.fixture
def viewer_token(db_session):
    user = User(
        email="viewer@ctip.io",
        hashed_password=hash_password("viewerpass"),
        role="VIEWER"
    )
    db_session.add(user)
    db_session.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    return token
