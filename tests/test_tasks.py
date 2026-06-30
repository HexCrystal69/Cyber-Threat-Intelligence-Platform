import os
import pytest
from unittest.mock import patch, Mock
from src.tasks.ingestion_tasks import ingest_feed, bulk_upload_iocs
from src.models.feed import ThreatFeed, FeedExecutionLog
from src.models.job import IngestionJob
from src.models.ioc import IOC, IOCFingerprint

def test_ingest_feed_not_found(db_session):
    # Ingesting feed that doesn't exist
    result = ingest_feed(9999)
    assert result["status"] == "FAILED"
    assert result["error"] == "Feed not found"

def test_ingest_feed_disabled(db_session):
    # Feed 3 is disabled in conftest pre-seed
    result = ingest_feed(3)
    assert result["status"] == "SKIPPED"

@patch("requests.get")
def test_ingest_openphish_task_success(mock_get, db_session):
    # Set up mock OpenPhish response
    mock_resp = Mock()
    mock_resp.text = "http://phishing-task-test.com/login\n"
    mock_resp.raise_for_status = Mock()
    mock_get.return_value = mock_resp

    # Feed 1 is OpenPhish
    result = ingest_feed(1)
    assert result["status"] == "SUCCESS"
    assert result["processed"] == 1
    assert result["failed"] == 0

    # Verify DB updates
    feed = db_session.query(ThreatFeed).filter(ThreatFeed.id == 1).first()
    assert feed.success_count == 1
    assert feed.last_success_at is not None

    # Check IOC and Fingerprint
    ioc = db_session.query(IOC).filter(IOC.indicator_value == "http://phishing-task-test.com/login").first()
    assert ioc is not None
    assert ioc.indicator_type == "URL"

    # Fingerprint
    fp = db_session.query(IOCFingerprint).filter(IOCFingerprint.ioc_id == ioc.id).first()
    assert fp is not None

    # Verify IngestionJob is created and marked SUCCESS
    job = db_session.query(IngestionJob).first()
    assert job is not None
    assert job.status == "SUCCESS"

    # Verify FeedExecutionLog is created
    log_entry = db_session.query(FeedExecutionLog).filter(FeedExecutionLog.feed_id == 1).first()
    assert log_entry is not None
    assert log_entry.records_processed == 1

def test_bulk_upload_iocs_task_success(db_session):
    # Write a temporary CSV file
    temp_csv_path = "./test_upload_task.csv"
    with open(temp_csv_path, "w", encoding="utf-8") as f:
        f.write("indicator_value,indicator_type,confidence_score,severity,tags\n1.2.3.4,IP,88,HIGH,tag1")

    # Run bulk upload task
    result = bulk_upload_iocs(temp_csv_path, feed_id=2)
    assert result["status"] == "SUCCESS"
    assert result["processed"] == 1
    assert result["failed"] == 0

    # File should be removed by task
    assert not os.path.exists(temp_csv_path)

    # Verify DB
    ioc = db_session.query(IOC).filter(IOC.indicator_value == "1.2.3.4").first()
    assert ioc is not None
    assert ioc.confidence_score == 88

def test_bulk_upload_non_existent_file(db_session):
    result = bulk_upload_iocs("./nonexistent.csv", feed_id=2)
    assert result["status"] == "FAILED"
    assert "does not exist" in result["error"]

def test_deduplication_during_task(db_session, monkeypatch):
    # Setup mock feed response
    mock_resp = Mock()
    mock_resp.text = "http://dup-task.com/login\n"
    mock_resp.raise_for_status = Mock()
    
    with patch("requests.get", return_value=mock_resp):
        # Run first time to create
        res1 = ingest_feed(1)
        assert res1["processed"] == 1
        
        # Run second time to update last_seen
        res2 = ingest_feed(1)
        assert res2["processed"] == 1

    # Verify only 1 IOC is created (deduplicated)
    count = db_session.query(IOC).filter(IOC.indicator_value == "http://dup-task.com/login").count()
    assert count == 1
