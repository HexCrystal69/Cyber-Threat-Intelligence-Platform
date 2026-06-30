import pytest
from unittest.mock import patch, Mock
from src.services.feed_collectors.openphish import OpenPhishCollector
from src.services.feed_collectors.abuseipdb import AbuseIPDBCollector
from src.services.feed_collectors.csv_upload import CSVUploadCollector
from src.utils.validation import validate_ioc

def test_base_collector_fingerprint():
    from src.services.feed_collectors.base import BaseFeedCollector
    class DummyCollector(BaseFeedCollector):
        def fetch(self): pass
        def validate(self, r): return True
        def normalize(self, r): return r

    c = DummyCollector("dummy", "http://dummy")
    fp1 = c.compute_fingerprint("IP", "1.1.1.1")
    fp2 = c.compute_fingerprint("ip", "1.1.1.1 ")
    # Normalization should strip and lowercase
    fp3 = c.compute_fingerprint("IP", "1.1.1.1")
    assert fp1 == fp3

def test_openphish_collector_fetch_and_parse():
    collector = OpenPhishCollector(feed_source_url="http://mockopenphish.com/feed.txt")
    
    mock_response = Mock()
    mock_response.text = "http://phish1.com/login\nhttp://phish2.com/login\n"
    mock_response.raise_for_status = Mock()

    with patch("requests.get", return_value=mock_response) as mock_get:
        records = collector.fetch()
        assert len(records) == 2
        assert records[0] == "http://phish1.com/login"
        mock_get.assert_called_once_with("http://mockopenphish.com/feed.txt", timeout=15)

def test_openphish_validation_and_normalize():
    collector = OpenPhishCollector()
    assert collector.validate("http://badsite.com") is True
    assert collector.validate("not-a-url") is False

    norm = collector.normalize("http://badsite.com")
    assert norm["indicator_value"] == "http://badsite.com"
    assert norm["indicator_type"] == "URL"
    assert norm["severity"] == "HIGH"

def test_abuseipdb_collector_fetch_no_key_fallback():
    collector = AbuseIPDBCollector()
    mock_response = Mock()
    mock_response.text = "# IP address blacklist\n8.8.8.8 10\n9.9.9.9 20"
    mock_response.raise_for_status = Mock()

    with patch("requests.get", return_value=mock_response):
        records = collector.fetch()
        assert len(records) == 2
        assert records[0]["ipAddress"] == "8.8.8.8"

def test_abuseipdb_normalize():
    collector = AbuseIPDBCollector()
    raw = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 85}
    assert collector.validate(raw) is True
    
    norm = collector.normalize(raw)
    assert norm["indicator_value"] == "1.2.3.4"
    assert norm["severity"] == "CRITICAL"

def test_csv_upload_collector_json():
    collector = CSVUploadCollector()
    content = '[{"indicator_value": "test@domain.com", "indicator_type": "EMAIL", "confidence_score": 70, "severity": "MEDIUM"}]'
    records = collector.fetch_from_content(content, "json")
    assert len(records) == 1
    assert records[0]["indicator_value"] == "test@domain.com"
    assert collector.validate(records[0]) is True

def test_csv_upload_collector_csv():
    collector = CSVUploadCollector()
    content = 'indicator_value,indicator_type,confidence_score,severity,tags\n1.1.1.1,IP,90,HIGH,"dns,malicious"'
    records = collector.fetch_from_content(content, "csv")
    assert len(records) == 1
    assert records[0]["indicator_value"] == "1.1.1.1"
    
    norm = collector.normalize(records[0])
    assert norm["indicator_type"] == "IP"
    assert norm["metadata"]["tags"] == ["dns", "malicious"]

def test_ioc_validators():
    assert validate_ioc("192.168.1.1", "IP") is True
    assert validate_ioc("2001:db8::1", "IP") is True
    assert validate_ioc("google.com", "DOMAIN") is True
    assert validate_ioc("http://google.com/test", "URL") is True
    assert validate_ioc("invalid-ip", "IP") is False
    assert validate_ioc("not_domain", "DOMAIN") is False
    assert validate_ioc("098f6bcd4621d373cade4e832627b4f6", "HASH_MD5") is True
    assert validate_ioc("a9993e364706816aba3e25717850c26c9cd0d89d", "HASH_SHA1") is True
    assert validate_ioc("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "HASH_SHA256") is True
    assert validate_ioc("bad-hash", "HASH_MD5") is False
