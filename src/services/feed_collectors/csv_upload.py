import csv
import json
import logging
from io import StringIO
from typing import List, Dict, Any
from src.services.feed_collectors.base import BaseFeedCollector
from src.utils.validation import validate_ioc

logger = logging.getLogger(__name__)

class CSVUploadCollector(BaseFeedCollector):
    def __init__(self):
        super().__init__(feed_name="CSVUpload", feed_source_url="local_upload")

    def fetch(self) -> Any:
        raise NotImplementedError("Use fetch_from_content for CSVUploadCollector")

    def fetch_from_content(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        records = []
        if content_type == "json":
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    records = data
                elif isinstance(data, dict):
                    records = [data]
            except Exception as e:
                logger.error(f"Failed to parse JSON content: {e}")
                raise ValueError("Invalid JSON format")
        elif content_type == "csv":
            try:
                f = StringIO(content)
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))
            except Exception as e:
                logger.error(f"Failed to parse CSV content: {e}")
                raise ValueError("Invalid CSV format")
        else:
            raise ValueError("Unsupported content type")
        return records

    def validate(self, raw_record: Dict[str, Any]) -> bool:
        val = raw_record.get("indicator_value")
        itype = raw_record.get("indicator_type")
        if not val or not itype:
            return False
        return validate_ioc(val, itype)

    def normalize(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        val = raw_record.get("indicator_value")
        itype = raw_record.get("indicator_type")
        score = int(raw_record.get("confidence_score", 50))
        severity = raw_record.get("severity", "INFO").upper()
        status = raw_record.get("status", "ACTIVE").upper()

        normalized_val = val.strip().lower()
        
        # Additional fields
        country = raw_record.get("country")
        asn = raw_record.get("asn")
        org = raw_record.get("organization")
        
        tags_raw = raw_record.get("tags", "")
        if isinstance(tags_raw, str):
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            tags = tags_raw
        else:
            tags = []

        return {
            "indicator_value": val,
            "indicator_type": itype.upper(),
            "confidence_score": score,
            "severity": severity,
            "status": status,
            "normalized_indicator": normalized_val,
            "search_text": normalized_val,
            "metadata": {
                "country": country,
                "asn": asn,
                "organization": org,
                "tags": tags,
                "raw_data": raw_record
            }
        }
