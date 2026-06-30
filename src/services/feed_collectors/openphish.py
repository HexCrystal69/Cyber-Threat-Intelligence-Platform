import requests
import logging
from typing import List, Dict, Any
from src.services.feed_collectors.base import BaseFeedCollector
from src.utils.validation import validate_ioc

logger = logging.getLogger(__name__)

class OpenPhishCollector(BaseFeedCollector):
    def __init__(self, feed_source_url: str = "https://openphish.com/feed.txt"):
        super().__init__(feed_name="OpenPhish", feed_source_url=feed_source_url)

    def fetch(self) -> List[str]:
        try:
            response = requests.get(self.feed_source_url, timeout=15)
            response.raise_for_status()
            # Split lines and clean whitespaces/empty lines
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            return lines
        except Exception as e:
            logger.error(f"Error fetching OpenPhish feed: {e}")
            raise

    def validate(self, raw_record: str) -> bool:
        # Check if the record is a valid URL
        return validate_ioc(raw_record, "URL")

    def normalize(self, raw_record: str) -> Dict[str, Any]:
        normalized_val = raw_record.strip().lower()
        return {
            "indicator_value": raw_record,
            "indicator_type": "URL",
            "confidence_score": 80,
            "severity": "HIGH",
            "status": "ACTIVE",
            "normalized_indicator": normalized_val,
            "search_text": normalized_val,
            "metadata": {
                "tags": ["phishing", "openphish"],
                "raw_data": {"original_line": raw_record}
            }
        }
