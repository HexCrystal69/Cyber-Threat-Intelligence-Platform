import os
import requests
import logging
from typing import List, Dict, Any
from src.services.feed_collectors.base import BaseFeedCollector
from src.utils.validation import validate_ioc

logger = logging.getLogger(__name__)

class AbuseIPDBCollector(BaseFeedCollector):
    def __init__(self, feed_source_url: str = "https://api.abuseipdb.com/api/v2/blacklist"):
        super().__init__(feed_name="AbuseIPDB", feed_source_url=feed_source_url)
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

    def fetch(self) -> List[Dict[str, Any]]:
        # If no key, we fallback to a public domain list or community blacklist to avoid crashing/empty
        if not self.api_key:
            logger.warning("No ABUSEIPDB_API_KEY set. Attempting fetch from public alternative or mock response.")
            # For testing/demo fallback to a public feed of abuse IPs or mock data depending on configuration
            fallback_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
            try:
                response = requests.get(fallback_url, timeout=15)
                response.raise_for_status()
                ips = []
                for line in response.text.splitlines():
                    if line.strip() and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            ips.append({"ipAddress": parts[0], "abuseConfidenceScore": 75})
                return ips[:100]  # Limit to 100
            except Exception as e:
                logger.error(f"Failed to fetch from fallback: {e}")
                raise

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "limit": 100
            }
            response = requests.get(self.feed_source_url, headers=headers, params=params, timeout=15)
            response.raise_for_status()
            data = response.json()
            return data.get("data", [])
        except Exception as e:
            logger.error(f"Error fetching from AbuseIPDB API: {e}")
            raise

    def validate(self, raw_record: Dict[str, Any]) -> bool:
        ip = raw_record.get("ipAddress")
        if not ip:
            return False
        return validate_ioc(ip, "IP")

    def normalize(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        ip = raw_record.get("ipAddress")
        score = raw_record.get("abuseConfidenceScore", 50)
        
        # Calculate severity based on score
        severity = "INFO"
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"

        normalized_val = ip.strip().lower()
        return {
            "indicator_value": ip,
            "indicator_type": "IP",
            "confidence_score": score,
            "severity": severity,
            "status": "ACTIVE",
            "normalized_indicator": normalized_val,
            "search_text": normalized_val,
            "metadata": {
                "tags": ["abuseipdb", "malicious-ip"],
                "raw_data": raw_record
            }
        }
