import hashlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Generator

class BaseFeedCollector(ABC):
    def __init__(self, feed_name: str, feed_source_url: str):
        self.feed_name = feed_name
        self.feed_source_url = feed_source_url

    @abstractmethod
    def fetch(self) -> Any:
        """
        Fetch raw feed data from source.
        """
        pass

    @abstractmethod
    def validate(self, raw_record: Any) -> bool:
        """
        Validate the raw record.
        """
        pass

    @abstractmethod
    def normalize(self, raw_record: Any) -> Dict[str, Any]:
        """
        Normalize raw record into structured format.
        """
        pass

    def compute_fingerprint(self, indicator_type: str, indicator_value: str) -> str:
        """
        Compute SHA-256 fingerprint for deduplication.
        sha256(indicator_type.lower() + indicator_value.lower())
        """
        data = f"{indicator_type.lower()}{indicator_value.lower()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
