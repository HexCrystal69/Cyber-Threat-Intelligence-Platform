from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseEnricher(ABC):
    """
    Abstract Base Class interface for threat indicator enrichment.
    Future milestones will implement subclasses for:
    - GeoIP
    - ASN lookup
    - WHOIS
    - VirusTotal
    - URLHaus
    - GreyNoise
    """

    @abstractmethod
    async def enrich(self, indicator_value: str, indicator_type: str) -> Dict[str, Any]:
        """
        Enrich an indicator with external threat intelligence.
        """
        pass
