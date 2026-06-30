from sqlalchemy.orm import Session
from src.models.ioc import IOC
from src.models.enrichment import IOCEnrichment
from src.models.sighting import IOCSighting
from src.models.campaign import CampaignIOC, ThreatCampaign

class SeverityEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_severity(self, ioc_id: int) -> str:
        ioc = self.db.query(IOC).filter(IOC.id == ioc_id).first()
        if not ioc:
            raise ValueError(f"IOC ID {ioc_id} not found")

        # 1. Reputation (0-100)
        reputation = 50
        enrichment = self.db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc_id).first()
        if enrichment:
            reputation = enrichment.reputation_score

        # 2. Confidence (0-100)
        confidence = ioc.confidence_score

        # 3. Sightings (0-100)
        sightings = self.db.query(IOCSighting).filter(IOCSighting.ioc_id == ioc_id).all()
        sighting_count = sum(s.sighting_count for s in sightings)
        sightings_score = min(sighting_count * 10, 100)

        # 4. Campaign score (0-100)
        campaign_score = 0
        campaign_ioc = self.db.query(CampaignIOC).filter(CampaignIOC.ioc_id == ioc_id).first()
        if campaign_ioc:
            campaign = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_ioc.campaign_id).first()
            if campaign:
                campaign_score = campaign.confidence_score

        # Weighted calculation
        score = (
            (0.35 * reputation) +
            (0.25 * confidence) +
            (0.20 * sightings_score) +
            (0.20 * campaign_score)
        )

        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
