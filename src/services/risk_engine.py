import datetime
from sqlalchemy.orm import Session
from src.models.ioc import IOC
from src.models.enrichment import IOCEnrichment
from src.models.sighting import IOCSighting
from src.models.campaign import CampaignIOC, ThreatCampaign
from src.models.actor import ActorCampaign, ThreatActor
from src.models.score import ThreatScoreSnapshot

class RiskEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_risk(self, ioc_id: int) -> str:
        ioc = self.db.query(IOC).filter(IOC.id == ioc_id).first()
        if not ioc:
            raise ValueError(f"IOC ID {ioc_id} not found")

        # 1. Severity Score mapping (0-100)
        severity_map = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 25}
        severity_score = severity_map.get(ioc.severity.upper(), 50)

        # 2. Reputation (0-100)
        reputation = 50
        enrichment = self.db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc_id).first()
        if enrichment:
            reputation = enrichment.reputation_score

        # 3. Sightings (0-100)
        sightings = self.db.query(IOCSighting).filter(IOCSighting.ioc_id == ioc_id).all()
        sighting_count = sum(s.sighting_count for s in sightings)
        sightings_score = min(sighting_count * 10, 100)

        # 4. Campaign score (0-100)
        campaign_score = 0
        actor_confidence = 0
        campaign_ioc = self.db.query(CampaignIOC).filter(CampaignIOC.ioc_id == ioc_id).first()
        if campaign_ioc:
            campaign = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_ioc.campaign_id).first()
            if campaign:
                campaign_score = campaign.confidence_score
                
                # Check for mapped Threat Actor
                actor_camp = self.db.query(ActorCampaign).filter(ActorCampaign.campaign_id == campaign.id).first()
                if actor_camp:
                    actor_confidence = actor_camp.confidence

        # Weighted calculation
        score = (
            (0.30 * severity_score) +
            (0.25 * reputation) +
            (0.20 * sightings_score) +
            (0.15 * campaign_score) +
            (0.10 * actor_confidence)
        )

        risk_val = int(score)
        
        # Save Threat Score Snapshot
        snapshot = ThreatScoreSnapshot(
            ioc_id=ioc_id,
            severity_score=severity_score,
            risk_score=risk_val,
            reputation_score=reputation,
            confidence_score=ioc.confidence_score,
            snapshot_at=datetime.datetime.utcnow()
        )
        self.db.add(snapshot)
        self.db.commit()

        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
