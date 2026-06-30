import logging
from sqlalchemy.orm import Session
from src.models.actor import ThreatActor, ActorCampaign
from src.models.campaign import ThreatCampaign, CampaignIOC
from src.models.ioc import IOCMetadata
from src.models.enrichment import IOCEnrichment

logger = logging.getLogger(__name__)

class AttributionEngine:
    def __init__(self, db: Session):
        self.db = db

    def attribute_campaign(self, campaign_id: int) -> ActorCampaign | None:
        campaign = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
        if not campaign:
            return None

        # Fetch IOCs in the campaign
        campaign_iocs = self.db.query(CampaignIOC).filter(CampaignIOC.campaign_id == campaign_id).all()
        ioc_ids = [c.ioc_id for c in campaign_iocs]

        if not ioc_ids:
            return None

        # Analyze tags, ASNs, registrars of these IOCs
        asns = set()
        registrars = set()
        tags = set()

        enrichments = self.db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id.in_(ioc_ids)).all()
        for e in enrichments:
            if e.asn:
                asns.add(e.asn)
            if e.whois_registrar:
                registrars.add(e.whois_registrar)

        metadata = self.db.query(IOCMetadata).filter(IOCMetadata.ioc_id.in_(ioc_ids)).all()
        for m in metadata:
            if m.tags:
                tags.update(m.tags)

        # Look for matching ThreatActors that share these indicators
        actors = self.db.query(ThreatActor).all()
        best_actor = None
        highest_score = 0
        best_evidence = {}

        for actor in actors:
            # Check overlap
            # Simple rule: if actor description or tags match campaign metadata or alias
            shared_tags = [t for t in tags if actor.alias and t.lower() in actor.alias.lower()]
            
            # Simulated matching based on seeded threat actor profiles
            # In a real system, you would match against an actor profile database of signature rules
            score = len(shared_tags) * 10
            evidence = {"campaign_overlap": len(shared_tags)}
            
            # If the actor description notes a registrar or ASN they typically reuse
            if actor.description:
                for reg in registrars:
                    if reg.lower() in actor.description.lower():
                        score += 30
                        evidence["shared_registrar"] = True
                for asn in asns:
                    if asn.lower() in actor.description.lower():
                        score += 20
                        evidence["shared_asn"] = True

            if score > highest_score and score >= 30:
                highest_score = score
                best_actor = actor
                best_evidence = evidence

        if best_actor:
            # Save mapping
            actor_camp = self.db.query(ActorCampaign).filter(
                ActorCampaign.actor_id == best_actor.id,
                ActorCampaign.campaign_id == campaign_id
            ).first()

            if not actor_camp:
                actor_camp = ActorCampaign(
                    actor_id=best_actor.id,
                    campaign_id=campaign_id,
                    attribution_reason=f"Matched registrar or ASN signature with {best_actor.name}",
                    confidence=min(highest_score, 100),
                    evidence_json=best_evidence
                )
                self.db.add(actor_camp)
                self.db.commit()
                self.db.refresh(actor_camp)
                logger.info(f"Attributed campaign {campaign_id} to actor {best_actor.name}")
            return actor_camp

        return None
