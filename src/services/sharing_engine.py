import datetime
from sqlalchemy.orm import Session
from src.models.sharing import ThreatSharingPartner, SharedIntelligence, IntelligencePackage, SharingAudit
from src.services.audit import log_audit
from src.utils.metrics import threat_sharing_events_total

class SharingEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_partner_trust(self, partner_id: int) -> dict:
        partner = self.db.query(ThreatSharingPartner).filter(ThreatSharingPartner.id == partner_id).first()
        if not partner:
            raise ValueError("Partner not found")

        days_since_share = 30
        if partner.last_shared_at:
            delta = datetime.datetime.utcnow() - partner.last_shared_at
            days_since_share = delta.days

        reputation = max(10, min(100, partner.sharing_volume * 2 - days_since_share))
        partner.reputation_score = reputation
        partner.trust_score = int((partner.trust_level + reputation) / 2)
        
        self.db.commit()
        return {"trust_score": partner.trust_score, "reputation_score": partner.reputation_score}

    def share_intelligence(self, partner_id: int, object_type: str, object_id: str, classification_level: str = "TLP:CLEAR") -> dict:
        partner = self.db.query(ThreatSharingPartner).filter(ThreatSharingPartner.id == partner_id).first()
        if not partner:
            raise ValueError("Partner not found")

        shared = SharedIntelligence(
            partner_id=partner_id,
            object_type=object_type,
            object_id=object_id,
            classification_level=classification_level,
            shared_at=datetime.datetime.utcnow()
        )
        self.db.add(shared)

        partner.sharing_volume += 1
        partner.last_shared_at = datetime.datetime.utcnow()
        
        audit = SharingAudit(
            partner_id=partner_id,
            action_type="SHARED",
            object_count=1,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(audit)
        self.db.commit()

        self.calculate_partner_trust(partner_id)

        log_audit(
            self.db,
            user_id=1,
            action="SHARE_INTELLIGENCE",
            resource_type=object_type,
            resource_id=object_id
        )

        threat_sharing_events_total.labels(partner_id=str(partner_id), action_type="SHARED").inc()
        return {"shared_id": shared.id, "partner_id": partner_id}

    def create_package(self, package_name: str, package_type: str, object_ids: list) -> dict:
        pkg = IntelligencePackage(
            package_name=package_name,
            package_type=package_type,
            object_count=len(object_ids),
            checksum=f"sha256-{hash(package_name + str(object_ids))}",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(pkg)
        self.db.commit()
        self.db.refresh(pkg)
        return {"package_id": pkg.id, "checksum": pkg.checksum}
