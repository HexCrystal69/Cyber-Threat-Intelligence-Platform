import datetime
from sqlalchemy.orm import Session
from src.models.ioc import IOC
from src.models.campaign import CampaignIOC
from src.models.actor import ActorCampaign
from src.models.alert import AlertEvidence
from src.models.case import CaseEvidence
from src.models.blast_radius import IOCBlastRadiusSnapshot

class BlastRadiusEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_blast_radius(self, ioc_id: int) -> IOCBlastRadiusSnapshot:
        # 1. Affected campaigns
        camps = self.db.query(CampaignIOC).filter(CampaignIOC.ioc_id == ioc_id).all()
        camp_ids = [c.campaign_id for c in camps]

        # 2. Affected actors
        actors = []
        if camp_ids:
            actors = self.db.query(ActorCampaign).filter(ActorCampaign.campaign_id.in_(camp_ids)).all()
        actor_ids = [a.actor_id for a in actors]

        # 3. Affected alerts
        alerts = self.db.query(AlertEvidence).filter(
            AlertEvidence.evidence_type == "IOC",
            AlertEvidence.evidence_id == str(ioc_id)
        ).all()
        alert_ids = [a.alert_id for a in alerts]

        # 4. Affected cases
        cases = self.db.query(CaseEvidence).filter(
            CaseEvidence.evidence_type == "IOC",
            CaseEvidence.evidence_id == str(ioc_id)
        ).all()
        case_ids = [c.case_id for c in cases]

        # Score calculation formula
        score = (10 * len(camp_ids)) + (20 * len(actor_ids)) + (5 * len(alert_ids)) + (15 * len(case_ids))
        impact_score = min(score, 100)

        snapshot_json = {
            "campaign_ids": camp_ids,
            "actor_ids": actor_ids,
            "alert_ids": alert_ids,
            "case_ids": case_ids
        }

        # Save snapshot
        snap = IOCBlastRadiusSnapshot(
            ioc_id=ioc_id,
            impact_score=impact_score,
            snapshot_json=snapshot_json
        )
        self.db.add(snap)
        self.db.commit()
        self.db.refresh(snap)

        return snap
