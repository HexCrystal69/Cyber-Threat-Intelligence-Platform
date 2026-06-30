import datetime
from sqlalchemy.orm import Session
from src.models.case import InvestigationCase, CaseAlert, CaseEvidence
from src.models.alert import SecurityAlert
from src.models.analyst import AnalystAction

class CaseEngine:
    def __init__(self, db: Session):
        self.db = db

    def create_case(self, title: str, description: str, severity: str, user_id: int) -> InvestigationCase:
        case = InvestigationCase(
            title=title,
            description=description,
            severity=severity,
            status="OPEN"
        )
        self.db.add(case)
        self.db.commit()
        self.db.refresh(case)

        # Audit Action
        audit = AnalystAction(
            user_id=user_id,
            action_type="CASE_ASSIGNED",
            target_type="CASE",
            target_id=str(case.id),
            notes=f"Created SOC case: {title}"
        )
        self.db.add(audit)
        self.db.commit()

        return case

    def attach_alert_to_case(self, case_id: int, alert_id: int, user_id: int):
        # Verify both exist
        case = self.db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not case or not alert:
            raise ValueError("Case or Alert not found")

        # Map them
        mapping = CaseAlert(case_id=case_id, alert_id=alert_id)
        self.db.add(mapping)

        # Update Alert status
        alert.status = "UNDER_INVESTIGATION"

        # Audit Action
        audit = AnalystAction(
            user_id=user_id,
            action_type="ALERT_ACKNOWLEDGED",
            target_type="ALERT",
            target_id=str(alert_id),
            notes=f"Linked alert to case #{case_id}"
        )
        self.db.add(audit)
        self.db.commit()

    def attach_evidence_to_case(self, case_id: int, evidence_type: str, evidence_id: str):
        evidence = CaseEvidence(
            case_id=case_id,
            evidence_type=evidence_type,
            evidence_id=evidence_id
        )
        self.db.add(evidence)
        self.db.commit()

    def update_case_status(self, case_id: int, status: str, user_id: int):
        case = self.db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError("Case not found")

        case.status = status
        if status in ["RESOLVED", "CLOSED"]:
            case.closed_at = datetime.datetime.utcnow()

        audit = AnalystAction(
            user_id=user_id,
            action_type="CASE_ESCALATED" if status == "UNDER_INVESTIGATION" else "ALERT_DISMISSED",
            target_type="CASE",
            target_id=str(case_id),
            notes=f"Case status updated to {status}"
        )
        self.db.add(audit)
        self.db.commit()
