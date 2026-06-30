import logging
from sqlalchemy.orm import Session
from src.models.playbook import ResponsePlaybook, PlaybookStep
from src.services.enrichment_engine import EnrichmentEngine
from src.services.correlation_engine import CorrelationEngine
from src.services.alert_engine import AlertEngine
from src.services.case_engine import CaseEngine

logger = logging.getLogger(__name__)

class PlaybookEngine:
    def __init__(self, db: Session):
        self.db = db

    def execute_playbook(self, playbook_id: int, target_ioc_id: int, user_id: int = 1) -> bool:
        playbook = self.db.query(ResponsePlaybook).filter(ResponsePlaybook.id == playbook_id).first()
        if not playbook or not playbook.enabled:
            return False

        steps = self.db.query(PlaybookStep).filter(
            PlaybookStep.playbook_id == playbook_id
        ).order_by(PlaybookStep.step_order.asc()).all()

        for step in steps:
            logger.info(f"Executing step {step.step_order} ({step.action_type}) for playbook {playbook.name}")
            
            if step.action_type == "ENRICH":
                enrich = EnrichmentEngine(self.db)
                enrich.enrich_ioc(target_ioc_id)

            elif step.action_type == "CORRELATE":
                corr = CorrelationEngine(self.db)
                corr.run_correlation()

            elif step.action_type == "ESCALATE":
                alert_eng = AlertEngine(self.db)
                alert = alert_eng.trigger_alerts_for_ioc(target_ioc_id)
                if alert:
                    # Update score to Critical
                    alert_eng.update_alert_score(alert.id, 95, "Automated escalation step")

            elif step.action_type == "CASE_CREATE":
                # Create a SOC case
                case_eng = CaseEngine(self.db)
                case_eng.create_case(
                    title=f"Incident Playbook: IOC {target_ioc_id}",
                    description=f"Auto-generated SOC case by playbook: {playbook.name}",
                    severity=playbook.severity,
                    user_id=user_id
                )

        return True
