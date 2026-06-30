import datetime
from sqlalchemy.orm import Session
from src.models.compliance import SecurityControl, ControlMapping, ComplianceSnapshot
from src.models.detection import DetectionRule
from src.utils.metrics import compliance_snapshots_total

class ComplianceEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_compliance(self, framework: str) -> ComplianceSnapshot:
        controls = self.db.query(SecurityControl).filter(SecurityControl.control_framework == framework).all()
        if not controls:
            mock_controls = [
                SecurityControl(control_framework=framework, control_id="ID-1", description="Access Control"),
                SecurityControl(control_framework=framework, control_id="ID-2", description="Audit and Accountability")
            ]
            self.db.add_all(mock_controls)
            self.db.commit()
            controls = mock_controls

        covered_count = 0
        for ctrl in controls:
            mappings = self.db.query(ControlMapping).filter(ControlMapping.control_id == ctrl.control_id).all()
            for mapping in mappings:
                if mapping.detection_rule_id:
                    rule = self.db.query(DetectionRule).filter(
                        DetectionRule.id == mapping.detection_rule_id,
                        DetectionRule.enabled == True
                    ).first()
                    if rule:
                        covered_count += 1
                        break

        total = len(controls)
        score = (covered_count / total * 100.0) if total > 0 else 50.0

        snap = ComplianceSnapshot(
            framework=framework,
            compliance_score=score,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(snap)
        self.db.commit()
        self.db.refresh(snap)

        compliance_snapshots_total.inc()
        return snap
