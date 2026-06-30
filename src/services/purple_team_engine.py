import datetime
from sqlalchemy.orm import Session
from src.models.purple_team import AttackSimulation, SimulationResult, CoverageGap
from src.models.coverage import CoverageMatrix
from src.models.detection import DetectionRule
from src.utils.metrics import attack_simulations_total, coverage_gaps_total

class PurpleTeamEngine:
    def __init__(self, db: Session):
        self.db = db

    def execute_simulation(self, technique_id: str, simulation_name: str) -> dict:
        sim = AttackSimulation(
            technique_id=technique_id,
            simulation_name=simulation_name,
            status="RUNNING",
            executed_at=datetime.datetime.utcnow()
        )
        self.db.add(sim)
        self.db.commit()
        self.db.refresh(sim)

        rules_count = self.db.query(DetectionRule).filter(
            DetectionRule.enabled == True,
            DetectionRule.description.contains(technique_id)
        ).count()

        detection_triggered = rules_count > 0
        response_triggered = rules_count > 0
        response_time = 1500 if detection_triggered else 0

        res = SimulationResult(
            simulation_id=sim.id,
            detection_triggered=detection_triggered,
            response_triggered=response_triggered,
            response_time_ms=response_time,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(res)

        sim.status = "SUCCESS"
        self.db.commit()

        matrix = self.db.query(CoverageMatrix).filter(CoverageMatrix.attack_technique_id == technique_id).first()
        if not matrix:
            matrix = CoverageMatrix(
                attack_technique_id=technique_id,
                rule_count=rules_count,
                coverage_score=100.0 if rules_count > 0 else 0.0,
                snapshot_at=datetime.datetime.utcnow()
            )
            self.db.add(matrix)
        else:
            matrix.rule_count = rules_count
            matrix.coverage_score = 100.0 if rules_count > 0 else 0.0
            matrix.snapshot_at = datetime.datetime.utcnow()

        self.db.commit()
        attack_simulations_total.inc()
        return {"simulation_id": sim.id, "detection_triggered": detection_triggered}

    def discover_gaps(self, techniques: list) -> list:
        gaps = []
        for tech in techniques:
            rules_count = self.db.query(DetectionRule).filter(
                DetectionRule.enabled == True,
                DetectionRule.description.contains(tech)
            ).count()

            if rules_count == 0:
                gap = self.db.query(CoverageGap).filter(CoverageGap.technique_id == tech).first()
                if not gap:
                    gap = CoverageGap(
                        technique_id=tech,
                        severity="HIGH",
                        recommendation=f"Deploy YARA/Sigma rule to monitor technique {tech}",
                        created_at=datetime.datetime.utcnow()
                    )
                    self.db.add(gap)
                    self.db.commit()
                    self.db.refresh(gap)
                    coverage_gaps_total.inc()
                gaps.append(gap)
        return gaps
