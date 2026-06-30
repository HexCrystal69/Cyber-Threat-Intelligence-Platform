import datetime
from sqlalchemy.orm import Session
from src.models.detection_analytics import DetectionAnalyticsSnapshot, AlertFidelityScore
from src.models.detection_health import DetectionHealthSnapshot
from src.models.alert import SecurityAlert
from src.models.feedback import AlertFeedback
from src.utils.metrics import alert_fidelity_score

class DetectionAnalyticsEngine:
    def __init__(self, db: Session):
        self.db = db

    def calculate_metrics(self, rule_id: int, tp: int, fp: int, fn: int) -> dict:
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tp) if (fp + tp) > 0 else 0.0

        snap = DetectionAnalyticsSnapshot(
            detection_rule_id=rule_id,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision_score=precision,
            recall_score=recall,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(snap)

        health = DetectionHealthSnapshot(
            detection_rule_id=rule_id,
            precision_score=precision,
            recall_score=recall,
            f1_score=f1,
            false_positive_rate=fpr,
            snapshot_at=datetime.datetime.utcnow()
        )
        self.db.add(health)
        self.db.commit()

        return {"precision": precision, "recall": recall, "f1": f1}

    def score_alert_fidelity(self, alert_id: int) -> float:
        alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise ValueError("Alert not found")

        feedbacks = self.db.query(AlertFeedback).filter(AlertFeedback.alert_id == alert_id).all()
        
        tp_count = sum(1 for f in feedbacks if f.feedback_type == "TRUE_POSITIVE")
        fp_count = sum(1 for f in feedbacks if f.feedback_type == "FALSE_POSITIVE")

        base_score = 50.0
        if alert.severity == "CRITICAL":
            base_score += 20.0
        elif alert.severity == "HIGH":
            base_score += 10.0

        if tp_count > 0:
            base_score += tp_count * 15.0
        if fp_count > 0:
            base_score -= fp_count * 20.0

        fidelity = max(0.0, min(100.0, base_score))

        score_record = AlertFidelityScore(
            alert_id=alert_id,
            fidelity_score=fidelity,
            reasoning=f"Computed based on severity={alert.severity}, feedback TP={tp_count}, FP={fp_count}",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(score_record)
        self.db.commit()

        alert_fidelity_score.inc(int(fidelity))
        return fidelity
