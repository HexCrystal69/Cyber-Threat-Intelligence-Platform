import datetime
from sqlalchemy.orm import Session
from src.models.detection_ai import DetectionSuggestion, DetectionReview

class DetectionAIEngine:
    def __init__(self, db: Session):
        self.db = db

    def suggest_rule(self, technique_id: str, rule_type: str = "SIGMA") -> DetectionSuggestion:
        suggested_content = ""
        if rule_type.upper() == "SIGMA":
            suggested_content = f"""title: Detection for {technique_id}
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains: '{technique_id}'
    condition: selection"""
        else:
            suggested_content = f"""rule Yara_{technique_id} {{
    meta:
        description = "Detects files matching {technique_id}"
    strings:
        $s1 = "{technique_id}"
    condition:
        $s1
}}"""

        suggestion = DetectionSuggestion(
            technique_id=technique_id,
            rule_type=rule_type.upper(),
            suggested_rule=suggested_content,
            confidence_score=85.0,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(suggestion)
        self.db.commit()
        self.db.refresh(suggestion)
        return suggestion

    def review_suggestion(self, suggestion_id: int, reviewer: str, status: str) -> DetectionReview:
        sug = self.db.query(DetectionSuggestion).filter(DetectionSuggestion.id == suggestion_id).first()
        if not sug:
            raise ValueError("Suggestion not found")

        review = DetectionReview(
            suggestion_id=suggestion_id,
            review_status=status.upper(),
            reviewer=reviewer,
            reviewed_at=datetime.datetime.utcnow()
        )
        self.db.add(review)
        self.db.commit()
        self.db.refresh(review)
        return review
