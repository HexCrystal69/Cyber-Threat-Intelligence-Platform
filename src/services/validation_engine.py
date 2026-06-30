import datetime
from sqlalchemy.orm import Session
from src.models.ai_governance import AIValidationRun
from src.models.ai_validation import ClaimValidation
from src.utils.metrics import ai_validation_runs_total, ai_supported_claims_total, ai_unsupported_claims_total

class ValidationEngine:
    def __init__(self, db: Session):
        self.db = db

    def validate_response(self, response_id: int, claims: list) -> AIValidationRun:
        supported = sum(1 for c in claims if c.get("supported") is True)
        unsupported = sum(1 for c in claims if c.get("supported") is False)
        total = len(claims)

        score = (supported / total) if total > 0 else 1.0

        run = AIValidationRun(
            response_id=response_id,
            supported_claims=supported,
            unsupported_claims=unsupported,
            validation_score=score,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        # Log individual ClaimValidation entries
        for c in claims:
            cv = ClaimValidation(
                validation_run_id=run.id,
                claim_text=c.get("text"),
                supported=c.get("supported", True),
                supporting_evidence_count=c.get("evidence_count", 0),
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(cv)

        self.db.commit()
        ai_validation_runs_total.inc()
        ai_supported_claims_total.inc(supported)
        ai_unsupported_claims_total.inc(unsupported)

        return run
