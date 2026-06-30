import datetime
from sqlalchemy.orm import Session
from src.models.ai_usage import AIUsageSnapshot, UserAIUsage

class AIUsageEngine:
    def __init__(self, db: Session):
        self.db = db

    def record_usage(self, user_id: int, model_name: str, tokens_in: int, tokens_out: int) -> dict:
        cost_per_million_in = 2.50
        cost_per_million_out = 10.00
        cost = ((tokens_in * cost_per_million_in) + (tokens_out * cost_per_million_out)) / 1000000.0

        user_usage = self.db.query(UserAIUsage).filter(UserAIUsage.user_id == user_id).first()
        if not user_usage:
            user_usage = UserAIUsage(
                user_id=user_id,
                tokens_used=tokens_in + tokens_out,
                estimated_cost=cost,
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(user_usage)
        else:
            user_usage.tokens_used += (tokens_in + tokens_out)
            user_usage.estimated_cost += cost

        model_usage = self.db.query(AIUsageSnapshot).filter(AIUsageSnapshot.model_name == model_name).first()
        if not model_usage:
            model_usage = AIUsageSnapshot(
                model_name=model_name,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                estimated_cost=cost,
                request_count=1,
                snapshot_at=datetime.datetime.utcnow()
            )
            self.db.add(model_usage)
        else:
            model_usage.tokens_in += tokens_in
            model_usage.tokens_out += tokens_out
            model_usage.estimated_cost += cost
            model_usage.request_count += 1
            model_usage.snapshot_at = datetime.datetime.utcnow()

        self.db.commit()
        return {"estimated_cost": cost}
