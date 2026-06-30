import datetime
from sqlalchemy.orm import Session
from src.models.hunting_ai import NaturalLanguageQuery, QueryTranslationAudit

class QueryTranslationEngine:
    def __init__(self, db: Session):
        self.db = db

    def translate_query(self, nl_query: str) -> dict:
        query_words = nl_query.lower().split()
        
        target_type = "IP"
        if "domain" in query_words or "domains" in query_words:
            target_type = "DOMAIN"
        elif "hash" in query_words:
            target_type = "HASH_MD5"

        associated_campaign = "Unknown"
        for i, w in enumerate(query_words):
            if w in ("associated", "with", "campaign", "actor") and i + 1 < len(query_words):
                associated_campaign = query_words[i+1].upper()

        sql_output = f"SELECT * FROM iocs WHERE indicator_type = '{target_type}' AND campaign = '{associated_campaign}'"

        nlq = NaturalLanguageQuery(
            user_query=nl_query,
            generated_query=sql_output,
            execution_status="SUCCESS",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(nlq)
        self.db.commit()
        self.db.refresh(nlq)

        audit = QueryTranslationAudit(
            nl_query_id=nlq.id,
            confidence_score=95.0 if associated_campaign != "Unknown" else 60.0,
            validation_status="PASS" if associated_campaign != "Unknown" else "FAIL",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(audit)
        self.db.commit()

        return {"generated_query": sql_output, "audit_status": audit.validation_status}
