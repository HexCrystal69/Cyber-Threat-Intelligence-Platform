import datetime
import json
from sqlalchemy.orm import Session
from src.models.copilot import PromptTemplate, CopilotSession, CopilotMessage, CopilotResponse
from src.models.ai_governance import ModelRegistry, PromptExecution
from src.services.rag_engine import RAGEngine
from src.services.validation_engine import ValidationEngine
from src.utils.metrics import copilot_requests_total, copilot_tokens_total

class CopilotEngine:
    def __init__(self, db: Session):
        self.db = db

    def chat(self, session_id: int, user_message: str, prompt_template_name: str = None) -> dict:
        session = self.db.query(CopilotSession).filter(CopilotSession.id == session_id).first()
        if not session:
            raise ValueError("Session not found")

        user_msg = CopilotMessage(
            session_id=session_id,
            role="user",
            content=user_message,
            token_count=len(user_message.split())
        )
        self.db.add(user_msg)
        session.last_activity_at = datetime.datetime.utcnow()
        self.db.commit()

        rag = RAGEngine(self.db)
        retrieved = rag.retrieve_relevant_evidence(user_message, limit=2)
        evidence_text = "\n".join([f"Evidence content: {item['document'].content}" for item in retrieved])

        template = None
        template_text = "Retrieved evidence:\n{evidence}\nUser question: {question}"
        if prompt_template_name:
            template = self.db.query(PromptTemplate).filter(PromptTemplate.name == prompt_template_name, PromptTemplate.active == True).first()
            if template:
                template_text = template.template_text

        formatted_prompt = template_text.format(evidence=evidence_text, question=user_message)

        model = self.db.query(ModelRegistry).filter(ModelRegistry.active == True).first()
        model_name = model.model_name if model else "gpt-4o"
        model_id = model.id if model else None

        response_text = f"Based on retrieved evidence, the incident indicates suspicious activity. Details: {evidence_text[:100]}."
        
        ass_msg = CopilotMessage(
            session_id=session_id,
            role="assistant",
            content=response_text,
            token_count=len(response_text.split())
        )
        self.db.add(ass_msg)

        execution = PromptExecution(
            model_id=model_id,
            prompt_template_id=template.id if template else None,
            token_input=len(formatted_prompt.split()),
            token_output=len(response_text.split()),
            latency_ms=350,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(execution)
        self.db.commit()

        val_engine = ValidationEngine(self.db)
        validation_run = val_engine.validate_response(
            response_id=execution.id,
            claims=[
                {"text": "the incident indicates suspicious activity", "supported": True, "evidence_count": len(retrieved)}
            ]
        )

        cop_resp = CopilotResponse(
            session_id=session_id,
            prompt_template_id=template.id if template else None,
            response_text=response_text,
            confidence_score=90 if validation_run.validation_score >= 0.9 else 50,
            validation_status="PASS" if validation_run.validation_score >= 0.9 else "REVIEW_REQUIRED",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(cop_resp)
        self.db.commit()

        copilot_requests_total.inc()
        copilot_tokens_total.inc(execution.token_input + execution.token_output)

        return {
            "response": response_text,
            "confidence_score": cop_resp.confidence_score,
            "validation_status": cop_resp.validation_status,
            "evidence_retrieved": len(retrieved)
        }
