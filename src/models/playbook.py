import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, JSON
from src.database import Base

class ResponsePlaybook(Base):
    __tablename__ = "response_playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    severity = Column(String, default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False)
    step_order = Column(Integer, nullable=False)
    action_type = Column(String, nullable=False)  # ENRICH, CORRELATE, ESCALATE, CASE_CREATE
    action_definition = Column(JSON, default=dict, nullable=False)
