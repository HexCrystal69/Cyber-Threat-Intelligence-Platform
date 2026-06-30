import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from src.database import Base

class PromptTemplate(Base):
    __tablename__ = "prompt_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    version = Column(String, nullable=False)
    template_text = Column(Text, nullable=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class CopilotSession(Base):
    __tablename__ = "copilot_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    title = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class CopilotMessage(Base):
    __tablename__ = "copilot_messages"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("copilot_sessions.id"), nullable=False)
    role = Column(String, nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    token_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class CopilotResponse(Base):
    __tablename__ = "copilot_responses"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("copilot_sessions.id"), nullable=False)
    prompt_template_id = Column(Integer, ForeignKey("prompt_templates.id"), nullable=True)
    response_text = Column(Text, nullable=False)
    confidence_score = Column(Integer, default=50)
    validation_status = Column(String, default="PENDING")  # PENDING, PASS, REVIEW_REQUIRED, FAIL
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
