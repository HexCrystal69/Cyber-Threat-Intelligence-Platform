import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from src.database import Base

class AnalystAction(Base):
    __tablename__ = "analyst_actions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String, nullable=False)  # ALERT_ACKNOWLEDGED, CASE_ASSIGNED, CASE_ESCALATED, ALERT_DISMISSED
    target_type = Column(String, nullable=False)  # ALERT, CASE
    target_id = Column(String, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
