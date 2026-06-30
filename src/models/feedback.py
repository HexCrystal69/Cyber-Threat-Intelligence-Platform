import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from src.database import Base

class AlertFeedback(Base):
    __tablename__ = "alert_feedback"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
    analyst_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    feedback_type = Column(String, nullable=False)  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, DUPLICATE
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
