import datetime
from sqlalchemy import Column, Integer, String, DateTime
from src.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)  # Store user ID or system identifier
    action = Column(String, nullable=False)  # CREATE, UPDATE, DELETE, etc.
    resource_type = Column(String, nullable=False)  # USER, IOC, FEED, JOB, etc.
    resource_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
