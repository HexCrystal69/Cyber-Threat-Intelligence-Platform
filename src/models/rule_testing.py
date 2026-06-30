import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from src.database import Base

class RuleTestCase(Base):
    __tablename__ = "rule_test_cases"

    id = Column(Integer, primary_key=True, index=True)
    detection_rule_id = Column(Integer, nullable=False, index=True)
    test_name = Column(String, nullable=False)
    input_event_json = Column(Text, nullable=False)
    expected_match = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class RuleTestExecution(Base):
    __tablename__ = "rule_test_executions"

    id = Column(Integer, primary_key=True, index=True)
    rule_test_case_id = Column(Integer, ForeignKey("rule_test_cases.id"), nullable=False)
    status = Column(String, nullable=False)  # PASSED, FAILED, ERROR
    actual_match = Column(Boolean, nullable=True)
    execution_time_ms = Column(Integer, default=0, nullable=False)
    executed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
