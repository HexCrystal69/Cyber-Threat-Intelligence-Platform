import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from src.database import Base

class AutomatedResponse(Base):
    __tablename__ = "automated_responses"

    id = Column(Integer, primary_key=True, index=True)
    response_type = Column(String, nullable=False)  # CONTAINMENT, BLOCK_IOC, ESCALATION, etc.
    severity = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id = Column(Integer, primary_key=True, index=True)
    response_id = Column(Integer, ForeignKey("automated_responses.id"), nullable=True)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED, PENDING_APPROVAL, ROLLED_BACK
    target_type = Column(String, nullable=False)  # ALERT, IOC
    target_id = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

class ResponseApproval(Base):
    __tablename__ = "response_approvals"

    id = Column(Integer, primary_key=True, index=True)
    response_execution_id = Column(Integer, ForeignKey("response_executions.id"), nullable=False)
    approver = Column(String, nullable=True)
    approval_status = Column(String, default="PENDING")  # PENDING, APPROVED, REJECTED
    approved_at = Column(DateTime, nullable=True)

class ResponseRollback(Base):
    __tablename__ = "response_rollbacks"

    id = Column(Integer, primary_key=True, index=True)
    response_execution_id = Column(Integer, ForeignKey("response_executions.id"), nullable=False)
    rollback_status = Column(String, nullable=False)  # PENDING, SUCCESS, FAILED
    rollback_details = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class ResponseOutcome(Base):
    __tablename__ = "response_outcomes"

    id = Column(Integer, primary_key=True, index=True)
    response_execution_id = Column(Integer, ForeignKey("response_executions.id"), nullable=False)
    success = Column(Boolean, nullable=False)
    execution_time_ms = Column(Integer, nullable=False)
    alerts_resolved = Column(Integer, default=0)
    cases_created = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SOARAction(Base):
    __tablename__ = "soar_actions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    category = Column(String, nullable=False)  # ENRICHMENT, BLOCKING, ESCALATION, HUNTING, NOTIFICATION
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class AutomationPlaybook(Base):
    __tablename__ = "automation_playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class AutomationPlaybookStep(Base):
    __tablename__ = "automation_playbook_steps"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("automation_playbooks.id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    soar_action_id = Column(Integer, ForeignKey("soar_actions.id"), nullable=False)
    configuration_json = Column(Text, nullable=True)

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("automation_playbooks.id"), nullable=False)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    target_type = Column(String, nullable=False)
    target_id = Column(String, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
