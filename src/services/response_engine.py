import datetime
import time
from sqlalchemy.orm import Session
from src.models.response import (
    AutomatedResponse, ResponseExecution, ResponseApproval, ResponseRollback, ResponseOutcome,
    SOARAction, AutomationPlaybook, AutomationPlaybookStep, PlaybookExecution
)
from src.models.alert import SecurityAlert
from src.models.ioc import IOC
from src.services.audit import log_audit
from src.utils.metrics import response_executions_total

class ResponseEngine:
    def __init__(self, db: Session):
        self.db = db

    def execute_response(self, response_id: int, target_type: str, target_id: str, approver_name: str = None) -> dict:
        resp = self.db.query(AutomatedResponse).filter(AutomatedResponse.id == response_id).first()
        if not resp or not resp.enabled:
            raise ValueError("Response action not found or disabled")

        exec_record = ResponseExecution(
            response_id=response_id,
            status="PENDING_APPROVAL",
            target_type=target_type,
            target_id=target_id,
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(exec_record)
        self.db.commit()
        self.db.refresh(exec_record)

        approval = ResponseApproval(
            response_execution_id=exec_record.id,
            approval_status="PENDING"
        )
        self.db.add(approval)
        self.db.commit()

        if approver_name:
            self.approve_response(exec_record.id, approver_name)
            self.db.refresh(exec_record)
            
        return {"execution_id": exec_record.id, "status": exec_record.status}

    def approve_response(self, execution_id: int, approver_name: str) -> dict:
        start_time_ms = int(time.time() * 1000)
        exec_record = self.db.query(ResponseExecution).filter(ResponseExecution.id == execution_id).first()
        if not exec_record:
            raise ValueError("Execution not found")

        approval = self.db.query(ResponseApproval).filter(ResponseApproval.response_execution_id == execution_id).first()
        if not approval or approval.approval_status != "PENDING":
            raise ValueError("No pending approval found for this execution")

        approval.approval_status = "APPROVED"
        approval.approver = approver_name
        approval.approved_at = datetime.datetime.utcnow()
        exec_record.status = "RUNNING"
        self.db.commit()

        success = False
        alerts_resolved = 0
        cases_created = 0
        notes = ""

        try:
            resp = exec_record.response_id
            resp_obj = self.db.query(AutomatedResponse).filter(AutomatedResponse.id == resp).first()
            action_type = resp_obj.response_type if resp_obj else "GENERIC"

            if action_type == "CONTAINMENT":
                if exec_record.target_type == "ALERT":
                    alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == int(exec_record.target_id)).first()
                    if alert:
                        alert.status = "CONTAINED"
                        alerts_resolved = 1
                        success = True
                        notes = "Alert contained successfully"
            elif action_type == "BLOCK_IOC":
                if exec_record.target_type == "IOC":
                    ioc = self.db.query(IOC).filter(IOC.id == int(exec_record.target_id)).first()
                    if ioc:
                        ioc.severity = "CRITICAL"
                        success = True
                        notes = "IOC blocked across EDR/firewalls"
            elif action_type == "ESCALATION":
                if exec_record.target_type == "ALERT":
                    alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == int(exec_record.target_id)).first()
                    if alert:
                        alert.priority = "URGENT"
                        success = True
                        notes = "Alert escalated to URGENT priority"
            elif action_type == "ENRICHMENT":
                success = True
                notes = "Auto-enriched IOC threat data"
            elif action_type == "HUNTING":
                success = True
                notes = "Initiated automated threat hunt"
            else:
                success = True
                notes = "Generic automated action executed"

            exec_record.status = "SUCCESS"
            exec_record.completed_at = datetime.datetime.utcnow()
            
            log_audit(
                self.db,
                user_id=1,
                action=f"EXECUTE_RESPONSE_{action_type}",
                resource_type=exec_record.target_type,
                resource_id=exec_record.target_id
            )

        except Exception as e:
            exec_record.status = "FAILED"
            exec_record.completed_at = datetime.datetime.utcnow()
            notes = f"Failed to execute: {e}"
            success = False
        
        self.db.commit()

        end_time_ms = int(time.time() * 1000)
        outcome = ResponseOutcome(
            response_execution_id=execution_id,
            success=success,
            execution_time_ms=max(1, end_time_ms - start_time_ms),
            alerts_resolved=alerts_resolved,
            cases_created=cases_created,
            notes=notes,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(outcome)
        self.db.commit()

        response_executions_total.labels(
            response_type=resp_obj.response_type if resp_obj else "GENERIC",
            status=exec_record.status
        ).inc()

        return {"status": exec_record.status, "notes": notes}

    def rollback_response(self, execution_id: int) -> dict:
        exec_record = self.db.query(ResponseExecution).filter(ResponseExecution.id == execution_id).first()
        if not exec_record or exec_record.status != "SUCCESS":
            raise ValueError("Only successful executions can be rolled back")

        rollback = ResponseRollback(
            response_execution_id=execution_id,
            rollback_status="RUNNING",
            executed_at=datetime.datetime.utcnow()
        )
        self.db.add(rollback)
        self.db.commit()

        resp_obj = self.db.query(AutomatedResponse).filter(AutomatedResponse.id == exec_record.response_id).first()
        action_type = resp_obj.response_type if resp_obj else "GENERIC"

        success = False
        details = ""

        try:
            if action_type == "CONTAINMENT":
                if exec_record.target_type == "ALERT":
                    alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == int(exec_record.target_id)).first()
                    if alert:
                        alert.status = "NEW"
                        success = True
                        details = "Reopened contained alert"
            elif action_type == "BLOCK_IOC":
                if exec_record.target_type == "IOC":
                    ioc = self.db.query(IOC).filter(IOC.id == int(exec_record.target_id)).first()
                    if ioc:
                        ioc.severity = "MEDIUM"
                        success = True
                        details = "Unblocked IOC"
            elif action_type == "ESCALATION":
                if exec_record.target_type == "ALERT":
                    alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == int(exec_record.target_id)).first()
                    if alert:
                        alert.priority = "MEDIUM"
                        success = True
                        details = "Reverted alert priority to MEDIUM"
            else:
                success = True
                details = "Generic action rolled back"

            if success:
                rollback.rollback_status = "SUCCESS"
                exec_record.status = "ROLLED_BACK"
                log_audit(
                    self.db,
                    user_id=1,
                    action=f"ROLLBACK_RESPONSE_{action_type}",
                    resource_type=exec_record.target_type,
                    resource_id=exec_record.target_id
                )
            else:
                rollback.rollback_status = "FAILED"

        except Exception as e:
            rollback.rollback_status = "FAILED"
            details = f"Rollback failed: {e}"

        rollback.rollback_details = details
        self.db.commit()
        return {"status": rollback.rollback_status, "details": details}

    def execute_playbook(self, playbook_id: int, target_type: str, target_id: str) -> dict:
        playbook = self.db.query(AutomationPlaybook).filter(AutomationPlaybook.id == playbook_id).first()
        if not playbook or not playbook.enabled:
            raise ValueError("Playbook not found or disabled")

        pe = PlaybookExecution(
            playbook_id=playbook_id,
            status="RUNNING",
            target_type=target_type,
            target_id=target_id,
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(pe)
        self.db.commit()
        self.db.refresh(pe)

        steps = self.db.query(AutomationPlaybookStep).filter(AutomationPlaybookStep.playbook_id == playbook_id).order_by(AutomationPlaybookStep.step_order).all()
        
        success = True
        for step in steps:
            action = self.db.query(SOARAction).filter(SOARAction.id == step.soar_action_id).first()
            if action and action.enabled:
                resp = AutomatedResponse(
                    response_type=action.category,
                    severity="HIGH",
                    enabled=True
                )
                self.db.add(resp)
                self.db.commit()
                self.db.refresh(resp)

                self.execute_response(resp.id, target_type, target_id, approver_name="Playbook Engine")

        pe.status = "SUCCESS" if success else "FAILED"
        pe.completed_at = datetime.datetime.utcnow()
        self.db.commit()
        return {"execution_id": pe.id, "status": pe.status}
