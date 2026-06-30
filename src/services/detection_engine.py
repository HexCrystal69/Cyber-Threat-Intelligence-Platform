import datetime
import uuid
import logging
from sqlalchemy.orm import Session
from src.models.detection import DetectionRule, DetectionExecution, DetectionMatch
from src.models.ioc import IOC
from src.models.campaign import CampaignIOC, ThreatCampaign
from src.models.actor import ActorCampaign, ThreatActor

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db

    def execute_all_rules(self) -> str:
        exec_id = f"det_exec_{uuid.uuid4()}"
        rules = self.db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
        
        # We start an execution log
        execution = DetectionExecution(
            id=exec_id,
            detection_rule_id=1,  # fallback/dummy run header reference
            status="RUNNING",
            started_at=datetime.datetime.utcnow()
        )
        # Find if dummy rule exists or just map to first rule if any, else dummy
        if rules:
            execution.detection_rule_id = rules[0].id
        else:
            # Seed a dummy rule to avoid FK issue
            dummy = self.db.query(DetectionRule).first()
            if not dummy:
                dummy = DetectionRule(name="Default System Detection Rule", rule_type="CUSTOM", severity="MEDIUM")
                self.db.add(dummy)
                self.db.commit()
                self.db.refresh(dummy)
            execution.detection_rule_id = dummy.id

        self.db.add(execution)
        self.db.commit()

        matched_count = 0
        try:
            active_iocs = self.db.query(IOC).all()

            for rule in rules:
                for ioc in active_iocs:
                    is_match = False
                    evidence = {}
                    
                    if rule.rule_type == "YARA":
                        # Simulate YARA logic matching hex patterns or specific file hash structures
                        if ioc.indicator_type.startswith("HASH_") and len(ioc.indicator_value) in [32, 40, 64]:
                            is_match = True
                            evidence = {"yara_rule": rule.name, "matched_hash": ioc.indicator_value}
                    elif rule.rule_type == "SIGMA":
                        # Simulate Sigma log/behavior matching patterns (e.g. suspicious C2 domain strings)
                        if ioc.indicator_type in ["DOMAIN", "URL"] and any(x in ioc.indicator_value for x in ["evil", "malware", "phish", "c2"]):
                            is_match = True
                            evidence = {"sigma_rule": rule.name, "matched_pattern": ioc.indicator_value}
                    else: # CUSTOM
                        # Default matching e.g. severity threshold high
                        if ioc.severity == "CRITICAL" or ioc.confidence_score >= 80:
                            is_match = True
                            evidence = {"custom_rule": rule.name, "ioc_severity": ioc.severity, "confidence": ioc.confidence_score}

                    if is_match:
                        # Record match
                        match = DetectionMatch(
                            execution_id=exec_id,
                            ioc_id=ioc.id,
                            match_type=rule.rule_type,
                            evidence_json=evidence,
                            confidence_score=ioc.confidence_score
                        )
                        self.db.add(match)
                        matched_count += 1

            execution.status = "SUCCESS"
            execution.matched_records = matched_count
            execution.completed_at = datetime.datetime.utcnow()
            execution.execution_runtime_ms = 150.0  # mock execution time
            self.db.commit()
            return exec_id

        except Exception as e:
            logger.error(f"Detection execution {exec_id} failed: {e}")
            self.db.rollback()
            execution.status = "FAILED"
            execution.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise
