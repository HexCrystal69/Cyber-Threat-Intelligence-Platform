import datetime
import logging
from sqlalchemy.orm import Session
from src.models.alert import SecurityAlert, AlertEvidence, AlertScoreHistory
from src.models.ioc import IOC
from src.models.score import ThreatScoreSnapshot
from src.models.campaign import CampaignIOC, ThreatCampaign

logger = logging.getLogger(__name__)

class AlertEngine:
    def __init__(self, db: Session):
        self.db = db

    def trigger_alerts_for_ioc(self, ioc_id: int) -> SecurityAlert | None:
        ioc = self.db.query(IOC).filter(IOC.id == ioc_id).first()
        if not ioc:
            return None

        # Fetch latest ThreatScoreSnapshot
        snap = self.db.query(ThreatScoreSnapshot).filter(
            ThreatScoreSnapshot.ioc_id == ioc_id
        ).order_by(ThreatScoreSnapshot.snapshot_at.desc()).first()

        risk = snap.risk_score if snap else 50
        
        severity_map = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10}
        sev_val = severity_map.get(ioc.severity.upper(), 50)
        
        confidence = ioc.confidence_score
        
        camp_score = 0
        camp_ioc = self.db.query(CampaignIOC).filter(CampaignIOC.ioc_id == ioc_id).first()
        if camp_ioc:
            camp = self.db.query(ThreatCampaign).filter(ThreatCampaign.id == camp_ioc.campaign_id).first()
            if camp:
                camp_score = camp.confidence_score

        # Alert Score Formula
        alert_score = int(
            (0.35 * risk) +
            (0.30 * sev_val) +
            (0.20 * confidence) +
            (0.15 * camp_score)
        )

        # Decide Severity & Priority
        alert_severity = ioc.severity
        alert_priority = "MEDIUM"
        if alert_score >= 80:
            alert_priority = "URGENT"
        elif alert_score >= 60:
            alert_priority = "HIGH"

        # Create SecurityAlert
        alert = SecurityAlert(
            title=f"Threat Detection Alert: IOC {ioc.indicator_value}",
            severity=alert_severity,
            priority=alert_priority,
            status="NEW",
            confidence_score=confidence,
            risk_score=alert_score
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)

        # Save AlertEvidence
        evidence = AlertEvidence(
            alert_id=alert.id,
            evidence_type="IOC",
            evidence_id=str(ioc_id),
            evidence_summary=f"Indicator value {ioc.indicator_value} ({ioc.indicator_type}) triggered threat match with risk score {risk}."
        )
        self.db.add(evidence)

        # Log AlertScoreHistory
        hist = AlertScoreHistory(
            alert_id=alert.id,
            old_score=0,
            new_score=alert_score,
            reason="Initial alert generation calculation"
        )
        self.db.add(hist)
        self.db.commit()

        logger.info(f"Generated alert {alert.id} for IOC {ioc_id} with score {alert_score}")
        return alert

    def update_alert_score(self, alert_id: int, new_score: int, reason: str):
        alert = self.db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            old = alert.risk_score
            alert.risk_score = new_score
            
            hist = AlertScoreHistory(
                alert_id=alert_id,
                old_score=old,
                new_score=new_score,
                reason=reason
            )
            self.db.add(hist)
            self.db.commit()
