from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.exposure import ThreatExposureSnapshot

router = APIRouter(prefix="/exposure", tags=["Threat Exposure Metrics"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", status_code=status.HTTP_200_OK)
def get_current_exposure(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    latest = db.query(ThreatExposureSnapshot).order_by(ThreatExposureSnapshot.snapshot_at.desc()).first()
    if not latest:
        # Default mock exposure dashboard response
        return {
            "critical_assets": 2,
            "high_risk_assets": 5,
            "active_campaigns": 1,
            "active_actors": 3,
            "critical_alerts": 4,
            "exposure_score": 42.5
        }
    return latest

@router.post("/snapshot", status_code=status.HTTP_200_OK)
def trigger_exposure_snapshot(db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    # Calculate: 0.30 * Asset Risk + 0.25 * Active Campaigns + 0.20 * Active Threat Actors + 0.15 * Critical Alerts + 0.10 * Detection Gaps
    from src.models.edr import EndpointAsset
    from src.models.campaign import ThreatCampaign
    from src.models.actor import ThreatActor
    from src.models.alert import SecurityAlert
    from src.models.purple_team import CoverageGap
    
    # Calculate averages
    assets = db.query(EndpointAsset).all()
    avg_asset_risk = sum(a.risk_score for a in assets) / len(assets) if assets else 25.0
    active_campaigns = db.query(ThreatCampaign).filter(ThreatCampaign.status == "ACTIVE").count()
    active_actors = db.query(ThreatActor).count()
    critical_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL").count()
    detection_gaps = db.query(CoverageGap).count()

    exposure_score = (
        0.30 * avg_asset_risk +
        0.25 * min(100, active_campaigns * 20) +
        0.20 * min(100, active_actors * 10) +
        0.15 * min(100, critical_alerts * 15) +
        0.10 * min(100, detection_gaps * 15)
    )

    import datetime
    snap = ThreatExposureSnapshot(
        critical_assets=sum(1 for a in assets if a.asset_criticality == "CRITICAL"),
        high_risk_assets=sum(1 for a in assets if a.risk_score > 70.0),
        active_campaigns=active_campaigns,
        active_actors=active_actors,
        critical_alerts=critical_alerts,
        exposure_score=round(exposure_score, 2),
        snapshot_at=datetime.datetime.utcnow()
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)
    return snap
