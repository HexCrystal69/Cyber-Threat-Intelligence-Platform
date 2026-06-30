from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.models.alert import SecurityAlert
from src.models.case import InvestigationCase
from src.models.dashboard import SocDashboardSnapshot
import datetime

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("/soc")
def get_soc_dashboard(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status.in_(["NEW", "OPEN"])).count()
    critical_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL").count()
    active_cases = db.query(InvestigationCase).filter(InvestigationCase.status.in_(["OPEN", "UNDER_INVESTIGATION"])).count()
    
    # Simple coverage check
    from src.models.detection import DetectionRule
    from src.models.attack import AttackTechnique, DetectionTechnique
    total_rules = db.query(DetectionRule).count()
    total_techniques = db.query(AttackTechnique).count()
    covered = db.query(DetectionTechnique.attack_technique_id).distinct().count()
    coverage_pct = (covered / total_techniques * 100.0) if total_techniques > 0 else 0.0

    snap = SocDashboardSnapshot(
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        active_cases=active_cases,
        mttr_hours=2.5,  # simulated metric
        mtta_minutes=15.0,  # simulated metric
        detection_coverage=coverage_pct
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)

    return snap
