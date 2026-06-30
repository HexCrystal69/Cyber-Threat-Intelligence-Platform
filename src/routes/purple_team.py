from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.purple_team import AttackSimulation, SimulationResult, CoverageGap
from src.services.purple_team_engine import PurpleTeamEngine

router = APIRouter(prefix="/purple", tags=["Purple Team Operations"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/simulations", status_code=status.HTTP_202_ACCEPTED)
def run_simulation(technique_id: str, simulation_name: str, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    from src.tasks.purple_team_tasks import execute_attack_simulation
    task = execute_attack_simulation.delay(technique_id, simulation_name)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/results", status_code=status.HTTP_200_OK)
def list_results(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SimulationResult).all()

@router.get("/gaps", status_code=status.HTTP_200_OK)
def list_gaps(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(CoverageGap).all()
