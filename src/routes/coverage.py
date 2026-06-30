from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.coverage import CoverageMatrix
from src.models.purple_team import CoverageGap

router = APIRouter(prefix="/coverage", tags=["Detection Coverage"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("", status_code=status.HTTP_200_OK)
def get_coverage_matrix(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(CoverageMatrix).all()

@router.get("/gaps", status_code=status.HTTP_200_OK)
def list_coverage_gaps(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(CoverageGap).all()
