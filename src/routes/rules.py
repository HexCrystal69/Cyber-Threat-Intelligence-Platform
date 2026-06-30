from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.rule_testing import RuleTestCase, RuleTestExecution
from src.services.rule_testing_engine import RuleTestingEngine

router = APIRouter(prefix="/rules/tests", tags=["Detection Rule Verification"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", status_code=status.HTTP_200_OK)
def list_test_cases(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(RuleTestCase).all()

@router.post("/run", status_code=status.HTTP_200_OK)
def run_rule_test(test_case_id: int, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = RuleTestingEngine(db)
    try:
        res = engine.run_test_case(test_case_id)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
