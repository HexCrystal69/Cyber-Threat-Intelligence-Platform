from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from src.database import get_db
from src.models.user import User
from src.schemas.user import UserCreate, UserResponse, Token
from src.security.auth import hash_password, verify_password, create_access_token
from src.services.audit import log_audit

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    
    # Hash password and save user
    hashed = hash_password(user_in.password)
    user = User(
        email=user_in.email,
        hashed_password=hashed,
        role=user_in.role.upper() if user_in.role else "VIEWER"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Log audit event
    log_audit(db, user.id, "REGISTER", "USER", str(user.id))

    return user

@router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )
    
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role}
    )
    
    # Log audit event
    log_audit(db, user.id, "LOGIN", "USER", str(user.id))

    return {"access_token": access_token, "token_type": "bearer"}
