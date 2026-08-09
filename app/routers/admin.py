from app.core.security import revoke_all_refresh_tokens, log_audit_event
from app.core.dependencies import require_role, require_verified
from app.models.role import Role
from app.models.users import User
from app.models.recovery_code import RecoveryCode
from app.schemas.user import UserResponse
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
import uuid

router = APIRouter()

@router.get("/users", response_model=list[UserResponse])
def list_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    return db.query(User).all()

@router.patch("/users/{user_id}/roles", response_model=UserResponse)
def update_user_roles(user_id:str, new_role_names:list[str], full_request: Request,db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")), _verified: User = Depends(require_verified)):
    """
    Update the roles of a user.
    """
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    old_roles = list(user.roles)
    # Fetch the new roles from the database
    new_roles = db.query(Role).filter(Role.name.in_(new_role_names)).all()
    
    if len(new_roles) != len(new_role_names):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more roles are invalid."
        )
    
    # Update the user's roles
    user.roles = new_roles
    db.commit()
    db.refresh(user)
    
    # Revoke all refresh tokens for the user
    revoke_all_refresh_tokens(user.id, db)
    log_audit_event(db, user.id, "role_changed", full_request.client.host, full_request.headers.get("user-agent") ,event_metadata= {"old_roles": [r.name for r in old_roles], "new_roles": new_role_names, "changed_by": str(current_user.id)})
    return user

@router.post("/users/{user_id}/mfa/disable")
def admin_disable_mfa(user_id: str, full_request: Request,current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id== uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail = "User not found."
        )
    user.mfa_enabled = False
    user.mfa_secret = None
    db.query(RecoveryCode).filter(RecoveryCode.user_id == uuid.UUID(user_id)).delete()
    db.commit()
    log_audit_event(db, user.id, "mfa_disabled_by_admin",  full_request.client.host, full_request.headers.get("user-agent") ,event_metadata = {"disabled_by_admin_id": str(current_user.id)})
    return {"message": "MFA is disabled"}