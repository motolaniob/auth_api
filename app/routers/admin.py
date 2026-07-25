from app.core.security import revoke_all_refresh_tokens
from app.core.dependencies import require_role
from app.models.role import Role
from app.models.users import User
from app.schemas.user import UserResponse
from fastapi import APIRouter, Depends, HTTPException, status
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
def update_user_roles(user_id:str, new_role_names:list[str], db: Session = Depends(get_db), current_user: User = Depends(require_role("admin"))):
    """
    Update the roles of a user.
    """
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
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
    
    return user