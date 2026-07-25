from fastapi import APIRouter, Depends
from app.models.users import User
from app.schemas.user import UserResponse
from app.core.dependencies import get_current_user

router = APIRouter()

@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    """
    Get the current authenticated user.
    """
    return current_user