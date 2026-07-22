from pydantic import BaseModel, EmailStr, Field, field_validator
from uuid import UUID
from datetime import datetime
from app.core.security import check_password_breach

class UserCreate(BaseModel):
    email: EmailStr
    password: str    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if check_password_breach(v) > 0:
            raise ValueError('Password has been breached')
        return v
    
class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True