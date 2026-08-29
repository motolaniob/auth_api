from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from uuid import UUID
from datetime import datetime
from app.core.security import check_password_breach

class UserCreate(BaseModel):
    email: EmailStr = Field(examples=["jane.doe@example.com"])
    password: str = Field(examples=["correct-horse-battery-staple"])
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if check_password_breach(v) > 0:
            raise ValueError('Password has been breached')
        return v
    
class UserResponse(BaseModel):
    id: UUID = Field(examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"])
    email: EmailStr = Field(examples=["jane.doe@example.com"])
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_verified: bool

    model_config = ConfigDict(from_attributes=True)