from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class Token(BaseModel):
    access_token: str
    token_type: str = Field(default="bearer")
    refresh_token: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class ResendVerificationRequest(BaseModel):
    email: EmailStr

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class MFADisableRequest(BaseModel):
    code: str

class MFAChallengeResponse(BaseModel):
    mfa_required: bool = True
    challenge_token: str

class MFAVerifyRequest(BaseModel):
    code: str

class MFALoginVerifyRequest(BaseModel):
    challenge_token: str
    code: str

class SessionOut(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    device_info: str | None

    model_config = ConfigDict(form_attributes=True)