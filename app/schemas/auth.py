from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from uuid import UUID

class Token(BaseModel):
    access_token: str = Field(examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])
    token_type: str = Field(default="bearer")
    refresh_token: str = Field(examples=["k7Jd9xQmP2vN8rT4wL1yB6hZ3sC5aF0e..."])

class LoginRequest(BaseModel):
    email: EmailStr = Field(examples=["jane.doe@example.com"])
    password: str = Field(examples=["correct-horse-battery-staple"])

class RefreshRequest(BaseModel):
    refresh_token: str = Field(examples=["k7Jd9xQmP2vN8rT4wL1yB6hZ3sC5aF0e..."])

class ResendVerificationRequest(BaseModel):
    email: EmailStr  = Field(examples=["jane.doe@example.com"])

class ForgotPasswordRequest(BaseModel):
    email: EmailStr  = Field(examples=["jane.doe@example.com"])

class ResetPasswordRequest(BaseModel):
    token: str = Field(examples=["a1B2c3D4e5F6..."])
    new_password: str = Field(examples=["new-correct-horse-battery"])

class MFADisableRequest(BaseModel):
    code: str = Field(examples=["123456"])

class MFAChallengeResponse(BaseModel):
    mfa_required: bool = True
    challenge_token: str = Field(examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])

class MFAVerifyRequest(BaseModel):
    code: str = Field(examples=["123456"])

class MFALoginVerifyRequest(BaseModel):
    challenge_token: str = Field(examples=["eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."])
    code: str = Field(examples=["123456"])

class SessionOut(BaseModel):
    id: UUID = Field(examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"])
    created_at: datetime
    expires_at: datetime
    device_info: str | None = Field(examples=["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"])

    model_config = ConfigDict(from_attributes=True)

class MessageResponse(BaseModel):
    message: str = Field(examples=["Email verified successfully"])

class MFASetupResponse(BaseModel):
    secret: str = Field(examples=["JBSWY3DPEHPK3PXP"])
    recovery_codes: list[str] = Field(examples=[["a1b2c3d4e5", "f6g7h8i9j0"]])
    provisioning_url: str = Field(examples=["otpauth://totp/AUTH_API:jane.doe@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AUTH_API"])