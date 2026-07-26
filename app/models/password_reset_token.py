from uuid import UUID as pyUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean, DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from app.database import Base

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default= text("gen_random_uuid()"))
    user_id : Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash : Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    is_used : Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    expires_at : Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)