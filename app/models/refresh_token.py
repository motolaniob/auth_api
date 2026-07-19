from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import UUID as pyUUID
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, text
from .associations import user_roles
from ..database import Base

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default= text("gen_random_uuid()"))
    user_id: Mapped[pyUUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"),index = True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    revoked: Mapped[bool] = mapped_column(nullable=False, default = False)
    device_info: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
    