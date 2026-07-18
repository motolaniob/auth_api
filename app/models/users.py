from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import UUID as pyUUID
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, text
from .associations import user_roles
from ..database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default= text("gen_random_uuid()"))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index = True)
    hashed_password: Mapped[str | None] = mapped_column(String(60), nullable=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    is_verified: Mapped[bool] = mapped_column(nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(nullable=False, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate= lambda: datetime.now(timezone.utc), server_default=text("now()"))
    roles: Mapped[list["Role"]] = relationship(back_populates="users", secondary=user_roles)
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")