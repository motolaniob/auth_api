from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import UUID as pyUUID
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, text
from .associations import user_roles
from ..database import Base

class Role(Base):
    __tablename__ = "roles"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default= text("gen_random_uuid()"))
    name: Mapped[str] = mapped_column(String(10), unique=True, nullable=False, index = True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate= lambda: datetime.now(timezone.utc), server_default=text("now()"))
    users: Mapped[list["User"]] = relationship(back_populates="roles", secondary=user_roles)

