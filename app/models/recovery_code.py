from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import UUID as pyUUID
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, text
from .associations import user_roles
from ..database import Base

class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default = text("gen_random_uuid()"))
    user_id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable = False)
    code_hash:Mapped[str] = mapped_column
    is_used:
    created_at: