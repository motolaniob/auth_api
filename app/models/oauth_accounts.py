from uuid import UUID as pyUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Boolean, DateTime, ForeignKey, text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from app.database import Base

class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True),primary_key=True,server_default=text("gen_random_uuid()"))
    user_id: Mapped[pyUUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"),nullable=False)
    provider: Mapped[str] = mapped_column(String(50),nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),server_default=text("now()"))

    # Unique constraint on provide and provider user id to prevent duplicate links
    __table_args__ = (UniqueConstraint("provider","provider_user_id", name="unique_provider_user_id"),)