from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from uuid import uuid4
from datetime import datetime
from ..database import Base
from sqlalchemy import String, DateTime, ForeignKey, text