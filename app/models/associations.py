from sqlalchemy import Table, Column, ForeignKey
from ..database import Base


user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete = "CASCADE"), primary_key = True),
    Column("role_id", ForeignKey("roles.id", ondelete = "RESTRICT"), primary_key = True)

)