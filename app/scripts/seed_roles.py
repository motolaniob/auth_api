from app.models.role import Role
from app.database import get_db
from sqlalchemy.orm import Session

db = get_db()
current_roles = db.query(Role).all()
if not current_roles:
    roles_to_seed = [
        Role(name="admin", description="Administrator role with full access"),
        Role(name="user", description="Regular user role with limited access"),
    ]
    db.add_all(roles_to_seed)
    db.commit()
    print("Roles seeded successfully.")