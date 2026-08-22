"""
FastAPI application entry point. Wires together the auth, users, and admin
routers, and seeds required role data on startup via the lifespan handler.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.routers import auth as auth_router
from app.routers import users as users_router
from app.routers import admin as admin_router
from app.database import SessionLocal
from app.models.role import Role

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensures the base "admin" and "user" roles exist on every app startup.
    # Idempotent — no-ops if roles are already present. Runs here rather than
    # as a separate manual script so a fresh database is always usable
    # immediately after the app starts (important for Docker deployments).
    db = SessionLocal()
    try:
        if not db.query(Role).first():
            db.add_all([
                Role(name="admin", description="Administrator role with full access"),
                Role(name="user", description="Regular user role with limited access"),
            ])
            db.commit()
    finally:
        db.close()
    yield
    # (no shutdown cleanup needed currently)



app = FastAPI(lifespan=lifespan)
app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(users_router.router, prefix="/users", tags=["users"])
app.include_router(admin_router.router, prefix="/admin", tags=["admin"])
@app.get("/health")
def health_check():
    return {"status": "healthy"}