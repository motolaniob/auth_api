from fastapi import FastAPI
from app.routers import auth as auth_router
from app.routers import users as users_router
from app.routers import admin as admin_router
app = FastAPI()


app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(users_router.router, prefix="/users", tags=["users"])
app.include_router(admin_router.router, prefix="/admin", tags=["admin"])
@app.get("/health")
def health_check():
    return {"status": "healthy"}