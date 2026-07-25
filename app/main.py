from fastapi import FastAPI
from app.routers import auth as auth_router
from app.routers import users as users_router
app = FastAPI()


app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(users_router.router, prefix="/users", tags=["users"])

@app.get("/health")
def health_check():
    return {"status": "healthy"}