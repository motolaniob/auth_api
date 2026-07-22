from fastapi import FastAPI
from app.routers import auth as auth_router
app = FastAPI()
app.include_router(auth_router.router, prefix="/auth", tags=["auth"])

@app.get("/health")
def health_check():
    return {"status": "healthy"}