from sqlalchemy import create_engine, text
from app.config import settings
from sqlalchemy.orm import sessionmaker, DeclarativeBase 

DEBUG_MODE = settings.debug_mode
DB = settings.database_url
engine = create_engine(DB, echo=DEBUG_MODE)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()