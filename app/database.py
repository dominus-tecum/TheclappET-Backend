# app/database.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path

# Import the SINGLE, SHARED Base that ALL models use
from app.database_base import Base

# ========== ENVIRONMENT-BASED DATABASE SELECTION ==========
def get_database_url():
    """Determine database file based on environment"""
    environment = os.getenv("ENVIRONMENT", "development").lower()
    
    if environment == "production":
        return "sqlite:////dominusvobiscum/hospiapp_et.db"
    elif environment == "staging":
        return "sqlite:///./hospiapp_staging.db"
    else:  # development
        return "sqlite:///./hospiapp_et.db"

DATABASE_URL = get_database_url()
# ===========================================================

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ========== IMPORT ALL MODELS THAT USE THIS BASE ==========
# 1. Core models (User, Prescription, Appointment)
from app.models import User, Prescription, Appointment

# 2. Fertility models
from app.fertility.models import Patient, FertilityEntry, FertilityProfile, CycleAnalysis, FertilityInsight

# 3. Security models
from app.security.models import SecurityEvent  # ✅ CORRECT PLACE

# 4. Add other models as needed:
# from app.medical_record.models import MedicalRecord
# ===========================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables for ALL imported models
environment = os.getenv("ENVIRONMENT", "development").lower()
Base.metadata.create_all(bind=engine)
print(f"✅ [{environment.upper()}] Database initialized: {DATABASE_URL}")
print(f"   Tables: {list(Base.metadata.tables.keys())}")