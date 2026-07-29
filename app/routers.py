from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import bcrypt
from . import models, schemas, database
from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel
from .authentication.auth import get_current_user
from app.models import User, UserRole, PatientDoctorAssignment, Organization, AuditLog
from app.utils.audit import log_audit
from app.database import get_db
import os
import base64
from fastapi import Form, UploadFile, File

router = APIRouter(dependencies=[])

# Direct bcrypt functions
def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode('utf-8')[:72]
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

# ========== MEDICAL RECORD SCHEMAS ==========

class MedicalRecordCreate(BaseModel):
    patient_id: int
    patient_name: str
    record_type: str
    title: str
    record_date: str
    status: str
    details: Dict[str, Any]
    doctor_name: Optional[str] = None

class MedicalRecordResponse(BaseModel):
    id: int
    patient_id: int
    patient_name: str
    doctor_id: Optional[int] = None
    doctor_name: Optional[str] = None
    record_type: str
    title: str
    record_date: str
    status: str
    details: Dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ========== USER REGISTRATION ==========

@router.post("/users/", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, request: Request, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash_password(user.password)
    new_user = models.User(
        username=user.username,
        name=user.name,
        email=user.email,
        password_hash=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit(
        db=db,
        user_id=None,
        username=user.username,
        user_role="PATIENT",
        action='REGISTER',
        resource_type='USER',
        resource_id=new_user.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )

    return new_user

# ========== MEDICAL RECORD ENDPOINTS ==========

@router.get("/patients/search")
def search_patients(
    q: str = "",
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(models.User).filter(models.User.role == UserRole.PATIENT)
    
    if q and len(q) >= 2:
        query = query.filter(
            (models.User.name.ilike(f"%{q}%")) | 
            (models.User.email.ilike(f"%{q}%"))
        )
    
    patients = query.limit(20).all()
    
    return {
        "patients": [
            {
                "id": p.id,
                "name": p.name,
                "email": p.email,
                "phone_number": p.phone_number
            }
            for p in patients
        ]
    }

@router.post("/medical-records", response_model=MedicalRecordResponse, status_code=201)
def create_medical_record(
    record: MedicalRecordCreate,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    patient = db.query(models.User).filter(
        models.User.id == record.patient_id, 
        models.User.role == UserRole.PATIENT
    ).first()
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    doctor = db.query(models.User).filter(models.User.id == current_user.id).first()
    
    db_record = models.MedicalRecord(
        patient_id=record.patient_id,
        patient_name=record.patient_name,
        doctor_id=doctor.id if doctor else None,
        doctor_name=record.doctor_name or (doctor.name if doctor else None),
        record_type=record.record_type,
        title=record.title,
        record_date=record.record_date,
        status=record.status,
        details=record.details
    )
    
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='CREATE',
        resource_type='MEDICAL_RECORD',
        resource_id=db_record.id,
        patient_id=record.patient_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return db_record

@router.get("/medical-records/patient/{patient_id}")
def get_patient_medical_records(
    patient_id: int,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    patient = db.query(models.User).filter(models.User.id == patient_id, models.User.role == UserRole.PATIENT).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    records = db.query(models.MedicalRecord).filter(
        models.MedicalRecord.patient_id == patient_id
    ).order_by(models.MedicalRecord.record_date.desc()).all()

    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='MEDICAL_RECORD',
        patient_id=patient_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {
        "patient": {
            "id": patient.id,
            "name": patient.name,
            "email": patient.email
        },
        "records": records,
        "total": len(records)
    }

@router.delete("/medical-records/{record_id}")
def delete_medical_record(
    record_id: int,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(models.MedicalRecord).filter(models.MedicalRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    
    deleted_patient_id = record.patient_id
    deleted_record_type = record.record_type
    deleted_title = record.title
    
    db.delete(record)
    db.commit()

    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='DELETE',
        resource_type='MEDICAL_RECORD',
        resource_id=record_id,
        patient_id=deleted_patient_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "Record deleted successfully"}

@router.get("/doctors/search")
def search_doctors(
    q: str = "",
    organization_id: int = None,
    request: Request = None,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(models.User).filter(models.User.role == UserRole.DOCTOR)
    
    # Filter by organization if provided
    if organization_id:
        query = query.filter(models.User.organization_id == organization_id)
    elif current_user.organization_id:
        query = query.filter(models.User.organization_id == current_user.organization_id)
    
    if q and len(q) >= 2:
        query = query.filter(
            (models.User.name.ilike(f"%{q}%")) | 
            (models.User.email.ilike(f"%{q}%"))
        )
    
    doctors = query.all()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='DOCTORS_SEARCH',
        status='success',
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get('user-agent') if request else None,
        new_value={
            "search_term": q,
            "organization_id": organization_id or current_user.organization_id,
            "results_count": len(doctors)
        }
    )
    
    return {
        "doctors": [
            {
                "id": d.id,
                "name": d.name,
                "email": d.email,
                "specialization": d.specialization,
                "department": d.department,
                "phone_number": d.phone_number,
                "is_active": d.is_active,
                "description": d.description,
                "education": d.education,
                "experience_years": d.experience_years,
                "profile_image": base64.b64encode(d.profile_image).decode('utf-8') if d.profile_image else None
            }
            for d in doctors
        ]
    }

@router.get("/patients/{patient_id}/current-doctor")
def get_patient_current_doctor(
    patient_id: int,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    assignment = db.query(PatientDoctorAssignment).filter(
        PatientDoctorAssignment.patient_id == patient_id,
        PatientDoctorAssignment.end_date == None
    ).first()
    
    if not assignment:
        return {"doctor": None}
    
    doctor = db.query(User).filter(User.id == assignment.doctor_id).first()
    
    return {
        "doctor": {
            "id": doctor.id,
            "name": doctor.name,
            "email": doctor.email,
            "specialization": doctor.specialization
        }
    }

@router.post("/patients/{patient_id}/assign-doctor")
def assign_doctor_to_patient(
    patient_id: int,
    doctor_id: int,
    request: Request,
    reason: str = None,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    current = db.query(PatientDoctorAssignment).filter(
        PatientDoctorAssignment.patient_id == patient_id,
        PatientDoctorAssignment.end_date == None
    ).first()
    
    if current:
        current.end_date = datetime.now()
    
    doctor = db.query(User).filter(User.id == doctor_id).first()
    patient = db.query(User).filter(User.id == patient_id).first()
    
    new_assignment = PatientDoctorAssignment(
        patient_id=patient_id,
        doctor_id=doctor_id,
        assigned_date=datetime.now(),
        reason=reason
    )
    
    db.add(new_assignment)
    db.commit()

    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='ASSIGN',
        resource_type='DOCTOR_ASSIGNMENT',
        resource_id=new_assignment.id,
        patient_id=patient_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "Doctor assigned successfully"}

@router.get("/doctors/{doctor_id}")
def get_doctor_details(
    doctor_id: int,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    doctor = db.query(User).filter(
        User.id == doctor_id,
        User.role == UserRole.DOCTOR
    ).first()
    
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    return {
        "doctor": {
            "id": doctor.id,
            "name": doctor.name,
            "email": doctor.email,
            "specialization": doctor.specialization,
            "department": doctor.department,
            "phone_number": doctor.phone_number,
            "is_active": doctor.is_active,
            "profile_image": base64.b64encode(doctor.profile_image).decode('utf-8') if doctor.profile_image else None,
            "description": doctor.description,
            "education": doctor.education,
            "experience_years": doctor.experience_years
        }
    }

@router.post("/doctors/profile")
def create_doctor_profile(
    doctor_data: dict,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value != 'admin':
        raise HTTPException(status_code=403, detail="Admin only")
    
    existing = db.query(models.User).filter(models.User.email == doctor_data.get('email')).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    email = doctor_data.get('email')
    username = email.split('@')[0]
    password = "Doctor@2024"
    hashed_password = hash_password(password)
    
    new_user = models.User(
        username=username,
        email=email,
        password_hash=hashed_password,
        name=doctor_data.get('name'),
        phone_number=doctor_data.get('phone_number'),
        role=UserRole.DOCTOR,
        specialization=doctor_data.get('specialization'),
        department=doctor_data.get('department'),
        is_active=True,
        status='approved'
    )
    
    if doctor_data.get('experience_years'):
        new_user.experience_years = doctor_data.get('experience_years')
    if doctor_data.get('education'):
        new_user.education = doctor_data.get('education')
    if doctor_data.get('description'):
        new_user.description = doctor_data.get('description')
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='CREATE',
        resource_type='DOCTOR',
        resource_id=new_user.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "Doctor created successfully", "id": new_user.id}

@router.put("/users/{user_id}")
async def update_user(
    user_id: int,
    name: str = Form(None),
    email: str = Form(None),
    phone_number: str = Form(None),
    specialization: str = Form(None),
    department: str = Form(None),
    experience_years: int = Form(None),
    education: str = Form(None),
    description: str = Form(None),
    is_active: bool = Form(None),
    profile_image: UploadFile = File(None),
    request: Request = None,
    db: Session = Depends(database.get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role.value != 'admin':
        raise HTTPException(status_code=403, detail="Admin only")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Track changes for audit log
    changes = {}
    
    # Update text fields
    if name is not None and name != user.name:
        changes['name'] = {'old': user.name, 'new': name}
        user.name = name
    if email is not None and email != user.email:
        changes['email'] = {'old': user.email, 'new': email}
        user.email = email
    if phone_number is not None and phone_number != user.phone_number:
        changes['phone_number'] = {'old': user.phone_number, 'new': phone_number}
        user.phone_number = phone_number
    if specialization is not None and specialization != user.specialization:
        changes['specialization'] = {'old': user.specialization, 'new': specialization}
        user.specialization = specialization
    if department is not None and department != user.department:
        changes['department'] = {'old': user.department, 'new': department}
        user.department = department
    if experience_years is not None and experience_years != user.experience_years:
        changes['experience_years'] = {'old': user.experience_years, 'new': experience_years}
        user.experience_years = experience_years
    if education is not None and education != user.education:
        changes['education'] = {'old': user.education, 'new': education}
        user.education = education
    if description is not None and description != user.description:
        changes['description'] = {'old': user.description, 'new': description}
        user.description = description
    if is_active is not None and is_active != user.is_active:
        changes['is_active'] = {'old': user.is_active, 'new': is_active}
        user.is_active = is_active
    
    # Handle photo
    photo_updated = False
    if profile_image:
        image_bytes = await profile_image.read()
        if image_bytes != user.profile_image:
            changes['profile_image'] = {'old': 'previous image', 'new': 'new image uploaded'}
            user.profile_image = image_bytes
            photo_updated = True
    
    if not changes and not photo_updated:
        return {"message": "No changes made", "id": user.id}
    
    db.commit()
    db.refresh(user)
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='UPDATE',
        resource_type='USER',
        resource_id=user_id,
        patient_id=user_id if user.role == UserRole.PATIENT else None,
        status='success',
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get('user-agent') if request else None,
        new_value=changes
    )
    
    return {"message": "User updated successfully", "id": user.id, "changes": changes}


# ========== ADMIN MANAGEMENT ENDPOINTS ==========

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "change-this-in-production")

class AdminCreateRequest(BaseModel):
    email: str = "admin@theclapp.com"
    password: str = "Admin123!"
    username: str = "admin"
    name: str = "System Administrator"
    one_time_token: str

class AdminRemoveRequest(BaseModel):
    email: str = "admin@theclapp.com"
    secret_key: str

@router.post("/admin/create", status_code=201)
def create_admin_endpoint(
    admin_data: AdminCreateRequest,
    request: Request,
    db: Session = Depends(database.get_db)
):
    if not admin_data.one_time_token:
        log_audit(
            db=db,
            user_id=None,
            username="unknown",
            user_role="unknown",
            action='ADMIN_CREATE_FAILED',
            resource_type='ADMIN',
            status='denied',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        raise HTTPException(status_code=403, detail="Invalid token")
    
    existing_admin = db.query(models.User).filter(
        models.User.email == admin_data.email
    ).first()
    
    if existing_admin:
        log_audit(
            db=db,
            user_id=None,
            username="unknown",
            user_role="unknown",
            action='ADMIN_CREATE_FAILED',
            resource_type='ADMIN',
            status='denied',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        raise HTTPException(status_code=400, detail="Admin already exists")
    
    hashed_password = hash_password(admin_data.password)
    
    new_admin = models.User(
        username=admin_data.username,
        name=admin_data.name,
        email=admin_data.email,
        password_hash=hashed_password,
        role=models.UserRole.ADMIN,
        is_active=True,
        status="approved"
    )
    
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    
    log_audit(
        db=db,
        user_id=None,
        username="one_time_token_creation",
        user_role="SYSTEM",
        action='ADMIN_CREATED',
        resource_type='ADMIN',
        resource_id=new_admin.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        purpose="ADMIN_MANAGEMENT"
    )
    
    return {
        "message": "Admin created successfully",
        "admin_id": new_admin.id,
        "email": new_admin.email,
        "role": new_admin.role.value if hasattr(new_admin.role, 'value') else str(new_admin.role)
    }

@router.delete("/admin/remove")
def remove_admin_endpoint(
    admin_data: AdminRemoveRequest,
    request: Request,
    db: Session = Depends(database.get_db)
):
    if admin_data.secret_key != ADMIN_SECRET_KEY:
        log_audit(
            db=db,
            user_id=None,
            username="unknown",
            user_role="unknown",
            action='ADMIN_REMOVE_FAILED',
            resource_type='ADMIN',
            status='denied',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        raise HTTPException(status_code=403, detail="Invalid secret key")
    
    admin = db.query(models.User).filter(
        models.User.email == admin_data.email,
        models.User.role == models.UserRole.ADMIN
    ).first()
    
    if not admin:
        log_audit(
            db=db,
            user_id=None,
            username="unknown",
            user_role="unknown",
            action='ADMIN_REMOVE_FAILED',
            resource_type='ADMIN',
            status='denied',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        raise HTTPException(status_code=404, detail="Admin not found")
    
    admin_count = db.query(models.User).filter(
        models.User.role == models.UserRole.ADMIN
    ).count()
    
    if admin_count <= 1:
        log_audit(
            db=db,
            user_id=admin.id,
            username=admin.username,
            user_role="ADMIN",
            action='ADMIN_REMOVE_FAILED',
            resource_type='ADMIN',
            resource_id=admin.id,
            status='denied',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        raise HTTPException(status_code=400, detail="Cannot remove the last admin")
    
    deleted_admin_email = admin.email
    deleted_admin_username = admin.username
    deleted_admin_id = admin.id
    
    db.delete(admin)
    db.commit()
    
    log_audit(
        db=db,
        user_id=None,
        username="system_admin_removal",
        user_role="SYSTEM",
        action='ADMIN_REMOVED',
        resource_type='ADMIN',
        resource_id=deleted_admin_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        purpose="ADMIN_MANAGEMENT"
    )
    
    return {"message": f"Admin {admin_data.email} removed successfully"}

@router.get("/admin/info")
def get_admin_info_endpoint(
    email: str = "admin@theclapp.com",
    db: Session = Depends(database.get_db)
):
    admin = db.query(models.User).filter(
        models.User.email == email,
        models.User.role == models.UserRole.ADMIN
    ).first()
    
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")
    
    return {
        "id": admin.id,
        "email": admin.email,
        "username": admin.username,
        "name": admin.name,
        "role": admin.role.value if hasattr(admin.role, 'value') else str(admin.role),
        "status": admin.status,
        "is_active": admin.is_active
    }

@router.get("/admin/list")
def list_all_admins(
    secret_key: str,
    request: Request,
    db: Session = Depends(database.get_db)
):
    if secret_key != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Invalid secret key")
    
    admins = db.query(models.User).filter(
        models.User.role == models.UserRole.ADMIN
    ).all()

    log_audit(
        db=db,
        user_id=None,
        username="system",
        user_role="SYSTEM",
        action='READ',
        resource_type='ADMIN',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {
        "admins": [
            {
                "id": admin.id,
                "email": admin.email,
                "username": admin.username,
                "name": admin.name,
                "role": admin.role.value if hasattr(admin.role, 'value') else str(admin.role),
                "status": admin.status,
                "is_active": admin.is_active
            }
            for admin in admins
        ],
        "total": len(admins)
    }

# ========== SUPER ADMIN ENDPOINTS ==========

@router.get("/admin/stats")
async def get_system_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    stats = {
        "organizations": db.query(Organization).count(),
        "total_users": db.query(User).count(),
        "pending_users": db.query(User).filter(User.status == 'pending').count(),
        "clinic_admins": db.query(User).filter(User.role == UserRole.ADMIN, User.is_super_admin == False).count(),
        "doctors": db.query(User).filter(User.role == UserRole.DOCTOR).count(),
        "patients": db.query(User).filter(User.role == UserRole.PATIENT).count()
    }
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='SYSTEM_STATS',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return stats

@router.get("/admin/all-users")
async def get_all_users_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    users = db.query(User).all()
    result = []
    for user in users:
        org = db.query(Organization).filter(Organization.id == user.organization_id).first()
        result.append({
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "email": user.email,
            "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
            "status": user.status,
            "organization_id": user.organization_id,
            "organization_name": org.name if org else None
        })
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='ALL_USERS',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return result

@router.get("/admin/clinic-admins")
async def get_clinic_admins(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    admins = db.query(User).filter(User.role == UserRole.ADMIN, User.is_super_admin == False).all()
    result = []
    for admin in admins:
        org = db.query(Organization).filter(Organization.id == admin.organization_id).first()
        result.append({
            "id": admin.id,
            "name": admin.name,
            "username": admin.username,
            "email": admin.email,
            "status": admin.status,
            "organization_id": admin.organization_id,
            "organization_name": org.name if org else None
        })
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='CLINIC_ADMINS',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return result

@router.post("/admin/create-clinic-admin")
async def create_clinic_admin(
    data: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    existing = db.query(User).filter(User.email == data.get('email')).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(data.get('password', 'Admin123!'))
    
    new_admin = User(
        username=data.get('username'),
        email=data.get('email'),
        password_hash=hashed_password,
        name=data.get('name'),
        role=UserRole.ADMIN,
        organization_id=data.get('organization_id'),
        status='approved',
        is_super_admin=False
    )
    
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='CREATE',
        resource_type='CLINIC_ADMIN',
        resource_id=new_admin.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "Clinic admin created", "id": new_admin.id}

@router.put("/admin/reset-password/{user_id}")
async def reset_user_password(
    user_id: int,
    data: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.password_hash = hash_password(data.get('password', 'Admin123!'))
    db.commit()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='UPDATE',
        resource_type='USER_PASSWORD',
        resource_id=user_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "Password reset successfully"}

@router.delete("/admin/users/{user_id}")
async def delete_user_by_admin(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    deleted_email = user.email
    deleted_name = user.name
    
    db.delete(user)
    db.commit()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='DELETE',
        resource_type='USER',
        resource_id=user_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "User deleted"}

@router.get("/admin/audit-logs")
async def get_audit_logs(
    limit: int = 100,
    user: str = None,
    action: str = None,
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    query = db.query(AuditLog)
    if user:
        query = query.filter(AuditLog.username.ilike(f"%{user}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='AUDIT_LOGS',
        status='success',
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get('user-agent') if request else None
    )
    
    return logs

@router.get("/doctors/by-organization")
def get_doctors_by_organization(
    organization_id: int,
    request: Request,
    db: Session = Depends(database.get_db),
    skip_auth: bool = True
):
    print(f"🔍 ENDPOINT REACHED! organization_id={organization_id}")
    """Get all active doctors in an organization (no auth required for registration)"""
    doctors = db.query(User).filter(
        User.role == UserRole.DOCTOR,
        User.organization_id == organization_id,
        User.is_active == True,
        User.status == 'approved'
    ).all()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=None,
        username=None,
        user_role=None,
        action='READ',
        resource_type='DOCTORS_LIST',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        details={"organization_id": organization_id, "doctors_count": len(doctors)}
    )
    
    return {
        "doctors": [
            {
                "id": d.id,
                "name": d.name,
                "specialization": d.specialization,
                "department": d.department,
                "experience_years": d.experience_years,
                "profile_image": base64.b64encode(d.profile_image).decode('utf-8') if d.profile_image else None,
            }
            for d in doctors
        ]
    }

@router.get("/doctors/{doctor_id}/patients")
async def get_doctor_patients(
    doctor_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != doctor_id and current_user.role.value != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Get active assignments
    assignments = db.query(PatientDoctorAssignment).filter(
        PatientDoctorAssignment.doctor_id == doctor_id,
        PatientDoctorAssignment.end_date == None
    ).all()
    
    patient_ids = [a.patient_id for a in assignments]
    
    if not patient_ids:
        return {"patients": []}
    
    patients = db.query(User).filter(
        User.id.in_(patient_ids),
        User.role == UserRole.PATIENT
    ).all()
    
    return {
        "patients": [
            {
                "id": p.id,
                "name": p.name,
                "email": p.email,
                "phone_number": p.phone_number
            }
            for p in patients
        ]
    }