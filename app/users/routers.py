from fastapi import APIRouter, Depends, HTTPException, Body, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.database import get_db
from app.models import User, PatientProfile, UserRole
from .schemas import UserRegister, UserLogin, UserRead
from .service import create_user, authenticate_user
from app.authentication.auth import create_access_token, get_current_user
from jose import jwt
from app.core.config import settings
from app.utils.audit import log_audit

router = APIRouter(tags=["Authentication"])

# In-memory storage for refresh tokens
REFRESH_TOKENS = {}

def create_refresh_token(username: str, user_id: int):
    expire = datetime.utcnow() + timedelta(days=7)
    refresh_token = jwt.encode(
        {
            "sub": username,
            "user_id": user_id,
            "type": "refresh",
            "exp": expire
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    REFRESH_TOKENS[refresh_token] = {
        "user_id": user_id,
        "username": username,
        "expires_at": expire
    }
    return refresh_token


# ========== SPECIFIC ROUTES FIRST (ORDER MATTERS) ==========

@router.get("/pending")
def get_pending_patients(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get pending patients - Admin only"""
    # ✅ Allow admin OR doctor
    if current_user.role.value not in ['admin', 'doctor']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # ✅ If doctor, filter only their patients
    if current_user.role.value == 'doctor':
        # Get patients assigned to this doctor
        from app.models import PatientDoctorAssignment
        assigned_patient_ids = db.query(PatientDoctorAssignment.patient_id).filter(
            PatientDoctorAssignment.doctor_id == current_user.id,
            PatientDoctorAssignment.end_date == None
        ).all()
        patient_ids = [p[0] for p in assigned_patient_ids]
        
        patients = db.query(User).filter(
            User.role == 'PATIENT',
            User.status == 'pending',
            User.id.in_(patient_ids)
        ).all()
    else:
        # Admin or Super Admin
        if current_user.is_super_admin:
            patients = db.query(User).filter(
                User.role == 'PATIENT',
                User.status == 'pending'
            ).all()
        else:
            patients = db.query(User).filter(
                User.role == 'PATIENT',
                User.status == 'pending',
                User.organization_id == current_user.organization_id
            ).all()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='PENDING_PATIENTS',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    print(f"DEBUG - Returned patients: {[(p.id, p.email) for p in patients]}")
    return patients


@router.get("/stats")
def get_user_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics - Admin or Doctor"""
    # ✅ Allow admin OR doctor
    if current_user.role.value not in ['admin', 'doctor']:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # ✅ If doctor, filter their patients
    if current_user.role.value == 'doctor':
        from app.models import PatientDoctorAssignment
        assigned_patient_ids = db.query(PatientDoctorAssignment.patient_id).filter(
            PatientDoctorAssignment.doctor_id == current_user.id,
            PatientDoctorAssignment.end_date == None
        ).all()
        patient_ids = [p[0] for p in assigned_patient_ids]
        
        total = db.query(User).filter(User.id.in_(patient_ids)).count()
        pending = db.query(User).filter(
            User.id.in_(patient_ids),
            User.status == 'pending'
        ).count()
        approved = db.query(User).filter(
            User.id.in_(patient_ids),
            User.status == 'approved'
        ).count()
    else:
        # Admin or Super Admin
        if current_user.is_super_admin:
            total = db.query(User).count()
            pending = db.query(User).filter(User.status == 'pending').count()
            approved = db.query(User).filter(User.status == 'approved').count()
        else:
            total = db.query(User).filter(User.organization_id == current_user.organization_id).count()
            pending = db.query(User).filter(
                User.organization_id == current_user.organization_id,
                User.status == 'pending'
            ).count()
            approved = db.query(User).filter(
                User.organization_id == current_user.organization_id,
                User.status == 'approved'
            ).count()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='USER_STATS',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"total": total, "pending": pending, "approved": approved}


@router.get("/")
def get_all_users(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get users - Admin sees all, Doctor sees only themselves"""
    
    if current_user.role.value == 'admin':
        if current_user.is_super_admin:
            users = db.query(User).all()
        else:
            users = db.query(User).filter(
                User.organization_id == current_user.organization_id
            ).all()
    elif current_user.role.value == 'doctor':
        users = [current_user]
    else:
        raise HTTPException(status_code=403, detail="Access denied")
    
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "email": user.email,
            "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
            "status": user.status,
            "phone_number": user.phone_number,
            "organization_id": user.organization_id
        })
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='USERS_LIST',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return result

@router.post("/register", response_model=UserRead)
def register(user: UserRegister, db: Session = Depends(get_db)):
    print(f"🔍 REGISTER - Received: {user.dict()}")
    
    existing_email = db.query(User).filter(User.email == user.email).first()
    if existing_email:
        print("❌ REGISTER - Email already exists")
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_username = db.query(User).filter(User.username == user.username).first()
    if existing_username:
        print("❌ REGISTER - Username already taken")
        raise HTTPException(status_code=400, detail="Username already taken")

    created_user = create_user(db, user)
    print(f"✅ REGISTER - User created: {created_user.id}, {created_user.email}, {created_user.username}")
    created_user.status = 'pending'
    db.commit()
    
    existing_patient = db.query(PatientProfile).filter(PatientProfile.user_id == created_user.id).first()
    if not existing_patient:
        new_patient = PatientProfile(
            user_id=created_user.id,
            name=user.name or created_user.name or user.username,
            email=user.email,
            phone_number=user.phone_number,
            high_risk=False,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        db.add(new_patient)
        db.commit()
        db.refresh(new_patient)
        print(f"✅ Patient profile created with ID: {new_patient.id}")
    else:
        print(f"⚠️ Patient profile already exists: {existing_patient.id}")
    
    return created_user


@router.post("/login")
def login(
    user: UserLogin, 
    request: Request,
    db: Session = Depends(get_db)
):
    print(f"🔍 LOGIN - Attempt: {user.email}")
    
    authenticated_user = authenticate_user(db, user.email, user.password)
    
    if not authenticated_user:
        log_audit(
            db=db,
            username=user.email,
            action='LOGIN_FAILED',
            resource_type='AUTH',
            status='failed',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        print("❌ LOGIN - Invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    print(f"🔍 LOGIN - User status: {authenticated_user.status}")
    
    if authenticated_user.status == 'pending':
        log_audit(
            db=db,
            user_id=authenticated_user.id,
            username=authenticated_user.username,
            action='LOGIN_DENIED',
            resource_type='AUTH',
            status='denied',
            purpose='PENDING_APPROVAL',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        print("❌ LOGIN - Account pending approval")
        raise HTTPException(
            status_code=403, 
            detail="Account pending approval. Please wait for admin verification."
        )
    
    if authenticated_user.status == 'rejected':
        log_audit(
            db=db,
            user_id=authenticated_user.id,
            username=authenticated_user.username,
            action='LOGIN_DENIED',
            resource_type='AUTH',
            status='denied',
            purpose='REJECTED',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        print("❌ LOGIN - Account rejected")
        raise HTTPException(
            status_code=403, 
            detail="Account registration was rejected. Please contact support."
        )
    
    if authenticated_user.status == 'inactive':
        log_audit(
            db=db,
            user_id=authenticated_user.id,
            username=authenticated_user.username,
            action='LOGIN_DENIED',
            resource_type='AUTH',
            status='denied',
            purpose='INACTIVE',
            ip_address=request.client.host,
            user_agent=request.headers.get('user-agent')
        )
        print("❌ LOGIN - Account inactive")
        raise HTTPException(
            status_code=403, 
            detail="Account is deactivated. Please contact support."
        )
    
    log_audit(
        db=db,
        user_id=authenticated_user.id,
        username=authenticated_user.username,
        user_role=authenticated_user.role.value,
        action='LOGIN_SUCCESS',
        resource_type='AUTH',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    print(f"✅ LOGIN - Success for: {authenticated_user.email}, {authenticated_user.role}")
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": authenticated_user.username}, 
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        username=authenticated_user.username,
        user_id=authenticated_user.id
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": authenticated_user.id,
            "username": authenticated_user.username,
            "email": authenticated_user.email,
            "role": authenticated_user.role,
            "name": authenticated_user.name,
            "phone_number": authenticated_user.phone_number,
            "status": authenticated_user.status,
            "organization_id": authenticated_user.organization_id
        }
    }


@router.post("/refresh")
async def refresh_token(refresh_token: str = Body(..., embed=True)):
    print(f"🔍 REFRESH - Attempt with token: {refresh_token[:20]}...")
    
    if refresh_token not in REFRESH_TOKENS:
        print("❌ REFRESH - Token not found in storage")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    token_data = REFRESH_TOKENS[refresh_token]
    
    if datetime.utcnow() > token_data["expires_at"]:
        del REFRESH_TOKENS[refresh_token]
        print("❌ REFRESH - Token expired")
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": token_data["username"]}, 
        expires_delta=access_token_expires
    )
    
    print(f"✅ REFRESH - New access token created for: {token_data['username']}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800
    }


@router.get("/me", response_model=UserRead)
def get_current_user_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

from pydantic import BaseModel
from typing import Dict

class ConsentData(BaseModel):
    consents: Dict[str, bool]
    consent_version: str
    device_info: str

@router.post("/save-consent")
async def save_consent(
    consent_data: ConsentData,
    request: Request,
    db: Session = Depends(get_db)
):
    from app.models import AuditLog
    from datetime import datetime
    
    request.session['pending_consent'] = consent_data.dict()
    
    audit = AuditLog(
        action="consent_given",
        resource_type="consent_form",
        ip_address=request.client.host,
        user_agent=consent_data.device_info,
        created_at=datetime.now()
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Consent recorded"}


@router.put("/{user_id}/approve")
def approve_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Approve a user - Admin only"""
    if current_user.role.value != 'admin':
        raise HTTPException(status_code=403, detail="Admin only")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not current_user.is_super_admin:
        if user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Not authorized to approve users from other organizations")
    
    user.status = 'approved'
    db.commit()
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='APPROVE',
        resource_type='USER',
        resource_id=user_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {"message": "User approved"}


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete a user - Admin only"""
    if current_user.role.value != 'admin':
        raise HTTPException(status_code=403, detail="Admin only")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    if not current_user.is_super_admin:
        if user.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Not authorized to delete users from other organizations")
    
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
    
    return {"message": "User deleted successfully"}


# ========== VARIABLE ROUTES (KEEP AT THE BOTTOM) ==========

@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='USER',
        resource_id=user_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return user