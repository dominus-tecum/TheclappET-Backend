from fastapi import APIRouter, Depends, HTTPException, Body, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.database import get_db
from app.models import User, PatientProfile, Organization, PatientDoctorAssignment, UserRole, PatientConsent
from .schemas import UserRegister, UserLogin, UserRead
from .service import create_user 
from .auth import create_access_token, get_current_user, authenticate_user
from jose import jwt
from app.core.config import settings
from app.utils.audit import log_audit
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.utils.encryption import encrypt_value, hash_value
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Body, Request, Form, UploadFile, File

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(tags=["Authentication"])

# In-memory storage for refresh tokens
REFRESH_TOKENS = {}

# Direct bcrypt functions
def get_password_hash(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

# Helper function to create refresh tokens
def create_refresh_token(username: str, user_id: int):
    """Create a refresh token valid for 7 days"""
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



@router.post("/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(None),
    phone_number: str = Form(None),
    role: str = Form(...),
    organization_id: int = Form(...),
    doctor_id: int = Form(None),
    passport_number: str = Form(None),
    emirates_id: str = Form(None),
    profile_image: UploadFile = File(None),
    request: Request = None,
    db: Session = Depends(get_db)
):
    print(f"🔍 REGISTER - Received FormData")
    print(f"   username: {username}")
    print(f"   email: {email}")
    print(f"   organization_id: {organization_id}")
    print(f"   role: {role}")
    
    # ========== DUPLICATE CHECKS ==========
    existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    if passport_number:
        existing_passport = db.query(User).filter(User.passport_number == passport_number).first()
        if existing_passport:
            raise HTTPException(status_code=400, detail="Passport number already registered")

    if phone_number:
        existing_phone = db.query(User).filter(User.phone_number == phone_number).first()
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already registered")

    if emirates_id:
        existing_emirates = db.query(User).filter(User.emirates_id == emirates_id).first()
        if existing_emirates:
            raise HTTPException(status_code=400, detail="Emirates ID already registered")

    # Check by hash
    email_hash = hash_value(email)
    existing_email = db.query(User).filter(User.email_hash == email_hash).first()
    if not existing_email:
        existing_email = db.query(User).filter(User.email == email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if passport_number:
        passport_hash = hash_value(passport_number)
        existing_passport = db.query(User).filter(User.passport_hash == passport_hash).first()
        if not existing_passport:
            existing_passport = db.query(User).filter(User.passport_number == passport_number).first()
        if existing_passport:
            raise HTTPException(status_code=400, detail="Passport number already registered")
    else:
        passport_hash = None
                
    if phone_number:
        phone_hash = hash_value(phone_number)
        existing_phone = db.query(User).filter(User.phone_hash == phone_hash).first()
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already registered")
    
    if emirates_id:
        emirates_hash = hash_value(emirates_id)
        existing_emirates = db.query(User).filter(User.emirates_id_hash == emirates_hash).first()
        if existing_emirates:
            raise HTTPException(status_code=400, detail="Emirates ID already registered")

    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=400, detail="Invalid organization")

    # Hash password
    hashed_password = get_password_hash(password)

    # Handle profile image
    profile_image_data = None
    if profile_image:
        profile_image_data = await profile_image.read()

    # Create user
    created_user = User(
        username=username,
        password_hash=hashed_password,
        role=role,
        organization_id=organization_id,
        status='pending',
        name=name,
        email=email,
        phone_number=phone_number,
        passport_number=passport_number,
        emirates_id=emirates_id,
        profile_image=profile_image_data,
        name_encrypted=encrypt_value(name) if name else None,
        email_encrypted=encrypt_value(email),
        phone_encrypted=encrypt_value(phone_number) if phone_number else None,
        passport_encrypted=encrypt_value(passport_number) if passport_number else None,
        emirates_id_encrypted=encrypt_value(emirates_id) if emirates_id else None,
        email_hash=hash_value(email),
        phone_hash=hash_value(phone_number) if phone_number else None,
        passport_hash=passport_hash,
        emirates_id_hash=hash_value(emirates_id) if emirates_id else None
    )

    db.add(created_user)
    db.commit()
    db.refresh(created_user)

    # ========== LINK PENDING CONSENTS ==========
    if request and hasattr(request, 'session'):
        pending_consent_ids = request.session.get('pending_consent_ids')
        if pending_consent_ids:
            from sqlalchemy import update
            stmt = update(PatientConsent).where(
                PatientConsent.id.in_(pending_consent_ids)
            ).values(user_id=created_user.id)
            db.execute(stmt)
            db.commit()
            print(f"✅ Linked {len(pending_consent_ids)} pending consents to user {created_user.id}")
            request.session.pop('pending_consent_ids', None)

    print(f"✅ REGISTER - User created: {created_user.id}, {created_user.email}")

    # CREATE PATIENT PROFILE
    existing_patient = db.query(PatientProfile).filter(PatientProfile.user_id == created_user.id).first()
    if not existing_patient:
        new_patient = PatientProfile(
            user_id=created_user.id,
            name=name or created_user.name or username,
            email=email,
            phone_number=phone_number,
            high_risk=False,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        db.add(new_patient)
        db.commit()
        db.refresh(new_patient)
        print(f"✅ Patient profile created with ID: {new_patient.id}")

    # ========== DOCTOR ASSIGNMENT ==========
    if doctor_id:
        print(f"🔍 Attempting to assign patient to doctor_id: {doctor_id}")
        doctor = db.query(User).filter(
            User.id == doctor_id,
            User.role == UserRole.DOCTOR,
            User.organization_id == organization_id
        ).first()
        
        if doctor:
            assignment = PatientDoctorAssignment(
                patient_id=created_user.id,
                doctor_id=doctor_id,
                assigned_date=datetime.now(),
                reason="Patient selected during registration"
            )
            db.add(assignment)
            db.commit()
            print(f"✅ Patient assigned to doctor ID: {doctor_id}")
            
            log_audit(
                db=db,
                user_id=created_user.id,
                username=created_user.username,
                user_role=created_user.role.value if hasattr(created_user.role, 'value') else str(created_user.role),
                action='ASSIGN',
                resource_type='DOCTOR_ASSIGNMENT',
                patient_id=created_user.id,
                status='success',
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get('user-agent') if request else None,
                new_value={"doctor_id": doctor_id}
            )

    # Audit log
    log_audit(
        db=db,
        user_id=created_user.id,
        username=created_user.username,
        user_role=created_user.role.value if hasattr(created_user.role, 'value') else str(created_user.role),
        action='REGISTER',
        resource_type='USER',
        resource_id=created_user.id,
        status='success',
        ip_address=request.client.host if request else None,
        user_agent=request.headers.get('user-agent') if request else None
    )
    
    return {
        "id": created_user.id,
        "username": created_user.username,
        "email": email,
        "role": created_user.role.value if hasattr(created_user.role, 'value') else str(created_user.role),
        "status": created_user.status,
        "message": "Registration successful. Awaiting admin approval."
    }

@router.post("/login")
@limiter.limit("5/minute")
def login(request: Request, user: UserLogin, db: Session = Depends(get_db)):
    
    print(f"🔍 LOGIN - Attempt: {user.email}")
    
    authenticated_user = authenticate_user(db, user.email, user.password)
    
    if not authenticated_user:
        # ✅ ADD THIS AUDIT LOG
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
    
    # ✅ STATUS CHECK - BLOCK PENDING/REJECTED/INACTIVE USERS
    print(f"🔍 LOGIN - User status: {authenticated_user.status}")
    
    if authenticated_user.status == 'pending':
        # ✅ ADD THIS AUDIT LOG
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
        # ✅ ADD THIS AUDIT LOG
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
        # ✅ ADD THIS AUDIT LOG
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
    
    # ✅ SUCCESSFUL LOGIN - ADD THIS AUDIT LOG
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
    
    # Create tokens (your existing code)
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
    
    if authenticated_user.status == 'inactive':
        print("❌ LOGIN - Account inactive")
        raise HTTPException(
            status_code=403, 
            detail="Account is deactivated. Please contact support."
        )
    
    # Only approved users reach here
    print(f"✅ LOGIN - Success for: {authenticated_user.email}, {authenticated_user.role}")
    
    # 1. Create access token (30 minutes)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": authenticated_user.username}, 
        expires_delta=access_token_expires
    )
    
    # 2. Create refresh token (7 days)
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
            "status": authenticated_user.status  # ← IMPORTANT: Send status to frontend
        }
    }
@router.post("/refresh")
async def refresh_token(refresh_token: str = Body(..., embed=True)):
    """
    Get new access token using refresh token
    """
    print(f"🔍 REFRESH - Attempt with token: {refresh_token[:20]}...")
    
    # Check if token exists
    if refresh_token not in REFRESH_TOKENS:
        print("❌ REFRESH - Token not found in storage")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    token_data = REFRESH_TOKENS[refresh_token]
    
    # Check if expired
    if datetime.utcnow() > token_data["expires_at"]:
        del REFRESH_TOKENS[refresh_token]  # Clean up expired token
        print("❌ REFRESH - Token expired")
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    # Create new access token (30 minutes)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": token_data["username"]}, 
        expires_delta=access_token_expires
    )
    
    print(f"✅ REFRESH - New access token created for: {token_data['username']}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800  # 30 minutes in seconds
    }

@router.get("/me", response_model=UserRead)
def get_current_user_info(
    request: Request,
    current_user: dict = Depends(get_current_user),  # ← CHANGE User to dict
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=user.id,
        username=user.username,
        user_role=user.role.value if hasattr(user.role, 'value') else str(user.role),
        action='READ',
        resource_type='USER_PROFILE',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "name": user.name,
        "phone_number": user.phone_number,
        "status": user.status,
        "is_super_admin": getattr(user, 'is_super_admin', False)
    }


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
    from app.models import AuditLog, PatientConsent
    from datetime import datetime

    print("=" * 50)
    print("🔵 SAVE-CONSENT ENDPOINT CALLED")
    print(f"📝 Consent data received: {consent_data}")
    print("=" * 50)
    print(f"🔍 Session ID before save: {request.session}")
    print(f"🔍 Session keys before save: {list(request.session.keys())}")

    consent_mapping = {
        "privacy_policy": "Privacy Policy",
        "terms_of_service": "Terms of Service",
        "data_collection": "Data Collection",
        "medical_treatment": "Medical Treatment",
        "emergency_contact": "Emergency Contact Sharing",
        "telemedicine": "Telemedicine Services"
    }
    
    consent_ids = []
    
    # Save each accepted consent to patient_consents table
    for consent_key, accepted in consent_data.consents.items():
        if accepted:
            consent = PatientConsent(
                user_id=None,
                consent_type=consent_mapping.get(consent_key, consent_key),
                consent_version=consent_data.consent_version,
                accepted=accepted,
                ip_address=request.client.host if request.client else None,
                device_info=consent_data.device_info,
                created_at=datetime.now()
            )
            db.add(consent)
            db.flush()
            consent_ids.append(consent.id)
    
    db.commit()
    
    # Store consent IDs in session
    request.session['pending_consent_ids'] = consent_ids
    print(f"✅ Stored consent_ids in session: {consent_ids}")
    
    # Log audit
    audit = AuditLog(
        action="consent_given",
        resource_type="consent_form",
        ip_address=request.client.host if request.client else None,
        user_agent=consent_data.device_info,
        created_at=datetime.now()
    )
    db.add(audit)
    db.commit()

    return {"message": "Consent recorded", "consent_ids": consent_ids}

@router.post("/update-super-admin")
def update_super_admin(
    email: str = Body(None),
    password: str = Body(None),
    username: str = Body(None),
    organization_id: int = Body(None),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update super admin account - Only existing super admin can use this"""
    
    # SECURITY: Only existing super admin can access
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    # Get the super admin user (usually the one making the request)
    admin_user = db.query(User).filter(User.id == current_user.id).first()
    
    if not admin_user:
        raise HTTPException(status_code=404, detail="Admin user not found")
    
    # Update fields if provided
    if email:
        admin_user.email = email
    if username:
        admin_user.username = username
    if password:
        admin_user.password_hash = get_password_hash(password)
    
    # Ensure super admin flag stays true
    admin_user.is_super_admin = True
    admin_user.role = UserRole.ADMIN
    admin_user.status = 'approved'
    
    db.commit()
    db.refresh(admin_user)
    
    return {
        "message": "Super admin updated successfully",
        "user": {
            "id": admin_user.id,
            "email": admin_user.email,
            "username": admin_user.username,
            "is_super_admin": admin_user.is_super_admin
        }
    } 


@router.post("/create-super-admin-temp")
def create_super_admin_temp(
    email: str = Body(...),
    password: str = Body(...),
    username: str = Body(...),
    db: Session = Depends(get_db)
):
    """TEMPORARY - Create super admin"""
    
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        existing.is_super_admin = True
        existing.role = UserRole.ADMIN
        existing.status = 'approved'
        existing.organization_id = None
        db.commit()
        return {"message": "Existing user upgraded to super admin"}
    
    hashed = get_password_hash(password)
    new_admin = User(
        username=username,
        email=email,
        password_hash=hashed,
        role='admin',
        is_super_admin=True,
        organization_id=None,
        status='approved',
        name=username
    )
    db.add(new_admin)
    db.commit()
    
    return {"message": "Super admin created", "user_id": new_admin.id}