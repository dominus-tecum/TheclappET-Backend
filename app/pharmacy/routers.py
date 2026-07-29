from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
import csv
import io
import bcrypt
from app.database import get_db
from app.authentication.auth import get_current_user
from app.pharmacy.models import Pharmacy, PharmacyMedication
from app.models import User, Organization
from app.utils.audit import log_audit

router = APIRouter(tags=["pharmacy"])

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

@router.get("/search/{medication_name}")
async def search_medication_prices(
    medication_name: str,
    strength: str = None,
    db: Session = Depends(get_db)
):
    base_name = medication_name.split()[0] if medication_name else ""
    strength_pattern = f"%{strength}%" if strength else "%"
    query = text("""
    SELECT 
        p.id as pharmacy_id,
        p.name as pharmacy_name,
        p.phone_number,
        p.address,
        pm.medication_name,
        pm.strength,
        pm.unit_price as price
    FROM pharmacy_medications pm
    JOIN pharmacies p ON pm.pharmacy_id = p.id
    WHERE pm.medication_name LIKE :medication_name
    AND (pm.strength LIKE :strength OR :strength IS NULL)
        AND pm.is_active = 1
        AND p.is_active = 1
        AND (pm.deleted_at IS NULL OR pm.deleted_at = '')
        AND (p.deleted_at IS NULL OR p.deleted_at = '')
    ORDER BY pm.unit_price ASC
    LIMIT 5
""")
    
    result = db.execute(query, {"medication_name": f"%{base_name}%", "strength": strength_pattern})
    rows = result.fetchall()
    
    pharmacies = []
    for row in rows:
        pharmacies.append({
            "pharmacy_id": row[0],
            "pharmacy_name": row[1],
            "phone_number": row[2],
            "address": row[3],
            "medication_name": row[4],
            "strength": row[5] or "",
            "price": float(row[6])
        })
    
    # Optional audit log without user info
    log_audit(
        db=db,
        user_id=None,
        username="anonymous",
        user_role="public",
        action='SEARCH_MEDICATION',
        resource_type='MEDICATION',
        status='success',
    )
    
    return {
        "medication": medication_name,
        "results": pharmacies,
        "count": len(pharmacies)
    }

@router.get("/my-medications")
async def get_my_medications(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user or not user.pharmacy_id:
        raise HTTPException(status_code=403, detail="Pharmacy access only")
    
    meds = db.query(PharmacyMedication).filter(
        PharmacyMedication.pharmacy_id == user.pharmacy_id,
        PharmacyMedication.deleted_at.is_(None)
    ).all()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='VIEW_MEDICATIONS',
        resource_type='MEDICATION',
        status='success'
    )
    
    return [{
        "id": m.id,
        "medication_name": m.medication_name,
        "strength": getattr(m, 'strength', None),
        "price": float(m.unit_price),
        "updated_at": m.updated_at
    } for m in meds]

@router.post("/medications")
async def add_medication(
    request: Request,
    medication: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user or not user.pharmacy_id:
        raise HTTPException(status_code=403, detail="Pharmacy access only")
    
    new_med = PharmacyMedication(
        pharmacy_id=user.organization_id,
        medication_name=medication['medication_name'],
        strength=medication.get('strength'),
        unit_price=medication['price'],
        updated_at=datetime.now()
    )
    db.add(new_med)
    db.commit()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='ADD_MEDICATION',
        resource_type='MEDICATION',
        resource_id=new_med.id,
        status='success',
        ip_address=request.client.host if request.client else None,
        new_value={"medication_name": medication['medication_name'], "price": medication['price']}
    )
    
    return {"message": "Medication added"}

@router.put("/medications/{med_id}")
async def update_medication(
    request: Request,
    med_id: int,
    medication: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    med = db.query(PharmacyMedication).filter(
        PharmacyMedication.id == med_id,
        PharmacyMedication.pharmacy_id == user.pharmacy_id
    ).first()
    if not med:
        raise HTTPException(status_code=404, detail="Medication not found")
    
    old_price = med.unit_price
    med.medication_name = medication['medication_name']
    med.strength = medication.get('strength')
    med.unit_price = medication['price']
    med.updated_at = datetime.now()
    db.commit()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='UPDATE_MEDICATION',
        resource_type='MEDICATION',
        resource_id=med_id,
        status='success',
        ip_address=request.client.host if request.client else None,
        old_value={"price": old_price},
        new_value={"price": medication['price']}
    )
    
    return {"message": "Medication updated"}

@router.delete("/medications/{med_id}")
async def delete_medication(
    request: Request,
    med_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    med = db.query(PharmacyMedication).filter(
        PharmacyMedication.id == med_id,
        PharmacyMedication.pharmacy_id == user.pharmacy_id
    ).first()
    if not med:
        raise HTTPException(status_code=404, detail="Medication not found")
    
    med.deleted_at = datetime.now()
    db.commit()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='DELETE_MEDICATION',
        resource_type='MEDICATION',
        resource_id=med_id,
        status='success',
        ip_address=request.client.host if request.client else None,
        details=f"Deleted medication: {med.medication_name}"
    )
    
    return {"message": "Medication deleted"}

@router.post("/upload-csv")
async def upload_csv(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user or not user.pharmacy_id:
        raise HTTPException(status_code=403, detail="Pharmacy access only")
    
    contents = await file.read()
    
    # Try different encodings
    try:
        csv_data = csv.DictReader(io.StringIO(contents.decode('utf-8')))
    except UnicodeDecodeError:
        try:
            csv_data = csv.DictReader(io.StringIO(contents.decode('latin-1')))
        except:
            csv_data = csv.DictReader(io.StringIO(contents.decode('cp1252')))
    
    added = 0
    skipped = 0
    
    for row in csv_data:
        name = row.get('medication_name', '').strip()
        strength = row.get('strength', '').strip()
        try:
            price = float(row.get('price', 0))
        except:
            skipped += 1
            continue
        
        if not name or price <= 0:
            skipped += 1
            continue
        
        existing = db.query(PharmacyMedication).filter(
            PharmacyMedication.pharmacy_id == user.pharmacy_id,
            PharmacyMedication.medication_name == name,
            PharmacyMedication.strength == strength,
            PharmacyMedication.deleted_at.is_(None)
        ).first()
        
        if existing:
            existing.unit_price = price
            existing.updated_at = datetime.now()
        else:
            new_med = PharmacyMedication(
                pharmacy_id=user.organization_id,
                medication_name=name,
                strength=strength,
                unit_price=price,
                updated_at=datetime.now()
            )
            db.add(new_med)
        added += 1
    
    db.commit()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='BULK_UPLOAD',
        resource_type='MEDICATION',
        status='success',
        ip_address=request.client.host if request.client else None,
    )
    
    return {"message": "Upload complete", "added": added, "skipped": skipped}


@router.post("/upload-prices")
async def upload_prices(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload CSV/Excel file with medication prices"""
    return await upload_csv(request, file, current_user, db)    





@router.get("/stats")
async def get_pharmacy_stats(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user or not user.pharmacy_id:
        raise HTTPException(status_code=403, detail="Pharmacy access only")
    
    meds = db.query(PharmacyMedication).filter(
        PharmacyMedication.pharmacy_id == user.pharmacy_id,
        PharmacyMedication.deleted_at.is_(None)
    ).all()
    
    avg_price = sum(m.unit_price for m in meds) / len(meds) if meds else 0
    last_update = max((m.updated_at for m in meds), default=None)
    
    return {
        "count": len(meds),
        "avg_price": avg_price,
        "last_update": last_update.isoformat() if last_update else None
    }

@router.post("/change-password")
async def change_pharmacy_password(
    request: Request,
    password_data: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not verify_password(password_data['current_password'], user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    if len(password_data['new_password']) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    user.password_hash = hash_password(password_data['new_password'])
    db.commit()
    
    # Audit log
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        action='CHANGE_PASSWORD',
        resource_type='USER',
        resource_id=user.id,
        status='success',
        ip_address=request.client.host if request.client else None
    )
    
    return {"message": "Password changed successfully"}

# ========== SUPER ADMIN PHARMACY MANAGEMENT ENDPOINTS ==========

@router.get("/admin/pharmacies")
async def admin_get_all_pharmacies(
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    pharmacies = db.query(Pharmacy).filter(Pharmacy.deleted_at.is_(None)).all()
    result = []
    for p in pharmacies:
        user = db.query(User).filter(User.pharmacy_id == p.id).first()
        med_count = db.query(PharmacyMedication).filter(
            PharmacyMedication.pharmacy_id == p.id,
            PharmacyMedication.deleted_at.is_(None)
        ).count()
        
        result.append({
            "id": p.id,
            "name": p.name,
            "phone_number": p.phone_number,
            "address": p.address,
            "user_email": user.email if user else None,
            "is_active": p.is_active,
            "medication_count": med_count,
            "created_at": p.created_at
        })
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='READ',
        resource_type='PHARMACIES_LIST',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent')
    )
    
    return result

@router.post("/admin/pharmacies")
async def admin_create_pharmacy(
    request: Request,
    data: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    # ONLY CREATE PHARMACY - NO USER
    new_pharmacy = Pharmacy(
        name=data['name'],
        phone_number=data.get('phone_number'),
        address=data.get('address'),
        is_active=True
    )
    db.add(new_pharmacy)
    db.commit()
    db.refresh(new_pharmacy)
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='CREATE',
        resource_type='PHARMACY',
        resource_id=new_pharmacy.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        new_value={"name": data['name']}
    )
    
    return {"message": "Pharmacy created", "id": new_pharmacy.id}

@router.put("/admin/pharmacies/{pharmacy_id}")
async def admin_update_pharmacy(
    pharmacy_id: int,
    data: dict,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    pharmacy = db.query(Pharmacy).filter(Pharmacy.id == pharmacy_id).first()
    if not pharmacy:
        raise HTTPException(status_code=404, detail="Pharmacy not found")
    
    old_data = {"is_active": pharmacy.is_active}
    
    if 'is_active' in data:
        pharmacy.is_active = data['is_active']
    if 'name' in data:
        pharmacy.name = data['name']
    if 'phone_number' in data:
        pharmacy.phone_number = data['phone_number']
    if 'address' in data:
        pharmacy.address = data['address']
    
    db.commit()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='UPDATE',
        resource_type='PHARMACY',
        resource_id=pharmacy_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        old_value=old_data,
        new_value={"is_active": pharmacy.is_active}
    )
    
    return {"message": "Pharmacy updated"}

@router.delete("/admin/pharmacies/{pharmacy_id}")
async def admin_delete_pharmacy(
    pharmacy_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    pharmacy = db.query(Pharmacy).filter(Pharmacy.id == pharmacy_id).first()
    if not pharmacy:
        raise HTTPException(status_code=404, detail="Pharmacy not found")
    
    pharmacy_name = pharmacy.name
    pharmacy.deleted_at = datetime.now()
    
    # Soft delete associated user
    user = db.query(User).filter(User.pharmacy_id == pharmacy_id).first()
    if user:
        user.deleted_at = datetime.now()
    
    db.commit()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='DELETE',
        resource_type='PHARMACY',
        resource_id=pharmacy_id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        old_value={"name": pharmacy_name}
    )
    
    return {"message": "Pharmacy deleted"}

@router.post("/admin/pharmacies/bulk-delete")
async def admin_bulk_delete_pharmacies(
    data: dict,
    request: Request,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    pharmacy_ids = data.get('pharmacy_ids', [])
    deleted_count = 0
    for pid in pharmacy_ids:
        pharmacy = db.query(Pharmacy).filter(Pharmacy.id == pid).first()
        if pharmacy:
            pharmacy.deleted_at = datetime.now()
            user = db.query(User).filter(User.pharmacy_id == pid).first()
            if user:
                user.deleted_at = datetime.now()
            deleted_count += 1
    
    db.commit()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='BULK_DELETE',
        resource_type='PHARMACY',
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        new_value={"deleted_count": deleted_count, "pharmacy_ids": pharmacy_ids}
    )
    
    return {"message": f"Deleted {deleted_count} pharmacies"}   

@router.post("/admin/pharmacy-admins")
async def create_pharmacy_admin(
    request: Request,
    data: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.is_super_admin:
        raise HTTPException(status_code=403, detail="Super admin only")
    
    # Check if pharmacy exists
    pharmacy = db.query(Organization).filter(Organization.id == data.get('pharmacy_id'), Organization.type == 'pharmacy').first()
    if not pharmacy:
        raise HTTPException(status_code=404, detail="Pharmacy not found")
    
    # Check if email exists
    existing = db.query(User).filter(User.email == data.get('email')).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create pharmacy admin user - using direct bcrypt
    hashed_password = hash_password(data['password'])
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password,
        role='pharmacy',
        pharmacy_id=data['pharmacy_id'],
        organization_id=data['pharmacy_id'],
        status='approved',
        name=data['name'],
        phone_number=data.get('phone_number'),
        is_active=True
    )
    db.add(new_user)
    db.commit()
    
    # ✅ AUDIT LOG
    log_audit(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        user_role=current_user.role.value,
        action='CREATE',
        resource_type='PHARMACY_ADMIN',
        resource_id=new_user.id,
        status='success',
        ip_address=request.client.host,
        user_agent=request.headers.get('user-agent'),
        new_value={"email": data['email'], "pharmacy_id": data['pharmacy_id']}
    )
    
    return {"message": "Pharmacy admin created", "id": new_user.id, "pharmacy_id": data['pharmacy_id']}