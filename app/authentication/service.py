from sqlalchemy.orm import Session
import bcrypt
from app.models import User
from .schemas import UserRegister, UserLogin

def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode('utf-8')[:72]
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hashed_bytes)

def create_user(db: Session, user: UserRegister, organization_id: int):
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role,
        
        # COMMON FIELDS FOR ALL USERS
        name=user.name,
        phone_number=user.phone_number,
        emirates_id=user.emirates_id,
        passport_number=user.passport_number,
        
        # STAFF-SPECIFIC FIELDS
        specialization=user.specialization,
        department=user.department,
        
        organization_id=organization_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user