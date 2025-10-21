from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import models, database
from .email_service import send_otp_email  # Import from separate file
import string
import random

SECRET_KEY = "Gk3X9cLt7HvQjFlbYZkGZ6zzOqM1-Y-fM4TeqVu6P-0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str, db: Session):
    return db.query(models.User).filter(models.User.email == username).first()

def authenticate_user(username: str, password: str, db: Session):
    user = get_user(username, db)
    if user and verify_password(password, user.password):
        return user
    return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(username)
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(username, db)
    if user is None:
        raise credentials_exception
    return user


def generate_otp(length: int = 6) -> str:
    """Generate alphanumeric OTP"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def verify_otp(user, otp: str) -> bool:
    """Verify if OTP is valid and not expired"""
    if not user.otp or not user.otp_expires:
        print("In first")
        return False
    
    if datetime.utcnow() > user.otp_expires:
        print("in second")
        return False
    
    return user.otp == otp