from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi import Body
from datetime import datetime, timedelta
import os
from . import schemas, models, database, auth
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

router = APIRouter()

@router.post("/signup")
def signup(user: schemas.UserCreate = Body, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(
        (models.User.email == user.email)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name = "",
        last_name = ""
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = auth.create_access_token(data={"sub": new_user.username})

    return {
        "user_id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "access_token": access_token,
        "token_type": "bearer"
    }
    # return new_user

@router.post("/login")
def login(form_data: schemas.UserLogin, db: Session = Depends(database.get_db)):
    user = auth.authenticate_user(form_data.email, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token = auth.create_access_token(data={"sub": user.email})
    print(user.otp)
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id, "username": user.username, "email": user.email}

@router.get("/users", response_model=list[schemas.UserOut])
def get_all_users(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    return db.query(models.User).all()

@router.patch("/users/{user_id}", response_model=schemas.UserOut)
def update_user(
    user_id: int,
    updated_data: schemas.UserUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this user")

    update_data = updated_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        if key == "password":
            value = auth.get_password_hash(value)
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return user


@router.get("/users/{user_id}", response_model=schemas.UserOut)
def get_user_by_id(
    user_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# @router.delete("/users/{user_id}")
# def delete_user(
#     user_id: int,
#     db: Session = Depends(database.get_db),
#     current_user: models.User = Depends(auth.get_current_user),
# ):
#     user = db.query(models.User).filter(models.User.id == user_id).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     # Only allow deleting self (or add admin logic here)
#     if user.id != current_user.id:
#         raise HTTPException(status_code=403, detail="Not authorized to delete this user")

#     db.delete(user)
#     db.commit()
#     return {"detail": f"User with ID {user_id} deleted successfully"}


@router.post("/forgot-password")
def forgot_password(request: schemas.ForgotPassword, db: Session = Depends(database.get_db)):
    """Send OTP to user's email for password reset"""
    user = db.query(models.User).filter(models.User.email == request.email).first()
    print(user)
    if not user:
        # Return success even if user doesn't exist for security
        return {"message": "If the email exists, an OTP has been sent"}
    
    # Generate OTP and set expiration
    otp = auth.generate_otp()
    otp_expires = datetime.utcnow() + timedelta(minutes=10)  # OTP expires in 10 minutes
    
    # Update user with OTP
    user.otp = otp
    user.otp_expires = otp_expires
    db.commit()
    
    # Send OTP via email
    if auth.send_otp_email(user.email, otp):
        return {"message": "OTP sent to your email address"}
    else:
        raise HTTPException(
            status_code=500, 
            detail="Failed to send email. Please try again later."
        )

@router.post("/reset-password")
def reset_password(request: schemas.ResetPassword, db: Session = Depends(database.get_db)):
    """Reset password using OTP"""
    user = db.query(models.User).filter(models.User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify OTP
    if not auth.verify_otp(user, request.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # Hash new password and update user
    hashed_password = auth.get_password_hash(request.new_password)
    user.password = hashed_password
    user.otp = None  # Clear OTP
    user.otp_expires = None  # Clear OTP expiration
    
    db.commit()
    
    return {"message": "Password reset successfully"}

@router.post("/change-password")
def change_password(
    request: schemas.ChangePassword,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    """Change password with current password validation"""
    # Verify current password
    if not auth.verify_password(request.current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Hash new password and update
    hashed_password = auth.get_password_hash(request.new_password)
    current_user.password = hashed_password
    
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.delete("/users")
def delete_user(
    credentials: schemas.UserDelete,
    db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.email == credentials.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify password
    if not auth.verify_password(credentials.password, user.password):
        raise HTTPException(status_code=403, detail="Password is incorrect")

    db.delete(user)
    db.commit()
    return {"detail": f"User with email {credentials.email} deleted successfully"}


@router.post("/apple_signin")
def apple_signin(user: schemas.AppleLoginRequest = Body, db: Session = Depends(database.get_db)):
    try:
        db_user = db.query(models.User).filter(
        (models.User.email == user.email)
        ).first()
    except:
        db_user = db.query(models.User).filter(
        (models.User.user_token == user.user_token)
        ).first()

    if db_user:
        db_user.user_token = user.user_token
        db_user.login_type = user.login_type
        if user.username != "" and user.username is not None:
            db_user.username = user.username
        db.commit()
        access_token = auth.create_access_token(data={"sub": db_user.email})
        return {
        "user_id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "access_token": access_token,
        "token_type": "bearer",
        "login_type": user.login_type,
    }
    hashed_password = auth.get_password_hash("secret")

    new_user = models.User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        first_name = "",
        last_name = "",
        user_token=user.user_token,
        login_type=user.login_type,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = auth.create_access_token(data={"sub": new_user.email})

    return {
        "user_id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "access_token": access_token,
        "token_type": "bearer",
        "login_type": new_user.login_type,
    }


@router.post("/answer", response_model=schemas.AnswerResponse)
async def ask_question(request: schemas.QuestionRequest):
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }

    payload = {
        "model": "gpt-4o-mini",  # you can change to "gpt-4o" or "gpt-5" if available
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": request.question}
        ],
        "max_tokens": 500
    }

    try:
        response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
        response.raise_for_status()  # raise exception if not 2xx

        data = response.json()
        answer = data["choices"][0]["message"]["content"].strip()

        return {"answer": answer}

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Request error: {e}")
    except KeyError:
        raise HTTPException(status_code=500, detail="Invalid response from OpenAI API.")
