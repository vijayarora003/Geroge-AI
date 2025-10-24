from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    first_name: Optional[str] = "-"
    last_name: Optional[str] = "-"
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    first_name: Optional[str]
    last_name: Optional[str]
    username: str
    email: EmailStr

    class Config:
        orm_mode = True



class UserUpdate(BaseModel):
    username: Optional[str]


class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class UserDelete(BaseModel):
    email: EmailStr
    password: str

class AppleLoginRequest(BaseModel):
    user_token: str
    login_type: str
    email: str
    username: str

# Request model
class QuestionRequest(BaseModel):
    question: str

# Response model
class AnswerResponse(BaseModel):
    answer: str