from .database import Base
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    username = Column(String, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    otp = Column(String, nullable=True)
    otp_expires = Column(DateTime, nullable=True)
    user_token = Column(String, unique=True, nullable=True)  # Apple unique ID
    login_type = Column(String, nullable=True)
