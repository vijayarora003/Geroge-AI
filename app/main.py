from fastapi import FastAPI
from . import models, database
from .routes import router
from sqlalchemy import text

app = FastAPI()


def migrate_database():
    """Add missing columns to existing tables"""
    with database.engine.connect() as connection:
        try:
            # Check if columns exist
            result = connection.execute(text("PRAGMA table_info(users)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'otp' not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN otp VARCHAR"))
                print("Added otp column")
            
            if 'otp_expires' not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN otp_expires DATETIME"))
                print("Added otp_expires column")
            
            connection.commit()
        except Exception as e:
            print(f"Migration error: {e}")



models.Base.metadata.create_all(bind=database.engine)

migrate_database()

app.include_router(router)
