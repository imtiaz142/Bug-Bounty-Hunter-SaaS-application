"""Seed script to create a demo user."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from app.core.config import get_settings
from app.core.security import hash_password
from app.models.user import User
import uuid

settings = get_settings()
engine = create_engine(settings.DATABASE_URL_SYNC)
SessionLocal = sessionmaker(bind=engine)


def seed():
    session = SessionLocal()
    try:
        existing = session.execute(
            select(User).where(User.email == "demo@bugbounty.com")
        ).scalar_one_or_none()

        if existing:
            print("Demo user already exists, skipping seed.")
            return

        demo_user = User(
            id=uuid.uuid4(),
            email="demo@bugbounty.com",
            username="demo",
            password_hash=hash_password("Demo1234!"),
        )
        session.add(demo_user)
        session.commit()
        print(f"Demo user created: demo@bugbounty.com / Demo1234!")
    except Exception as e:
        print(f"Seed error (may be first run): {e}")
        session.rollback()
    finally:
        session.close()


if __name__ == "__main__":
    seed()
