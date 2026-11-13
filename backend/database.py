import os
from pathlib import Path
from dotenv import load_dotenv
from sqlmodel import SQLModel, Session, create_engine

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishing.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)


def init_db() -> None:
    from . import models  # noqa: F401  (registers tables)
    from .security import hash_password
    SQLModel.metadata.create_all(engine)
    
    # Pre-seed default Admin and Demo User if not present
    with Session(engine) as session:
        admin_user = session.exec(models.select(models.User).where(models.User.username == "admin")).first()
        if not admin_user:
            admin_user = models.User(
                username="admin",
                email="admin@tripwire.io",
                password_hash=hash_password("Admin@Tripwire2026!"),
                role="admin",
                is_active=True
            )
            session.add(admin_user)
            
        demo_user = session.exec(models.select(models.User).where(models.User.username == "user")).first()
        if not demo_user:
            demo_user = models.User(
                username="user",
                email="user@tripwire.io",
                password_hash=hash_password("User@Tripwire2026!"),
                role="user",
                is_active=True
            )
            session.add(demo_user)
        session.commit()


def get_session():
    with Session(engine) as session:
        yield session
