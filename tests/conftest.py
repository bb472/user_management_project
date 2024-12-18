"""
File: test_database_operations.py

Overview:
This test file manages the testing environment for a FastAPI application using SQLAlchemy and pytest.
It provides fixtures for clean database states, asynchronous HTTP clients, user setups, and mock services.

Fixtures:
- `async_client`: Provides an asynchronous HTTP client for API testing.
- `db_session`: Ensures clean database transactions for each test.
- User fixtures (`user`, `locked_user`, `verified_user`, etc.): Prepares various user states.
- `token` fixtures: Generates authentication tokens for testing secured endpoints.
- `setup_database`: Creates and drops database schema before and after tests.
- `email_service`: Mocks or returns the real email service depending on settings.
"""

# Standard library imports
from builtins import Exception, range, str
from datetime import timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

# Third-party imports
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, scoped_session
from faker import Faker

# Application-specific imports
from app.main import app
from app.database import Base, Database
from app.models.user_model import User, UserRole
from app.dependencies import get_db, get_settings
from app.utils.security import hash_password
from app.services.email_service import EmailService
from app.services.jwt_service import create_access_token
from app.utils.template_manager import TemplateManager

# Constants and settings
fake = Faker()
settings = get_settings()
TEST_DATABASE_URL = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")

# Async engine and session setup
engine = create_async_engine(TEST_DATABASE_URL, echo=settings.debug)
AsyncTestingSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
AsyncSessionScoped = scoped_session(AsyncTestingSessionLocal)


# ----------------- Database Setup Fixtures ----------------- #

@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    """Initialize the database schema once per session."""
    try:
        Database.initialize(settings.database_url)
    except Exception as e:
        pytest.fail(f"Failed to initialize the database: {str(e)}")


@pytest.fixture(scope="function", autouse=True)
async def setup_database():
    """Setup and teardown the database for each test function."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(setup_database):
    """Provide a clean database session for each test."""
    async with AsyncSessionScoped() as session:
        try:
            yield session
        finally:
            await session.close()


# ----------------- Async HTTP Client Fixture ----------------- #

@pytest.fixture(scope="function")
async def async_client(db_session):
    """Asynchronous HTTP client for testing FastAPI endpoints."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        app.dependency_overrides[get_db] = lambda: db_session
        try:
            yield client
        finally:
            app.dependency_overrides.clear()


# ----------------- Mocked Email Service ----------------- #

@pytest.fixture
def email_service():
    """Mock email service to prevent sending real emails."""
    if settings.send_real_mail == "true":
        return EmailService()
    else:
        mock_service = AsyncMock(spec=EmailService)
        mock_service.send_verification_email.return_value = None
        mock_service.send_user_email.return_value = None
        return mock_service


# ----------------- User Fixtures ----------------- #

@pytest.fixture(scope="function")
async def user(db_session):
    """Create a standard user."""
    user_data = {
        "nickname": fake.user_name(),
        "email": fake.email(),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "hashed_password": hash_password("Password123!"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def verified_user(db_session):
    """Create a verified user."""
    user_data = {
        "nickname": fake.user_name(),
        "email": fake.email(),
        "hashed_password": hash_password("Password123!"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": True,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def locked_user(db_session):
    """Create a locked user."""
    user_data = {
        "nickname": fake.user_name(),
        "email": fake.email(),
        "hashed_password": hash_password("Password123!"),
        "role": UserRole.AUTHENTICATED,
        "is_locked": True,
        "failed_login_attempts": settings.max_login_attempts,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def users_with_same_role_50_users(db_session):
    """Create 50 users with the same role for pagination tests."""
    users = []
    for _ in range(50):
        user_data = {
            "nickname": fake.user_name(),
            "email": fake.email(),
            "hashed_password": hash_password("Password123!"),
            "role": UserRole.AUTHENTICATED,
            "is_locked": False,
        }
        user = User(**user_data)
        db_session.add(user)
        users.append(user)
    await db_session.commit()
    return users


# ----------------- Token Fixtures ----------------- #

@pytest.fixture(scope="function")
def admin_token(admin_user):
    """Generate a token for an admin user."""
    return create_access_token(data={"sub": str(admin_user.id), "role": admin_user.role.name}, expires_delta=timedelta(minutes=30))


@pytest.fixture(scope="function")
def user_token(user):
    """Generate a token for a regular user."""
    return create_access_token(data={"sub": str(user.id), "role": user.role.name}, expires_delta=timedelta(minutes=30))


@pytest.fixture(scope="function")
def manager_token(manager_user):
    """Generate a token for a manager user."""
    return create_access_token(data={"sub": str(manager_user.id), "role": manager_user.role.name}, expires_delta=timedelta(minutes=30))


# ----------------- Role-based User Fixtures ----------------- #

@pytest.fixture(scope="function")
async def admin_user(db_session):
    """Create an admin user."""
    user = User(
        nickname="admin_user",
        email="admin@example.com",
        hashed_password=hash_password("AdminPassword123!"),
        role=UserRole.ADMIN,
        is_locked=False,
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def manager_user(db_session):
    """Create a manager user."""
    user = User(
        nickname="manager_user",
        email="manager@example.com",
        hashed_password=hash_password("ManagerPassword123!"),
        role=UserRole.MANAGER,
        is_locked=False,
    )
    db_session.add(user)
    await db_session.commit()
    return user
