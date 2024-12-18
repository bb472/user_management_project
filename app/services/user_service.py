from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import logging
import secrets
from typing import Optional, Dict, List
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import func, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_email_service, get_settings
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password

# Settings and Logger
settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        """Helper to execute a query and commit."""
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        """Fetch a single user based on filters."""
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        """Retrieve a user by ID."""
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        """Retrieve a user by email."""
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        """Retrieve a user by nickname."""
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service) -> Optional[User]:
        """Create a new user with duplicate email validation."""
        try:
            validated_data = UserCreate(**user_data).model_dump()
            
            # Check for duplicate email
            if await cls.get_by_email(session, validated_data['email']):
                logger.error("User with this email already exists.")
                return None
            
            # Generate hashed password
            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            
            # Assign nickname ensuring uniqueness
            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            
            new_user = User(**validated_data, nickname=new_nickname)
            
            # Assign role
            user_count = await cls.count(session)
            new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS
            
            # Handle email verification
            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True
            else:
                new_user.verification_token = generate_verification_token()
                await email_service.send_verification_email(new_user)
            
            # Save user
            session.add(new_user)
            await session.commit()
            logger.info(f"User {new_user.email} created successfully.")
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during user creation: {e}")
        return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        """Update user information."""
        try:
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            # Hash new password if provided
            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            query = (
                update(User)
                .where(User.id == user_id)
                .values(**validated_data)
                .execution_options(synchronize_session="fetch")
            )
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            
            if updated_user:
                session.refresh(updated_user)
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
        except ValidationError as e:
            logger.error(f"Validation error during update: {e}")
        except Exception as e:
            logger.error(f"Error during user update: {e}")
        return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        """Delete a user by ID."""
        try:
            user = await cls.get_by_id(session, user_id)
            if user:
                await session.delete(user)
                await session.commit()
                logger.info(f"User {user_id} deleted successfully.")
                return True
        except Exception as e:
            logger.error(f"Error during user deletion: {e}")
        return False

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        """Authenticate a user by email and password."""
        user = await cls.get_by_email(session, email)
        if user and not user.is_locked and user.email_verified:
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                logger.info(f"User {email} logged in successfully.")
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                session.add(user)
                await session.commit()
        return None

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """Count the total number of users."""
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        return result.scalar_one()

    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        """Unlock a user account."""
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0
            session.add(user)
            await session.commit()
            logger.info(f"User {user_id} account unlocked.")
            return True
        return False
