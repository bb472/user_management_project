import pytest
from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.services.user_service import UserService
from app.utils.nickname_gen import generate_nickname

pytestmark = pytest.mark.asyncio


# Test creating a user with valid data
async def test_create_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "valid_user@example.com",
        "password": "ValidPassword123!",
        "role": UserRole.ADMIN.name
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is not None, "User creation with valid data should succeed"
    assert user.email == user_data["email"], "Email should match the input data"


# Test creating a user with invalid data
async def test_create_user_with_invalid_data(db_session, email_service):
    user_data = {
        "nickname": "",  # Invalid nickname
        "email": "invalidemail",  # Invalid email format
        "password": "short",  # Too short password
    }
    user = await UserService.create(db_session, user_data, email_service)
    assert user is None, "User creation with invalid data should fail"


# Test fetching a user by ID when the user exists
async def test_get_by_id_user_exists(db_session, user):
    retrieved_user = await UserService.get_by_id(db_session, user.id)
    assert retrieved_user is not None, "User should exist in the database"
    assert retrieved_user.id == user.id, "Retrieved user ID should match the test user ID"


# Test fetching a user by ID when the user does not exist
async def test_get_by_id_user_does_not_exist(db_session):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"
    retrieved_user = await UserService.get_by_id(db_session, non_existent_user_id)
    assert retrieved_user is None, "Retrieving a non-existent user should return None"


# Test updating a user with valid data
async def test_update_user_valid_data(db_session, user):
    updated_data = {"email": "updated_email@example.com"}
    updated_user = await UserService.update(db_session, user.id, updated_data)
    assert updated_user is not None, "Updating user with valid data should succeed"
    assert updated_user.email == updated_data["email"], "Email should be updated"


# Test deleting a user who exists
async def test_delete_user_exists(db_session, user):
    success = await UserService.delete(db_session, user.id)
    assert success, "Deleting an existing user should succeed"
    deleted_user = await UserService.get_by_id(db_session, user.id)
    assert deleted_user is None, "Deleted user should not exist in the database"


# Test listing users with pagination
async def test_list_users_with_pagination(db_session, users_with_same_role_50_users):
    users_page_1 = await UserService.list_users(db_session, skip=0, limit=10)
    users_page_2 = await UserService.list_users(db_session, skip=10, limit=10)
    assert len(users_page_1) == 10, "First page should contain 10 users"
    assert len(users_page_2) == 10, "Second page should contain 10 users"
    assert users_page_1[0].id != users_page_2[0].id, "Users in different pages should not overlap"


# Test registering a user with valid data
async def test_register_user_with_valid_data(db_session, email_service):
    user_data = {
        "nickname": generate_nickname(),
        "email": "register_valid_user@example.com",
        "password": "RegisterValid123!",
    }
    user = await UserService.register_user(db_session, user_data, email_service)
    assert user is not None, "Registering a user with valid data should succeed"
    assert user.email == user_data["email"], "Email should match the input data"


# Test resetting a user's password
async def test_reset_password(db_session, user):
    new_password = "NewSecurePassword123!"
    reset_success = await UserService.reset_password(db_session, user.id, new_password)
    assert reset_success, "Password reset should succeed"
    logged_in_user = await UserService.login_user(db_session, user.email, new_password)
    assert logged_in_user is not None, "User should be able to log in with the new password"


# Test account lock after maximum failed login attempts
async def test_account_lock_after_failed_logins(db_session, verified_user):
    max_attempts = get_settings().max_login_attempts
    for _ in range(max_attempts):
        await UserService.login_user(db_session, verified_user.email, "wrongpassword")
    is_locked = await UserService.is_account_locked(db_session, verified_user.email)
    assert is_locked, "Account should be locked after max failed login attempts"


# Test verifying a user's email with a valid token
async def test_verify_email_with_token(db_session, user):
    token = "valid_token_example"
    user.verification_token = token
    await db_session.commit()

    result = await UserService.verify_email_with_token(db_session, user.id, token)
    assert result, "Email verification with a valid token should succeed"

    refreshed_user = await UserService.get_by_id(db_session, user.id)
    assert refreshed_user.email_verified, "User's email should be marked as verified"


# Test unlocking a user's account
async def test_unlock_user_account(db_session, locked_user):
    unlocked = await UserService.unlock_user_account(db_session, locked_user.id)
    assert unlocked, "Unlocking the account should succeed"

    refreshed_user = await UserService.get_by_id(db_session, locked_user.id)
    assert not refreshed_user.is_locked, "User's account should be unlocked"
