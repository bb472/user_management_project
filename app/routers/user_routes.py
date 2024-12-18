from datetime import timedelta
from uuid import UUID
from fastapi import (
    APIRouter, Depends, HTTPException, Response, status, Request
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import (
    get_current_user, get_db, get_email_service, require_role, get_settings
)
from app.schemas.pagination_schema import EnhancedPagination
from app.schemas.token_schema import TokenResponse
from app.schemas.user_schemas import (
    UserBase, UserCreate, UserListResponse, UserResponse, UserUpdate
)
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.utils.link_generation import create_user_links, generate_pagination_links

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
settings = get_settings()


# ------------------ User Management Endpoints ------------------ #

@router.get("/users/{user_id}", response_model=UserResponse, tags=["User Management"])
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Fetch user details by user ID.
    """
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        **user.__dict__, links=create_user_links(user.id, request)
    )


@router.put("/users/{user_id}", response_model=UserResponse, tags=["User Management"])
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Update user details.
    """
    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)

    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        **updated_user.__dict__, links=create_user_links(updated_user.id, request)
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["User Management"])
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Delete a user by ID.
    """
    if not await UserService.delete(db, user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["User Management"])
async def create_user(
    user: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email_service = Depends(get_email_service),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    Create a new user.
    """
    if await UserService.get_by_email(db, user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    created_user = await UserService.create(db, user.model_dump(), email_service)

    if not created_user:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

    return UserResponse.model_construct(
        **created_user.__dict__, links=create_user_links(created_user.id, request)
    )


@router.get("/users/", response_model=UserListResponse, tags=["User Management"])
async def list_users(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"]))
):
    """
    List users with pagination support.
    """
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)

    user_responses = [UserResponse.model_validate(user) for user in users]
    pagination_links = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=user_responses,
        total=total_users,
        page=skip // limit + 1,
        size=len(user_responses),
        links=pagination_links
    )


# ------------------ Login and Registration Endpoints ------------------ #

@router.post("/register/", response_model=UserResponse, tags=["Authentication"])
async def register_user(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db),
    email_service = Depends(get_email_service)
):
    """
    Register a new user.
    """
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    if not user:
        raise HTTPException(status_code=400, detail="Email already exists")
    return user


@router.post("/login/", response_model=TokenResponse, tags=["Authentication"])
async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db)
):
    """
    Authenticate a user and provide an access token.
    """
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(status_code=400, detail="Account locked due to too many failed login attempts.")

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.email, "role": str(user.role.name)},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/verify-email/{user_id}/{token}", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def verify_email(
    user_id: UUID,
    token: str,
    db: AsyncSession = Depends(get_db),
    email_service = Depends(get_email_service)
):
    """
    Verify a user's email using the token provided.
    """
    if not await UserService.verify_email_with_token(db, user_id, token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")
    return {"message": "Email verified successfully"}
