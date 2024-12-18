from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re
from app.models.user_model import UserRole
from app.utils.nickname_gen import generate_nickname


def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")
    role: UserRole

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
 
    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

    @validator("email")
    def validate_email(cls, value):
        # Configurable list of allowed domains
        allowed_domains = {"example.com", "test.org"}
        # Extract domain from email
        domain = value.split("@")[-1].lower()
        if domain not in allowed_domains:
            raise ValueError(f"Email domain must be one of {', '.join(allowed_domains)}.")
        # Check for prohibited patterns in the username
        username = value.split("@")[0].lower()
        if re.search(r"admin", username):
            raise ValueError("Email username cannot contain 'admin'.")
        return value

    @validator("password")
    def validate_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in value):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError("Password must contain at least one special character.")
        return value

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, max_length=30, regex=r'^[a-zA-Z0-9_-]+$', example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[HttpUrl] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[HttpUrl] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[HttpUrl] = Field(None, example="https://github.com/johndoe")
    role: Optional[str] = Field(None, example="AUTHENTICATED")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

    @validator("nickname", pre=True)
    def validate_nickname(cls, value):
        """Validate nickname rules."""
        if value and (not re.match(r'^[a-zA-Z0-9_-]+$', value)):
            raise ValueError("Nickname must contain only alphanumeric characters, underscores, or hyphens.")
        return value
    
    @validator("profile_picture_url")
    def validate_profile_picture_url(cls, value):
        """Restrict profile picture URL to common image formats."""
        if value and not value.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
            raise ValueError("Profile picture URL must link to a valid image file (.png, .jpg, .jpeg, .gif).")
        return value

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())    
    is_professional: Optional[bool] = Field(default=False, example=True)
    role: UserRole

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "last_name": "Doe", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)
    