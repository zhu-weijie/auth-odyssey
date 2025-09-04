from typing import Optional
from sqlmodel import Field, SQLModel
from datetime import datetime, timezone


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    email: Optional[str] = Field(index=True, unique=True, default=None)
    hashed_password: Optional[str] = None
    disabled: bool = False

    github_id: Optional[int] = Field(default=None, unique=True, index=True)

    role: str = Field(default="user", index=True)


class UserCreate(SQLModel):
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None


class UserPublic(SQLModel):
    id: int
    username: str
    full_name: Optional[str] = None
    disabled: bool
    role: str


class Token(SQLModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenBlocklist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    jti: str = Field(index=True, unique=True)
    created_at: datetime = Field(
        default_factory=datetime.now(timezone.utc), nullable=False
    )


class UsedRefreshToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    jti: str = Field(index=True, unique=True)
    created_at: datetime = Field(
        default_factory=datetime.now(timezone.utc), nullable=False
    )
