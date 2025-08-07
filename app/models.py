from typing import Optional
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    email: Optional[str] = Field(index=True, unique=True, default=None)
    hashed_password: Optional[str] = None
    disabled: bool = False

    github_id: Optional[int] = Field(default=None, unique=True, index=True)


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
