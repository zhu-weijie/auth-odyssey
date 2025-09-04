import secrets
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Session
from . import crud
from .database import get_session
from .config import settings
from . import models

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
api_key_header = APIKeyHeader(name="X-API-Key")
REFRESH_TOKEN_ALGORITHM = "HS256"


def get_token_from_cookie(request: Request) -> str | None:
    token = request.cookies.get("access_token")
    return token


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})
    to_encode.update({"iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE})
    to_encode.update({"jti": str(uuid.uuid4())})

    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_PRIVATE_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def get_api_key(api_key: str = Depends(api_key_header)):
    if not secrets.compare_digest(api_key, settings.API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )
    return api_key


async def get_current_user(
    token: str | None = Depends(get_token_from_cookie),
    db: Session = Depends(get_session),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    if token is None:
        raise credentials_exception
    try:
        payload = jwt.decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )

        jti = payload.get("jti")
        if jti is None:
            raise credentials_exception

        if crud.is_jti_in_blocklist(db, jti=jti):
            raise credentials_exception

        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception

        user = crud.get_user_by_username(db, username=username)

        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expires = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode.update({"exp": expires})
    to_encode.update({"jti": str(uuid.uuid4())})

    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_REFRESH_SECRET_KEY, algorithm=REFRESH_TOKEN_ALGORITHM
    )
    return encoded_jwt


def require_admin_user(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have administrative privileges",
        )
    return current_user
