import httpx
import base64
import json
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from app import auth, models
from app.config import settings
from sqlmodel import Session
from app import crud, database
from jose import jwt, JWTError

router = APIRouter()


@router.post("/token")
async def login_for_access_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(database.get_session),
):
    user = crud.get_user_by_username(db, username=form_data.username)
    if (
        not user
        or not user.hashed_password
        or not auth.verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(...)

    token_data = {"sub": user.username, "role": user.role}
    access_token = auth.create_access_token(data=token_data)
    refresh_token = auth.create_refresh_token(data={"sub": user.username})

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=True,
    )

    return {"message": "Login successful"}


@router.post("/token/refresh")
async def refresh_access_token(
    response: Response,
    request: Request,
    db: Session = Depends(database.get_session),
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            refresh_token,
            settings.JWT_REFRESH_SECRET_KEY,
            algorithms=[auth.REFRESH_TOKEN_ALGORITHM],
        )
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception

        user = crud.get_user_by_username(db, username=username)
        if user is None:
            raise credentials_exception

        new_access_token = auth.create_access_token(
            data={"sub": user.username, "role": user.role}
        )
        new_refresh_token = auth.create_refresh_token(data={"sub": user.username})

        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            samesite="lax",
            secure=False,
        )
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            samesite="lax",
            secure=False,
        )

        return {"message": "Token refreshed successfully"}
    except JWTError:
        raise credentials_exception


@router.get("/protected", dependencies=[Depends(auth.get_api_key)])
def read_protected_data():
    return {"data": "You have accessed protected data with an API Key."}


@router.post(
    "/users", response_model=models.UserPublic, status_code=status.HTTP_201_CREATED
)
def register_user(
    user_create: models.UserCreate, db: Session = Depends(database.get_session)
):
    existing_user = crud.get_user_by_username(db, username=user_create.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    user = crud.create_db_user(db, user_create=user_create)
    # if user.username == "admin1":
    #     crud.promote_user_to_admin(db, user)
    return user


@router.get("/users/me", response_model=models.UserPublic)
async def read_users_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


@router.get("/login/github")
async def login_github():
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&scope=read:user",
        status_code=302,
    )


@router.get("/auth/github/callback")
async def auth_github_callback(code: str, db: Session = Depends(database.get_session)):
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
    }
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            params=params,
            headers=headers,
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data.get("access_token")

        user_headers = {"Authorization": f"Bearer {access_token}"}
        user_response = await client.get(
            "https://api.github.com/user", headers=user_headers
        )
        user_response.raise_for_status()
        github_user_data = user_response.json()

    github_id = github_user_data["id"]
    user = crud.get_user_by_github_id(db, github_id=github_id)
    if user is None:
        user = crud.create_user_from_github(db, github_user_data=github_user_data)

    internal_jwt = auth.create_access_token(
        data={"sub": user.username, "role": user.role}
    )

    response = RedirectResponse(url=f"/api/dashboard?token={internal_jwt}")
    return response


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(token: str):
    return f"""
    <html>
        <head><title>Login Successful</title></head>
        <body>
            <h1>Welcome! You have successfully logged in.</h1>
            <p>Your application JWT is:</p>
            <p style="word-wrap:break-word;"><b>{token}</b></p>
            <p>You can now use this token to access protected endpoints like /api/users/me.</p>
        </body>
    </html>
    """


@router.get("/admin/users", response_model=list[models.UserPublic])
def get_all_users_as_admin(
    admin_user: models.User = Depends(auth.require_admin_user),
    db: Session = Depends(database.get_session),
):
    return crud.get_all_users(db)


@router.post("/admin/promote/{username}", response_model=models.UserPublic)
def promote_user(
    username: str,
    admin_user: models.User = Depends(auth.require_admin_user),
    db: Session = Depends(database.get_session),
):
    user_to_promote = crud.get_user_by_username(db, username=username)
    if not user_to_promote:
        raise HTTPException(status_code=404, detail="User not found")

    return crud.promote_user_to_admin(db, user=user_to_promote)


@router.post("/logout")
def logout(
    response: Response, request: Request, db: Session = Depends(database.get_session)
):
    token = request.cookies.get("access_token")

    if token:
        try:
            payload_part = token.split(".")[1]

            padded_payload = payload_part + "=" * (-len(payload_part) % 4)
            decoded_payload = base64.urlsafe_b64decode(padded_payload)
            payload = json.loads(decoded_payload)
            jti = payload.get("jti")

            if jti:
                crud.add_jti_to_blocklist(db, jti=jti)
        except Exception:
            pass

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logout successful"}
