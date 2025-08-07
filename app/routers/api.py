import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from app import auth, models
from app.config import settings

router = APIRouter()


@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = models.fake_users_db.get(form_data.username)
    if not user or not auth.verify_password(
        form_data.password, user["hashed_password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = auth.create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/protected", dependencies=[Depends(auth.get_api_key)])
def read_protected_data():
    return {"data": "You have accessed protected data with an API Key."}


@router.get("/users/me")
async def read_users_me(current_user: dict = Depends(auth.get_current_user)):
    return current_user


@router.get("/login/github")
async def login_github():
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&scope=read:user",
        status_code=302,
    )


@router.get("/auth/github/callback")
async def auth_github_callback(code: str):
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
        return user_response.json()
