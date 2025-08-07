import os
import secrets
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader


load_dotenv()

app = FastAPI()


api_key_header = APIKeyHeader(name="X-API-Key")


SECRET_API_KEY = os.getenv("API_KEY")


async def get_api_key(api_key: str = Depends(api_key_header)):
    if SECRET_API_KEY is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key not configured on the server.",
        )

    if secrets.compare_digest(api_key, SECRET_API_KEY):
        return api_key
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )


@app.get("/")
def read_root():
    return {"message": "Hello, Auth-Odyssey!"}


@app.get("/api/protected", dependencies=[Depends(get_api_key)])
def read_protected_data():
    return {"data": "You have accessed protected data."}
