from fastapi import FastAPI
from app.routers import api

app = FastAPI(title="Auth-Odyssey")


@app.get("/")
def read_root():
    return {"message": "Welcome to Auth-Odyssey"}


app.include_router(api.router, prefix="/api")
