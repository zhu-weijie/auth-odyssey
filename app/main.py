from fastapi import FastAPI
from app.routers import api
from app.database import create_db_and_tables

app = FastAPI(title="Auth-Odyssey")


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
def read_root():
    return {"message": "Welcome to Auth-Odyssey"}


app.include_router(api.router, prefix="/api")
