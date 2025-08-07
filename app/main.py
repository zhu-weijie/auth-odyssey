from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.routers import api
from app.database import create_db_and_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("INFO:     Lifespan startup: creating database and tables.")
    create_db_and_tables()
    yield
    print("INFO:     Lifespan shutdown.")


app = FastAPI(title="Auth-Odyssey", lifespan=lifespan)


@app.get("/")
def read_root():
    return {"message": "Welcome to Auth-Odyssey"}


app.include_router(api.router, prefix="/api")
