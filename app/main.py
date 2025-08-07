from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.routers import api
from app.database import create_db_and_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("INFO:     Lifespan startup: creating database and tables.")
    create_db_and_tables()
    yield
    print("INFO:     Lifespan shutdown.")


app = FastAPI(title="Auth-Odyssey", lifespan=lifespan)

app.include_router(api.router, prefix="/api")

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def read_index():
    return FileResponse("static/index.html")
