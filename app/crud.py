from sqlmodel import Session, select
from . import models, auth


def get_user_by_username(db: Session, username: str) -> models.User | None:
    statement = select(models.User).where(models.User.username == username)
    return db.exec(statement).first()


def get_user_by_github_id(db: Session, github_id: int) -> models.User | None:
    statement = select(models.User).where(models.User.github_id == github_id)
    return db.exec(statement).first()


def create_user_from_github(db: Session, github_user_data: dict) -> models.User:
    db_user = models.User(
        username=github_user_data["login"],
        github_id=github_user_data["id"],
        full_name=github_user_data.get("name"),
        email=github_user_data.get("email"),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_db_user(db: Session, user_create: models.UserCreate) -> models.User:
    hashed_password = auth.pwd_context.hash(user_create.password)

    db_user = models.User(
        username=user_create.username,
        full_name=user_create.full_name,
        email=user_create.email,
        hashed_password=hashed_password,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
