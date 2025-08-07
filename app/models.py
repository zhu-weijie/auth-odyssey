from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


fake_users_db = {
    "john.doe": {
        "username": "john.doe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("secretpassword"),
        "disabled": False,
    }
}


def get_or_create_user_from_github(github_user: dict):
    github_id = github_user.get("id")

    for user in fake_users_db.values():
        if user.get("github_id") == github_id:
            return user

    new_user = {
        "username": github_user.get("login"),
        "github_id": github_id,
        "full_name": github_user.get("name"),
        "email": github_user.get("email"),
        "hashed_password": None,  # No password for OAuth users
        "disabled": False,
    }
    fake_users_db[new_user["username"]] = new_user
    return new_user
