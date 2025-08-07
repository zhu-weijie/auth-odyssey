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
