from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    API_KEY: str

    JWT_SECRET_KEY: str
    JWT_REFRESH_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ISSUER: str
    JWT_AUDIENCE: str
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str

    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str

    ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
