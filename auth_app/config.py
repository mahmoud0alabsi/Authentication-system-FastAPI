from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DB_USER: str
    DB_PASSWORD: str
    DB_HOST: str
    DB_NAME: str
    SECRET_KEY: str
    DB_PORT: int
    JWT_SECRET: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRES_MINUTES: int = 15 # default 5 minutes
    REFRESH_TOKEN_EXPIRES_MINUTES: int = 60 * 24 * 7 # default 7 days
    class Config:
        env_file = ".env"

settings = Settings()
