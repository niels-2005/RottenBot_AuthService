from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str

    JWT_SECRET: str
    JWT_ALGORITHM: str

    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_PASSWORD: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# make it usable throughout the app
Config = Settings()
