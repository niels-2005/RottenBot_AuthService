from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # the database connection URL, needed to connect to the database
    DATABASE_URL: str

    # JWT settings, needed for authentication token generation and validation.
    JWT_SECRET: str
    JWT_ALGORITHM: str

    # Redis settings, needed for caching the authentication tokens.
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_PASSWORD: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# make it usable throughout the app
Config = Settings()
