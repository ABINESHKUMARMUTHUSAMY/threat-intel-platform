from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    postgres_user: str = "threat"
    postgres_password: str = "changeme"
    postgres_db: str = "threat_intel"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    redis_host: str = "redis"
    redis_port: int = 6379

    jwt_secret: str = "changeme"
    jwt_algorithm: str = "HS256"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    class Config:
        env_file = ".env"


settings = Settings()
