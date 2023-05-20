from ipaddress import IPv4Address
from os import getenv

from dotenv import load_dotenv
from pydantic import BaseSettings, validator

load_dotenv()


class Settings(BaseSettings):
    HOST: str
    REPORTING_PORT: int

    DATABASE_NAME: str

    DEV_MODE: bool = False

    @validator("HOST", always=True)
    def host_validator(cls, v):
        return str(IPv4Address(getenv("HOST")))

    @validator("REPORTING_PORT", always=True)
    def reporting_port_validator(cls, v):
        return int(getenv("REPORTING_PORT"))


settings = Settings()
