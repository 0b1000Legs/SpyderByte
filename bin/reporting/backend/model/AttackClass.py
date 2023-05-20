from pydantic import BaseModel, validator
from .AttackClassType import AttackClassType
from .Report import Report
from typing import List, Optional
from .constants import ATTACK_CLASS_DETAILS


class AttackClassReports(BaseModel):
    type: AttackClassType
    reports: List[Report] = []

    name: Optional[str]
    acronym: Optional[str]
    description: Optional[str]

    @validator("name", always=True)
    def name_validator(cls, v, values):
        return ATTACK_CLASS_DETAILS[values["type"]]["name"]

    @validator("acronym", always=True)
    def acronym_validator(cls, v, values):
        return ATTACK_CLASS_DETAILS[values["type"]]["acronym"]

    @validator("description", always=True)
    def description_validator(cls, v, values):
        return ATTACK_CLASS_DETAILS[values["type"]]["description"]
