from pydantic import BaseModel
from .AttackClassType import AttackClassType
from typing import Optional


class Report(BaseModel):
    id: Optional[str]
    endpoint: str
    attack_class: AttackClassType | int
    response_body: str
    request_body: str
