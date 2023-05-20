from enum import Enum, auto


class AttackClassType(Enum):
    IDOR = auto()
    SSRF = auto()
    JWT = auto()
