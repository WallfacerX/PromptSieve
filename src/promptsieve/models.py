from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel


@dataclass(frozen=True)
class Segment:
    text: str
    field: str
    role: str
    source: str


class Finding(BaseModel):
    detector_id: str
    category: str
    severity: Literal["low", "medium", "high"]
    field: str
    reason: str


class Detector(Protocol):
    def inspect(self, segment: Segment) -> list[Finding]: ...


class ProxyError(Exception):
    def __init__(self, status: int, code: str, message: str, findings=()):
        self.status, self.code, self.message = status, code, message
        self.findings = list(findings)
