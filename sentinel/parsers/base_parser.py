"""
Базовый класс парсера событий безопасности.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class ParsedEvent:
    timestamp: str
    source_ip: str
    service: str          # NGINX, SSH, WINDOWS, FIREWALL
    event_type: str       # AUTH_FAIL, AUTH_SUCCESS, WEB_REQUEST, PRIVILEGE_USE
    status: str           # SUCCESS, FAILURE, SUSPICIOUS
    user: Optional[str]
    message: str
    raw_log: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseLogParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        pass

