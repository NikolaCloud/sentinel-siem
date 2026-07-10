"""
Парсер журналов веб-серверов (Nginx / Apache combined log format).
"""

from datetime import datetime
import re
from typing import Optional
from sentinel.parsers.base_parser import BaseLogParser, ParsedEvent

COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


class WebLogParser(BaseLogParser):
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None

        match = COMBINED_LOG_REGEX.match(line)
        if not match:
            return None

        data = match.groupdict()
        status_code = int(data["status"])
        method = data["method"]
        uri = data["uri"]
        ip = data["ip"]
        user = data["user"] if data["user"] != "-" else None

        # Преобразование времени Nginx (например: 10/Oct/2026:13:55:36 +0300)
        try:
            dt = datetime.strptime(data["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
            time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        status = "SUCCESS" if status_code < 400 else ("FAILURE" if status_code >= 500 else "SUSPICIOUS")

        return ParsedEvent(
            timestamp=time_str,
            source_ip=ip,
            service="NGINX",
            event_type="WEB_REQUEST",
            status=status,
            user=user,
            message=f"{method} {uri} (HTTP {status_code})",
            raw_log=line
        )

