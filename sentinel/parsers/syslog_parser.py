"""
Парсер журналов авторизации Linux (auth.log / secure / syslog).
"""

from datetime import datetime
import re
from typing import Optional
from sentinel.parsers.base_parser import BaseLogParser, ParsedEvent

# Примеры строк:
# Oct 24 14:23:10 server sshd[14221]: Failed password for invalid user root from 198.51.100.22 port 51234 ssh2
# Oct 24 14:24:02 server sshd[14225]: Accepted publickey for alex from 10.0.0.15 port 42112 ssh2
SSH_FAIL_REGEX = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+(?:for\s+(?:invalid\s+user\s+)?(?P<user>\S+))\s+from\s+(?P<ip>\S+)'
)
SSH_ACCEPT_REGEX = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
)


class SyslogParser(BaseLogParser):
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None

        # Проверка неудачной аутентификации SSH
        m_fail = SSH_FAIL_REGEX.search(line)
        if m_fail:
            data = m_fail.groupdict()
            now = datetime.now()
            time_str = f"{now.year}-{data['month']}-{data['day']} {data['time']}"
            return ParsedEvent(
                timestamp=time_str,
                source_ip=data["ip"],
                service="SSH",
                event_type="AUTH_FAIL",
                status="FAILURE",
                user=data.get("user", "unknown"),
                message=f"Failed SSH login for user '{data.get('user')}'",
                raw_log=line
            )

        # Проверка успешной аутентификации SSH
        m_acc = SSH_ACCEPT_REGEX.search(line)
        if m_acc:
            data = m_acc.groupdict()
            now = datetime.now()
            time_str = f"{now.year}-{data['month']}-{data['day']} {data['time']}"
            return ParsedEvent(
                timestamp=time_str,
                source_ip=data["ip"],
                service="SSH",
                event_type="AUTH_SUCCESS",
                status="SUCCESS",
                user=data.get("user", "unknown"),
                message=f"Successful SSH login for user '{data.get('user')}'",
                raw_log=line
            )

        return None

