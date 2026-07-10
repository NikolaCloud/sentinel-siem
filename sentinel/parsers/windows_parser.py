"""
Парсер событий безопасности Windows Event Log (Security.evtx / CSV экспорт).
"""

from datetime import datetime
import re
from typing import Optional
from sentinel.parsers.base_parser import BaseLogParser, ParsedEvent


class WindowsEventParser(BaseLogParser):
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        line = line.strip()
        if not line:
            return None

        # Пример: 2026-10-24 16:40:12, EventID=4625, User=Administrator, IP=192.168.1.105, Status=0xC000006D
        if "EventID=" not in line and "EventId=" not in line:
            return None

        event_id = None
        m_id = re.search(r"EventID[=:\s]+(\d+)", line, re.I)
        if m_id:
            event_id = int(m_id.group(1))

        m_user = re.search(r"User[=:\s]+([^\s,;]+)", line, re.I)
        user = m_user.group(1) if m_user else "SYSTEM"

        m_ip = re.search(r"IP[=:\s]+([^\s,;]+)", line, re.I)
        ip = m_ip.group(1) if m_ip else "127.0.0.1"

        m_time = re.search(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
        time_str = m_time.group(1) if m_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if event_id == 4625:
            ev_type = "AUTH_FAIL"
            status = "FAILURE"
            msg = f"Windows Failed Logon (EventID 4625) for account '{user}'"
        elif event_id == 4624:
            ev_type = "AUTH_SUCCESS"
            status = "SUCCESS"
            msg = f"Windows Successful Logon (EventID 4624) for account '{user}'"
        elif event_id == 4720:
            ev_type = "USER_CREATED"
            status = "SUSPICIOUS"
            msg = f"New User Account Created (EventID 4720): '{user}'"
        elif event_id == 4672:
            ev_type = "PRIVILEGE_USE"
            status = "SUSPICIOUS"
            msg = f"Special Privileges Assigned to Logon (EventID 4672) for '{user}'"
        else:
            ev_type = "SYSTEM_EVENT"
            status = "SUCCESS"
            msg = f"Windows Security Event {event_id}"

        return ParsedEvent(
            timestamp=time_str,
            source_ip=ip,
            service="WINDOWS",
            event_type=ev_type,
            status=status,
            user=user,
            message=msg,
            raw_log=line
        )

