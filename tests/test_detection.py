"""
Тесты сигнатурного и корреляционного анализа атак Sentinel SIEM.
"""

from sentinel.engine.correlation_engine import CorrelationEngine
from sentinel.engine.signature_rules import SignatureEngine
from sentinel.parsers.base_parser import ParsedEvent
from sentinel.parsers.syslog_parser import SyslogParser
from sentinel.parsers.web_parser import WebLogParser


def test_sql_injection_detection():
    payload = "GET /api/user?id=1 UNION SELECT username, password FROM admin HTTP/1.1"
    matches = SignatureEngine.check_payload(payload)
    assert len(matches) > 0
    assert matches[0].severity == "CRITICAL"
    assert matches[0].mitre_id == "T1190"


def test_path_traversal_detection():
    payload = "GET /view?doc=../../../../etc/passwd HTTP/1.1"
    matches = SignatureEngine.check_payload(payload)
    assert len(matches) > 0
    assert matches[0].severity == "HIGH"


def test_web_log_parser():
    line = '198.51.100.20 - - [24/Oct/2026:14:10:05 +0300] "GET /admin HTTP/1.1" 403 210 "-" "Mozilla/5.0"'
    parser = WebLogParser()
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "198.51.100.20"
    assert event.service == "NGINX"
    assert event.status == "SUSPICIOUS"


def test_brute_force_correlation():
    engine = CorrelationEngine(config={"brute_force_threshold": 3})
    events = [
        ParsedEvent("2026-10-24 14:00:01", "10.0.0.99", "SSH", "AUTH_FAIL", "FAILURE", "root", "Fail", ""),
        ParsedEvent("2026-10-24 14:00:05", "10.0.0.99", "SSH", "AUTH_FAIL", "FAILURE", "admin", "Fail", ""),
        ParsedEvent("2026-10-24 14:00:09", "10.0.0.99", "SSH", "AUTH_FAIL", "FAILURE", "deploy", "Fail", ""),
    ]
    alerts = engine.analyze_events(events)
    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1110"
    assert alerts[0].source_ip == "10.0.0.99"

