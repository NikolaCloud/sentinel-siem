"""
Генератор реалистичных журналов событий безопасности (атаки, брутфорс, сканирование, легитимный трафик).
"""

from datetime import datetime, timedelta
import random


def generate_siem_test_logs(count=120):
    logs = []
    base_time = datetime.now() - timedelta(minutes=45)

    # 1. Атака Brute-Force SSH (12 попыток с одного IP)
    bf_ip = "198.51.100.45"
    bf_users = ["root", "admin", "deploy", "oracle", "user", "test"]
    for i in range(14):
        t = (base_time + timedelta(seconds=i * 4)).strftime("%b %d %H:%M:%S")
        u = random.choice(bf_users)
        logs.append(f"{t} soc-srv-01 sshd[142{i:02d}]: Failed password for invalid user {u} from {bf_ip} port {45000+i} ssh2")

    # 2. Веб-атаки: SQL Injection, Path Traversal, Web Shell
    attacker_ip = "45.33.32.156"
    web_attacks = [
        f'{attacker_ip} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "GET /api/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 500 2412 "https://google.com" "sqlmap/1.7#dev"',
        f'{attacker_ip} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 312 "-" "Mozilla/5.0"',
        f'{attacker_ip} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "POST /uploads/cache.php?cmd=id;whoami HTTP/1.1" 200 48 "https://target.com" "Mozilla/5.0"',
        f'{attacker_ip} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1204 "-" "Mozilla/5.0"',
    ]
    logs.extend(web_attacks)

    # 3. Сканирование директорий / уязвимостей
    scanner_ip = "185.220.101.5"
    probe_paths = ["/wp-admin", "/.env", "/phpmyadmin", "/.git/config", "/backup.sql", "/api/v2/swagger.json", "/admin.php", "/config.json"]
    for p in probe_paths:
        logs.append(f'{scanner_ip} - - [{base_time.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "GET {p} HTTP/1.1" 404 182 "-" "Nikto/2.1.6"')

    # 4. События Windows Security (EventID)
    win_time = (base_time.replace(hour=2, minute=45)).strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"{win_time}, EventID=4624, User=Administrator, IP=192.168.1.15, Status=0x0, Type=LogonSuccess (Off-hours)")
    logs.append(f"{win_time}, EventID=4720, User=backdoor_svc, IP=192.168.1.15, Status=0x0, Type=AccountCreated")

    # 5. Легитимный фоновый трафик
    normal_ips = ["192.168.1.50", "192.168.1.51", "10.0.0.12", "95.173.136.2"]
    for i in range(count - len(logs)):
        t_delta = timedelta(minutes=random.randint(1, 40))
        cur_t = base_time + t_delta
        ip = random.choice(normal_ips)
        if i % 3 == 0:
            logs.append(f'{cur_t.strftime("%b %d %H:%M:%S")} app-node sshd[8901]: Accepted publickey for devops from {ip} port 52140 ssh2')
        else:
            logs.append(f'{ip} - alex [{cur_t.strftime("%d/%b/%Y:%H:%M:%S")} +0300] "GET /dashboard/overview HTTP/1.1" 200 4812 "https://company.internal" "Mozilla/5.0"')

    random.shuffle(logs)
    return logs

