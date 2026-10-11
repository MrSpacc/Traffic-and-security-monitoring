from collections import Counter
from datetime import datetime, timezone
import re

NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

def parse_nginx_line(line):
    match = NGINX_PATTERN.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    parts = data["request"].split(maxsplit=2)
    try:
        occurred_at = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except ValueError:
        occurred_at = datetime.now(timezone.utc).isoformat()
    return {
        "ip": data["ip"], "occurred_at": occurred_at,
        "method": parts[0] if parts else "-",
        "path": parts[1] if len(parts) > 1 else "-",
        "protocol": parts[2] if len(parts) > 2 else "-",
        "status": int(data["status"]),
        "size": int(data["size"]) if data["size"] != "-" else 0,
        "referer": data.get("referer") or "-",
        "user_agent": data.get("user_agent") or "-",
    }

def analyze_nginx_403(file_path):
    """Совместимая с прежним кодом полная проверка файла."""
    counter = Counter()
    total_lines = parsed_lines = 0
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                total_lines += 1
                event = parse_nginx_line(line)
                if event:
                    parsed_lines += 1
                    if event["status"] == 403:
                        counter[event["ip"]] += 1
    except FileNotFoundError:
        print(f"Файл {file_path} не найден.")
        return None
    print(f"Обработано строк: {total_lines} (Успешно разобрано: {parsed_lines})")
    return counter
