"""Добавляет ограниченную тестовую серию в access.log без сетевой нагрузки."""

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "access.log"
TEST_IP = "198.51.100.77"  # TEST-NET-2, не является реальным публичным адресом


def main():
    timestamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")
    line = (f'{TEST_IP} - - [{timestamp}] "GET /anti-ddos-self-test HTTP/1.1" '
            '200 32 "-" "AntiDDoS-SelfTest/1.0"\n')
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.writelines(line for _ in range(130))
    print(f"Добавлено 130 тестовых запросов от {TEST_IP} в {LOG_FILE}")
    print("Откройте журнал инцидентов в панели через 2–3 секунды.")


if __name__ == "__main__":
    main()
