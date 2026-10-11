import os
import time
import threading
from log_parser import parse_nginx_line

class LogMonitor(threading.Thread):
    def __init__(self, log_path, database, security, poll_interval=0.05):
        super().__init__(name="nginx-log-monitor", daemon=True)
        self.log_path, self.database, self.security = log_path, database, security
        self.poll_interval = poll_interval
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.read_new_lines()
            except FileNotFoundError:
                print(f"Файл {self.log_path} не найден. Ожидание...")
            except OSError as error:
                print(f"Ошибка чтения лога: {error}")
            self.stop_event.wait(self.poll_interval)

    def read_new_lines(self):
        checkpoint = self.database.get_checkpoint(self.log_path)
        parsed = 0
        with self.log_path.open("rb") as log_file:
            stat = os.fstat(log_file.fileno())
            enforce = bool(checkpoint and checkpoint["inode"] == stat.st_ino and
                           checkpoint["offset"] <= stat.st_size)
            offset = checkpoint["offset"] if enforce else 0
            log_file.seek(offset)
            batch = []
            batch_started = time.monotonic()

            def flush(position):
                nonlocal parsed, batch_started
                stats = self.database.add_events(
                    batch, (self.log_path, stat.st_ino, position))
                for event, ip_stats in zip(batch, stats):
                    self.security.process_http(event, ip_stats, enforce)
                parsed += len(batch)
                batch.clear()
                batch_started = time.monotonic()

            while not self.stop_event.is_set():
                position = log_file.tell()
                raw_line = log_file.readline()
                if not raw_line or not raw_line.endswith(b"\n"):
                    # Retry a partially written line on the next poll.
                    log_file.seek(position)
                    break
                event = parse_nginx_line(raw_line.decode("utf-8", errors="ignore"))
                if event:
                    batch.append(event)
                if len(batch) >= 500 or time.monotonic() - batch_started >= 0.1:
                    flush(log_file.tell())
            position = log_file.tell()
            if batch or position != offset or not enforce:
                flush(position)
        if parsed:
            print(f"Добавлено запросов в метрики: {parsed}")
