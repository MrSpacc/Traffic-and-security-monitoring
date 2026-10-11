from datetime import datetime, timezone
import re
import sqlite3
import threading

FAILED_SSH = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)

class AuthLogMonitor(threading.Thread):
    def __init__(self, log_path, database, security, poll_interval=1.0):
        super().__init__(name="ssh-auth-monitor", daemon=True)
        self.log_path, self.database, self.security = log_path, database, security
        self.poll_interval = poll_interval
        self.stop_event = threading.Event()
        self.missing_reported = False

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.read_new_lines()
                self.missing_reported = False
            except (FileNotFoundError, PermissionError) as error:
                if not self.missing_reported:
                    print(f"SSH-мониторинг недоступен ({self.log_path}): {error}")
                    self.missing_reported = True
            except sqlite3.OperationalError as error:
                print(f"Временная ошибка SQLite в SSH-мониторе: {error}")
            self.stop_event.wait(self.poll_interval)

    def read_new_lines(self):
        stat = self.log_path.stat()
        checkpoint = self.database.get_checkpoint(self.log_path)
        enforce = bool(checkpoint and checkpoint["inode"] == stat.st_ino and
                       checkpoint["offset"] <= stat.st_size)
        offset = checkpoint["offset"] if checkpoint and checkpoint["inode"] == stat.st_ino and checkpoint["offset"] <= stat.st_size else 0
        with self.log_path.open("rb") as log_file:
            log_file.seek(offset)
            for raw_line in log_file:
                match = FAILED_SSH.search(raw_line.decode("utf-8", errors="ignore"))
                if match:
                    self.security.process_ssh(datetime.now(timezone.utc).isoformat(),
                                              match.group("ip"), match.group("user"), enforce)
            offset = log_file.tell()
        self.database.save_checkpoint(self.log_path, stat.st_ino, offset)
