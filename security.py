from collections import defaultdict, deque
from datetime import datetime, timezone
import time


AUTH_PATH_MARKERS = ("login", "signin", "auth", "admin", "wp-login", "xmlrpc")
SCAN_PATH_MARKERS = (".env", ".git", "wp-admin", "phpmyadmin", "cgi-bin", "vendor/phpunit")


class SecurityEngine:
    def __init__(self, database, firewall, settings):
        self.database = database
        self.firewall = firewall
        self.settings = settings
        self.requests = defaultdict(deque)
        self.auth_failures = defaultdict(deque)
        self.scan_errors = defaultdict(deque)
        self.ssh_failures = defaultdict(deque)
        self.cooldowns = {}

    @staticmethod
    def _push(bucket, now, window):
        bucket.append(now)
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        return len(bucket)

    def _alert_and_ban(self, ip, kind, severity, message):
        key = (ip, kind)
        now = time.monotonic()
        if self.cooldowns.get(key, 0) > now - 300:
            return
        self.cooldowns[key] = now
        occurred_at = datetime.now(timezone.utc).isoformat()
        alert_id = self.database.add_alert(occurred_at, ip, kind, severity, message)
        action = "blocked" if self.firewall.ban_ip(ip, kind) else "detected"
        self.database.set_alert_action(alert_id, action)

    def process_http(self, event, stats, enforce=True):
        # Старое правило 50 ответов 403 остаётся активным.
        self.firewall.maybe_ban(stats)
        if not enforce or self.firewall.is_trusted(event["ip"]):
            return
        ip, now = event["ip"], time.monotonic()
        count = self._push(self.requests[ip], now, self.settings["flood_window"])
        if count >= self.settings["flood_requests"]:
            self._alert_and_ban(ip, "http_flood", "critical",
                                f"HTTP-флуд: {count} запросов за {self.settings['flood_window']} сек.")

        path = event["path"].lower()
        if event["status"] in (401, 403) and any(marker in path for marker in AUTH_PATH_MARKERS):
            count = self._push(self.auth_failures[ip], now, self.settings["web_brute_window"])
            if count >= self.settings["web_brute_attempts"]:
                self._alert_and_ban(ip, "web_bruteforce", "high",
                                    f"Перебор веб-входа: {count} неудачных попыток")

        if event["status"] >= 400 and any(marker in path for marker in SCAN_PATH_MARKERS):
            count = self._push(self.scan_errors[ip], now, self.settings["scan_window"])
            if count >= self.settings["scan_errors"]:
                self._alert_and_ban(ip, "vulnerability_scan", "high",
                                    f"Сканирование уязвимостей: {count} подозрительных запросов")

    def process_ssh(self, occurred_at, ip, username, enforce=True):
        self.database.add_auth_failure(occurred_at, ip, username)
        if not enforce or self.firewall.is_trusted(ip):
            return
        now = time.monotonic()
        count = self._push(self.ssh_failures[ip], now, self.settings["ssh_brute_window"])
        if count >= self.settings["ssh_brute_attempts"]:
            self._alert_and_ban(ip, "ssh_bruteforce", "critical",
                                f"Перебор SSH: {count} неудачных попыток входа")
