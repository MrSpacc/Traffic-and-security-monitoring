from datetime import datetime, timezone
import ipaddress
import os
import shutil
import subprocess

class UfwFirewall:
    def __init__(self, database, threshold, trusted_networks=()):
        self.database, self.threshold = database, threshold
        self.attempted = set()
        self.available = shutil.which("ufw") is not None
        self.is_root = os.geteuid() == 0
        self.trusted_networks = tuple(ipaddress.ip_network(item) for item in trusted_networks)

    def is_trusted(self, ip):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(address in network for network in self.trusted_networks)

    def status_message(self):
        if not self.available:
            return "UFW не найден: мониторинг работает, автобан отключён"
        if not self.is_root:
            return "Нет прав root: мониторинг работает, автобан отключён"
        return f"UFW доступен: HTTP flood, Web/SSH brute-force, сканирование и порог {self.threshold} × 403"

    def maybe_ban(self, stats):
        ip = stats["ip"]
        if stats["errors_403"] < self.threshold or stats["banned"] or ip in self.attempted:
            return False
        return self.ban_ip(ip, "403_threshold")

    def ban_ip(self, ip, reason, force=False):
        if (ip in self.attempted and not force) or self.is_trusted(ip):
            return False
        self.attempted.add(ip)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"Некорректный IP пропущен: {ip}")
            return False
        if not self.available or not self.is_root:
            print(f"IP {ip} достиг порога, но автобан отключён")
            return False
        try:
            subprocess.run(["ufw","deny","from",ip], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            print(f"Не удалось заблокировать {ip}: {(error.stderr or error.stdout).strip()}")
            return False
        self.database.mark_banned(ip, datetime.now(timezone.utc).isoformat())
        print(f"IP {ip} заблокирован через UFW. Причина: {reason}")
        return True

    def manual_ban(self, ip):
        occurred_at = datetime.now(timezone.utc).isoformat()
        alert_id = self.database.add_alert(
            occurred_at, ip, "manual_block", "high", "Ручная блокировка оператором"
        )
        blocked = self.ban_ip(ip, "manual", force=True)
        self.database.set_alert_action(alert_id, "blocked" if blocked else "failed")
        return blocked

    def unban_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, "Некорректный IP"
        if not self.available:
            return False, "UFW не установлен"
        if not self.is_root:
            return False, "Нет прав root"
        try:
            subprocess.run(["ufw", "delete", "deny", "from", ip],
                           check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            return False, (error.stderr or error.stdout).strip()
        self.database.mark_unbanned(ip)
        self.attempted.discard(ip)
        occurred_at = datetime.now(timezone.utc).isoformat()
        self.database.add_alert(occurred_at, ip, "manual_unblock", "info",
                                "Ручная разблокировка оператором", "unblocked")
        print(f"IP {ip} разблокирован через UFW.")
        return True, "IP разблокирован"
