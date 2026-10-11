from config import (
    ADMIN_TOKEN, AUTH_LOG_FILE, BAN_THRESHOLD, DATABASE_FILE, HTTP_FLOOD_REQUESTS,
    HTTP_FLOOD_WINDOW, LOG_FILE, POLL_INTERVAL, SCAN_ERRORS, SCAN_WINDOW,
    SSH_BRUTE_ATTEMPTS, SSH_BRUTE_WINDOW, TRUSTED_NETWORKS,
    WEB_BRUTE_ATTEMPTS, WEB_BRUTE_WINDOW, WEB_HOST, WEB_PORT,
)
from auth_monitor import AuthLogMonitor
from database import MetricsDatabase
from firewall import UfwFirewall
from log_parser import analyze_nginx_403
from monitor import LogMonitor
from security import SecurityEngine
from web_server import create_server

def main():
    database = MetricsDatabase(DATABASE_FILE)
    firewall = UfwFirewall(database, BAN_THRESHOLD, TRUSTED_NETWORKS)
    security = SecurityEngine(database, firewall, {
        "flood_requests": HTTP_FLOOD_REQUESTS, "flood_window": HTTP_FLOOD_WINDOW,
        "web_brute_attempts": WEB_BRUTE_ATTEMPTS, "web_brute_window": WEB_BRUTE_WINDOW,
        "scan_errors": SCAN_ERRORS, "scan_window": SCAN_WINDOW,
        "ssh_brute_attempts": SSH_BRUTE_ATTEMPTS, "ssh_brute_window": SSH_BRUTE_WINDOW,
    })
    monitor = LogMonitor(LOG_FILE, database, security, POLL_INTERVAL)
    auth_monitor = AuthLogMonitor(AUTH_LOG_FILE, database, security, POLL_INTERVAL)
    server = create_server(WEB_HOST, WEB_PORT, database, firewall, ADMIN_TOKEN)
    print(firewall.status_message())
    print(f"Чтение лога: {LOG_FILE}")
    print(f"Панель открыта: http://{WEB_HOST}:{WEB_PORT}")
    print("Ручное управление: " + ("включено" if ADMIN_TOKEN else "отключено — задайте ANTI_DDOS_ADMIN_TOKEN"))
    print("Для остановки нажмите Ctrl+C")
    monitor.start()
    auth_monitor.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nПроверка остановлена.")
    finally:
        monitor.stop()
        auth_monitor.stop()
        server.server_close()
        monitor.join(timeout=2)
        auth_monitor.join(timeout=2)

if __name__ == "__main__":
    main()

