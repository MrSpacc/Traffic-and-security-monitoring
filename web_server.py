from collections import defaultdict, deque
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import parse_qs, unquote, urlparse


SESSION_LIFETIME = 12 * 60 * 60
LOGIN_WINDOW = 60
LOGIN_ATTEMPTS = 5


class DashboardHandler(SimpleHTTPRequestHandler):
    database = firewall = None
    panel_password = ""
    sessions = {}
    login_attempts = defaultdict(deque)
    auth_lock = threading.Lock()
    static_dir = Path(__file__).resolve().parent / "static"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            if self.is_authenticated():
                return self.redirect("/")
            return self.send_file("login.html", "text/html; charset=utf-8")
        if parsed.path.startswith("/static/"):
            filename = Path(parsed.path).name
            if Path(filename).suffix not in (".css", ".js"):
                return self.send_error(404)
            content_type = {".css": "text/css", ".js": "application/javascript"}.get(
                Path(filename).suffix, "text/plain"
            )
            return self.send_file(filename, content_type)
        if not self.is_authenticated():
            if parsed.path.startswith("/api/"):
                return self.send_json({"error": "Требуется вход"}, 401)
            return self.redirect("/login")

        if parsed.path == "/":
            return self.send_file("index.html", "text/html; charset=utf-8")
        if parsed.path == "/api/summary":
            data = self.database.summary()
            data["firewall"] = self.firewall.status_message()
            return self.send_json(data)
        if parsed.path == "/api/ips":
            query = parse_qs(parsed.query).get("q", [""])[0][:100]
            return self.send_json(self.database.list_ips(query=query))
        if parsed.path == "/api/banned":
            return self.send_json(self.database.list_banned())
        if parsed.path.startswith("/api/ip/"):
            ip = unquote(parsed.path[len("/api/ip/"):])
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                return self.send_json({"error": "Некорректный IP"}, 400)
            data = self.database.ip_details(ip)
            if not data:
                return self.send_json({"error": "IP не найден"}, 404)
            data["ip_version"] = f"IPv{address.version}"
            data["ip_type"] = "частный" if address.is_private else "публичный"
            return self.send_json(data)
        if parsed.path == "/api/recent":
            return self.send_json(self.database.recent_events())
        if parsed.path == "/api/alerts":
            return self.send_json(self.database.recent_alerts())
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            return self.login()
        if not self.is_authenticated():
            return self.send_json({"error": "Сессия истекла. Войдите снова"}, 401)
        if parsed.path == "/api/logout":
            return self.logout()
        if parsed.path not in ("/api/firewall/block", "/api/firewall/unblock"):
            return self.send_json({"error": "Маршрут не найден"}, 404)
        try:
            data = self.read_json()
            ip = str(ipaddress.ip_address(data.get("ip", "")))
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.send_json({"error": "Некорректный IP или JSON"}, 400)
        if parsed.path.endswith("/block"):
            if self.firewall.is_trusted(ip):
                return self.send_json({"error": "IP находится в TRUSTED_NETWORKS"}, 409)
            success = self.firewall.manual_ban(ip)
            message = "IP заблокирован" if success else "UFW не смог заблокировать IP"
        else:
            success, message = self.firewall.unban_ip(ip)
        return self.send_json({"success": success, "message": message}, 200 if success else 409)

    def login(self):
        client_ip = self.client_address[0]
        now = time.monotonic()
        with self.auth_lock:
            attempts = self.login_attempts[client_ip]
            while attempts and attempts[0] < now - LOGIN_WINDOW:
                attempts.popleft()
            if len(attempts) >= LOGIN_ATTEMPTS:
                return self.send_json({"error": "Слишком много попыток. Подождите минуту"}, 429)
        if not self.panel_password:
            return self.send_json({"error": "Пароль панели не настроен в config.py"}, 503)
        try:
            password = str(self.read_json().get("password", ""))
        except (ValueError, TypeError, json.JSONDecodeError):
            return self.send_json({"error": "Некорректный запрос"}, 400)
        if not secrets.compare_digest(password, self.panel_password):
            with self.auth_lock:
                self.login_attempts[client_ip].append(now)
            return self.send_json({"error": "Неверный пароль"}, 403)
        token = secrets.token_urlsafe(32)
        with self.auth_lock:
            self.sessions[token] = time.time() + SESSION_LIFETIME
            self.login_attempts.pop(client_ip, None)
        cookie = f"session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_LIFETIME}"
        return self.send_json({"success": True}, headers={"Set-Cookie": cookie})

    def logout(self):
        token = self.session_token()
        with self.auth_lock:
            self.sessions.pop(token, None)
        return self.send_json({"success": True}, headers={
            "Set-Cookie": "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        })

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["session"].value if "session" in cookie else ""
        except Exception:
            return ""

    def is_authenticated(self):
        token = self.session_token()
        if not token:
            return False
        with self.auth_lock:
            expires_at = self.sessions.get(token, 0)
            if expires_at <= time.time():
                self.sessions.pop(token, None)
                return False
            return True

    def read_json(self):
        length = max(0, min(int(self.headers.get("Content-Length", "0")), 4096))
        return json.loads(self.rfile.read(length))

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def send_file(self, filename, content_type):
        path = self.static_dir / filename
        if not path.is_file():
            return self.send_error(404)
        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.write_response(content)

    def send_json(self, data, status=200, headers=None):
        content = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.write_response(content)

    def write_response(self, content):
        try:
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            # Клиент или reverse proxy закрыл соединение. Само действие
            # (например, команда UFW) к этому моменту уже выполнено.
            pass

    def log_message(self, format_string, *args):
        pass


def create_server(host, port, database, firewall, panel_password=""):
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {
        "database": database,
        "firewall": firewall,
        "panel_password": panel_password,
        "sessions": {},
        "login_attempts": defaultdict(deque),
        "auth_lock": threading.Lock(),
    })
    return ThreadingHTTPServer((host, port), handler)
