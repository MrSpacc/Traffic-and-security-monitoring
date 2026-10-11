from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = Path(os.environ.get("NGINX_ACCESS_LOG", str(BASE_DIR / "access.log")))
DATABASE_FILE = BASE_DIR / "metrics.db"
BAN_THRESHOLD = 50
POLL_INTERVAL = 0.05
WEB_HOST = "127.0.0.1"
WEB_PORT = 8090

# Укажите пароль здесь или через переменную окружения ANTI_DDOS_PANEL_PASSWORD.
# Пока значение пустое, вход в панель закрыт.
PANEL_PASSWORD = os.environ.get("ANTI_DDOS_PANEL_PASSWORD", "pass")

# Пороговые значения защиты. Подстройте их под обычную нагрузку сайта.
HTTP_FLOOD_REQUESTS = 120
HTTP_FLOOD_WINDOW = 10
WEB_BRUTE_ATTEMPTS = 12
WEB_BRUTE_WINDOW = 300
SCAN_ERRORS = 25
SCAN_WINDOW = 60
SSH_BRUTE_ATTEMPTS = 6
SSH_BRUTE_WINDOW = 300

# На Debian/Ubuntu SSH-события обычно находятся здесь. Если файла нет,
# HTTP-защита продолжит работать без него.
AUTH_LOG_FILE = Path("/var/log/auth.log")

# Эти сети никогда не блокируются автоматически.
TRUSTED_NETWORKS = ("127.0.0.0/8", "::1/128")
