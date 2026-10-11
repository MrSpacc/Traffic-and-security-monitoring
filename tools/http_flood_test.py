"""Ограниченная проверка детектора HTTP-флуда на собственном сервере."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen


def request_once(url):
    request = Request(url, headers={"User-Agent": "AntiDDoS-SelfTest/1.0"})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status
    except Exception as error:
        return type(error).__name__


def main():
    parser = argparse.ArgumentParser(description="Отправляет 130 тестовых HTTP-запросов")
    parser.add_argument("url", help="URL вашего Nginx, например http://server/test")
    parser.add_argument("--requests", type=int, default=130)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--i-own-this-target", action="store_true",
                        help="Обязательное подтверждение владения сервером")
    args = parser.parse_args()
    if not args.i_own_this_target:
        parser.error("добавьте --i-own-this-target для подтверждения владения сервером")
    if not 1 <= args.requests <= 200 or not 1 <= args.workers <= 25:
        parser.error("разрешено не более 200 запросов и 25 потоков")
    if not args.url.startswith(("http://", "https://")):
        parser.error("URL должен начинаться с http:// или https://")

    print(f"Отправка {args.requests} запросов на {args.url}")
    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(request_once, args.url) for _ in range(args.requests)]
        for future in as_completed(futures):
            result = str(future.result())
            results[result] = results.get(result, 0) + 1
    print("Результаты:", results)


if __name__ == "__main__":
    main()
