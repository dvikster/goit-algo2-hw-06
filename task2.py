import hashlib
import ipaddress
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path


# Пошук X-Forwarded-For, якщо IP є в такому форматі
XFF_RE = re.compile(r"(?i)\bX-Forwarded-For\b\s*[:=]\s*([^\s\"']+)")

# Пошук IPv4 або IPv6 у рядку
IP_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,})\b")


def is_valid_ipv4(ip: str) -> bool:
    """
    Перевіряє, чи є рядок коректною IPv4-адресою.
    """

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        number = int(part)

        if number < 0 or number > 255:
            return False

    return True


def parse_ip_from_line(line: str):
    """
    Дістає IP-адресу з рядка логу.
    Якщо рядок некоректний або IP не знайдено — повертає None.
    """

    # Спочатку перевіряємо X-Forwarded-For
    xff_match = XFF_RE.search(line)

    if xff_match:
        first_ip = xff_match.group(1).split(",")[0].strip().strip("\"',;")

        if "." in first_ip and is_valid_ipv4(first_ip):
            return first_ip

        if ":" in first_ip:
            try:
                ipaddress.ip_address(first_ip)
                return first_ip
            except ValueError:
                pass

    # Якщо X-Forwarded-For немає — шукаємо будь-який IP у рядку
    for match in IP_RE.finditer(line):
        candidate = match.group(0)

        if "." in candidate and is_valid_ipv4(candidate):
            return candidate

        if ":" in candidate:
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue

    return None


def iter_valid_ips(log_path: str):
    """
    Потоково читає лог-файл і повертає валідні IP-адреси.
    Некоректні рядки ігноруються.
    """

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            ip = parse_ip_from_line(line)

            if ip is not None:
                yield ip


def count_unique_exact(log_path: str) -> int:
    """
    Точний підрахунок унікальних IP через set.
    """

    unique_ips = set()

    for ip in iter_valid_ips(log_path):
        unique_ips.add(ip)

    return len(unique_ips)


def leading_zeros_64(value: int) -> int:
    """
    Підраховує кількість початкових нулів у 64-бітному числі.
    """

    if value == 0:
        return 64

    return 64 - value.bit_length()


@dataclass
class HyperLogLog:
    """
    Реалізація алгоритму HyperLogLog.

    p — кількість бітів для індексу регістру.
    m = 2^p — кількість регістрів.
    Для p=14 очікувана похибка приблизно 0.81%.
    """

    p: int = 14

    def __post_init__(self):
        if not 4 <= self.p <= 18:
            raise ValueError("p має бути в межах від 4 до 18")

        self.m = 1 << self.p
        self.registers = bytearray(self.m)

        if self.m == 16:
            self.alpha = 0.673
        elif self.m == 32:
            self.alpha = 0.697
        elif self.m == 64:
            self.alpha = 0.709
        else:
            self.alpha = 0.7213 / (1 + 1.079 / self.m)

    def hash64(self, value: str) -> int:
        """
        Створює 64-бітний хеш для значення.
        """

        hash_bytes = hashlib.blake2b(
            value.encode("utf-8", errors="ignore"),
            digest_size=8
        ).digest()

        return int.from_bytes(hash_bytes, byteorder="big", signed=False)

    def add(self, value: str) -> None:
        """
        Додає елемент до HyperLogLog.
        """

        x = self.hash64(value)

        # Перші p бітів — індекс регістру
        index = x >> (64 - self.p)

        # Решта бітів використовується для підрахунку провідних нулів
        remaining = (x << self.p) & ((1 << 64) - 1)

        rank = leading_zeros_64(remaining) + 1

        if rank > self.registers[index]:
            self.registers[index] = rank

    def count(self) -> float:
        """
        Повертає наближену кількість унікальних елементів.
        """

        indicator = 0.0
        empty_registers = 0

        for register in self.registers:
            indicator += 2.0 ** (-register)

            if register == 0:
                empty_registers += 1

        estimate = self.alpha * (self.m ** 2) / indicator

        # Корекція для малих значень
        if estimate <= 2.5 * self.m and empty_registers > 0:
            estimate = self.m * math.log(self.m / empty_registers)

        return estimate


def count_unique_hyperloglog(log_path: str, p: int = 14) -> float:
    """
    Наближений підрахунок унікальних IP через HyperLogLog.
    """

    hll = HyperLogLog(p=p)

    for ip in iter_valid_ips(log_path):
        hll.add(ip)

    return hll.count()


def measure_time(function, *args):
    """
    Вимірює час виконання функції.
    """

    start = time.perf_counter()
    result = function(*args)
    end = time.perf_counter()

    return result, end - start


def print_table(exact_count, exact_time, hll_count, hll_time):
    """
    Виводить таблицю порівняння результатів.
    """

    print("Результати порівняння:")
    print(f"{'':<30}{'Точний підрахунок':>20}{'HyperLogLog':>15}")
    print(f"{'Унікальні елементи':<30}{float(exact_count):>20.1f}{float(hll_count):>15.1f}")
    print(f"{'Час виконання (сек.)':<30}{exact_time:>20.5f}{hll_time:>15.5f}")


def quick_diagnostics(log_path: str, max_lines: int = 20_000, sample_limit: int = 10):
    """
    Невелика діагностика файлу:
    показує, чи знаходяться IP-адреси в логах.
    """

    total_lines = 0
    found_ips = 0
    unique_ips = set()
    samples = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            total_lines += 1

            if total_lines > max_lines:
                break

            line = line.strip()

            if not line:
                continue

            ip = parse_ip_from_line(line)

            if ip is not None:
                found_ips += 1
                unique_ips.add(ip)

                if len(samples) < sample_limit:
                    samples.append(ip)

    ratio = found_ips / total_lines * 100 if total_lines > 0 else 0

    print("Діагностика файлу:")
    print(f"Перевірено рядків: {total_lines}")
    print(f"Рядків з валідним IP: {found_ips}")
    print(f"Частка рядків з IP: {ratio:.2f}%")
    print(f"Унікальних IP у діагностиці: {len(unique_ips)}")
    print(f"Приклади IP: {samples}")
    print()


if __name__ == "__main__":
    base_dir = Path(__file__).parent
    log_path = base_dir / "lms-stage-access.log"

    if not log_path.exists():
        print(f"Файл не знайдено: {log_path}")
    else:
        quick_diagnostics(str(log_path))

        exact_result, exact_time = measure_time(
            count_unique_exact,
            str(log_path)
        )

        hll_result, hll_time = measure_time(
            count_unique_hyperloglog,
            str(log_path),
            14
        )

        print_table(
            exact_result,
            exact_time,
            hll_result,
            hll_time
        )

        if exact_result > 0:
            error = abs(hll_result - exact_result) / exact_result * 100
        else:
            error = 0

        expected_error = 1.04 / math.sqrt(1 << 14) * 100

        print()
        print(f"Похибка HyperLogLog: {error:.2f}%")
        print(f"Очікувана теоретична похибка для p=14: приблизно {expected_error:.2f}%")