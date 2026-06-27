import hashlib


class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("Size must be a positive integer")

        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes must be a positive integer")

        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray(size)

    def _hashes(self, item: str):
        for i in range(self.num_hashes):
            data = f"{i}:{item}".encode("utf-8")
            hash_value = int(hashlib.sha256(data).hexdigest(), 16)
            yield hash_value % self.size

    def add(self, item: str):
        if not isinstance(item, str) or item == "":
            raise ValueError("Password must be a non-empty string")

        for index in self._hashes(item):
            self.bit_array[index] = 1

    def contains(self, item: str) -> bool:
        if not isinstance(item, str) or item == "":
            return False

        for index in self._hashes(item):
            if self.bit_array[index] == 0:
                return False

        return True


def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list) -> dict:
    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError("bloom_filter must be an instance of BloomFilter")

    if not isinstance(passwords, list):
        raise TypeError("passwords must be a list")

    results = {}

    for password in passwords:
        if not isinstance(password, str) or password == "":
            results[str(password)] = "некоректне значення"
            continue

        if bloom_filter.contains(password):
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)

    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]

    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]

    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")