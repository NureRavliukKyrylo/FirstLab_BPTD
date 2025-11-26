# Містить компоненти для аналізу криптографічних властивостей DES:
#
#   1) Перевірку слабких та напівслабких DES-ключів:
#      - офіційні слабкі ключі (4)
#      - офіційні напівслабкі ключі (6 пар = 12 ключів)
#      - підозрілі ключі, які породжують періодичні субключі (періоди 1,2,4)
#
#   2) Інструментоване DES-шифрування:
#      - стандартний DES, але з додатковою можливістю зібрати R після кожного з 16 раундів
#
#   3) Статистичний аналіз ентропії кожного біта R у кожному раунді:
#      - для кожного раунду i (0..15) і кожного біта j (0..31) рахується p(bit=1)
#      - обчислюється бінарна ентропія H(p)
#
#   4) Генерація випадкових plaintext для статистики
#
#   5) Повний процес аналізу: запуск шифрування на N випадкових блоках і обчислення ентропії

import math
import os
from typing import List, Tuple

from des_core import (
    permute, generate_subkeys, f_function, split_bits
)

from constants.tables import IP_TABLE, FP_TABLE


# ОФІЦІЙНІ СЛАБКІ КЛЮЧІ DES
# Джерело: FIPS 46-3
# Це 4 ключі, для яких DES перетворюється на інволюцію:
#    encrypt == decrypt
# або всі субключі однакові.
WEAK_KEYS = {
    0x0101010101010101,
    0xFEFEFEFEFEFEFEFE,
    0xE0E0E0E0F1F1F1F1,
    0x1F1F1F1F0E0E0E0E,
}

# Напівслабкі ключі — 6 пар (12 ключів),
# де ключі у парі взаємно перетворюють один одного
# (підключі циклічно повторюються з періодом 2).
SEMI_WEAK_PAIRS = {
    (0x011F011F010E010E, 0x1F011F010E010E01),
    (0x01E001E001F101F1, 0xE001E001F101F101),
    (0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01),
    (0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E),
    (0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E),
    (0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1),
}

# Плоска множина напівслабких ключів (для швидкої перевірки)
SEMI_WEAK_KEYS = {k for pair in SEMI_WEAK_PAIRS for k in pair}


# 1) ПЕРЕВІРКА СЛАБКОСТІ КЛЮЧА DES
def is_weak_key(key64: int) -> Tuple[bool, str]:
    """
    Повертає:
        (True/False, текстове пояснення)

    Перевіряє:
        1) слабкі ключі (4 офіційні)
        2) напівслабкі ключі (12 офіційних)
        3) структурні аномалії:
            - період підключів = 1 (усі 16 однакові)
            - період = 2 (майже напівслабкий)
            - період = 4 (клас 48 "підозрілих" ключів згідно з літературою)
    """

    #1) Офіційно слабкі
    if key64 in WEAK_KEYS:
        return True, "Weak DES key — входить до офіційного списку 4 слабких ключів."

    #2) Офіційні напівслабкі 
    if key64 in SEMI_WEAK_KEYS:
        return True, "Semi-weak DES key — входить до офіційних 6 напівслабких пар."

    #3) Структура субключів 
    subkeys = generate_subkeys(key64)
    distinct = len(set(subkeys))

    # Внутрішня ф-ція для пошуку найменшого періоду підключів.
    def detect_period(arr):
        """
        Пошук найменшого періоду p, 1 ≤ p ≤ 16.
        Якщо subkeys виглядають як [A, B, A, B, A, B, ...] → період = 2.
        Якщо всі однакові → період = 1.
        Якщо немає короткого повторення → 16.
        """
        for p in range(1, 17):
            ok = all(arr[i] == arr[i + p] for i in range(16 - p))
            if not ok:
                continue

            # Перевіряємо, що шаблон arr[0..p-1] справді повторюється
            pattern_ok = True
            for i in range(16):
                if arr[i] != arr[i % p]:
                    pattern_ok = False
                    break

            if pattern_ok:
                return p

        return 16

    period = detect_period(subkeys)

    #Інтерпретації 
    if period == 1:
        return True, "Підозрілий: усі 16 підключів однакові (не з еталонного списку, але очевидно слабкий)."

    if period == 2:
        return True, "Підозрілий: період 2 — поводиться як напівслабкий ключ (але не у списку DES)."

    if period == 4:
        return True, "Possibly weak key — період 4 (належить до класу 48 підозрілих DES ключів)."

    #Нормальна ситуація
    return False, f"Normal DES key — 16 раундових підключів, period={period}, unique={distinct}."


# 2) ІНСТРУМЕНТОВАНЕ DES-ШИФРУВАННЯ (збирання R кожного раунду)
def encrypt_block_and_collect(block64: int, key64: int) -> Tuple[int, List[int]]:
    """
    Виконує DES-шифрування одного 64-бітного блоку, але додатково збирає
    значення 32-бітного R після кожного з 16 раундів.
    """

    subkeys = generate_subkeys(key64)

    # Початкова перестановка IP 
    ip = permute(block64, IP_TABLE, 64) & 0xFFFFFFFFFFFFFFFF
    L, R = split_bits(ip, 32)

    round_Rs: List[int] = []

    # 16 раундів DES 
    for i in range(16):
        f_out = f_function(R, subkeys[i]) & 0xFFFFFFFF

        newL = R & 0xFFFFFFFF
        newR = (L ^ f_out) & 0xFFFFFFFF  # Прямий Feistel-крок

        L, R = newL, newR

        round_Rs.append(R)  # вже масковане 32-бітне значення

    # Формування preoutput = R16 || L16 
    preoutput = ((R & 0xFFFFFFFF) << 32) | (L & 0xFFFFFFFF)
    preoutput &= 0xFFFFFFFFFFFFFFFF

    # Кінцева перестановка FP
    cipher = permute(preoutput, FP_TABLE, 64) & 0xFFFFFFFFFFFFFFFF
    return cipher, round_Rs


# 3) БІНАРНА ЕНТРОПІЯ ОКРЕМОГО БІТА
def entropy_binary(p: float) -> float:
    """
    Класична формула бінарної ентропії Шеннона:
        H(p) = -p log2(p) - (1-p) log2(1-p)

    Інтерпретація:
        H = 1   -> максимально випадковий біт (p=0.5)
        H = 0   -> біт завжди 0 або завжди 1
    """
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


# 4) РОЗРАХУНОК ЕНТРОПІЇ ДЛЯ 16×32 МАТРИЦІ
def compute_entropy_matrix(round_Rs_matrix: List[List[int]], msb_order: bool = True) -> List[List[float]]:
    """
    Приймає round_Rs_matrix:
        round_Rs_matrix[i] — список довжини N, що містить R_i від кожного plaintext.

    Повертає:
        16×32 матрицю ентропій, де:
            entropies[round][bit] = H(p)

    msb_order=True означає, що "біт 0" — це найстарший біт (MSB)
    """
    entropies_per_round: List[List[float]] = []

    for round_i in range(16):
        Rs = round_Rs_matrix[round_i]
        N = len(Rs)

        if N == 0:
            entropies_per_round.append([0.0] * 32)
            continue

        bit_entropies = []
        for b in range(32):

            # MSB = біт 31; LSB = біт 0
            shift = (31 - b) if msb_order else b
            mask = 1 << shift

            ones = sum(1 for r in Rs if (r & mask) != 0)
            p = ones / N

            bit_entropies.append(entropy_binary(p))

        entropies_per_round.append(bit_entropies)

    return entropies_per_round


# 5) ГЕНЕРАЦІЯ ВИПАДКОВИХ 64-БІТНИХ БЛОКІВ
def generate_random_plaintexts(n: int) -> List[int]:
    """
    Генерує n випадкових plaintext, кожен 64 біти.

    Використання os.urandom гарантує криптографічно безпечний випадковий потік,
    що важливо для коректного статистичного аналізу (уникає кореляцій).
    """
    pts: List[int] = []
    for _ in range(n):
        block = int.from_bytes(os.urandom(8), "big")
        pts.append(block)
    return pts


# 6) ПОВНИЙ АНАЛІЗ ЕНТРОПІЇ
def analyze_entropy(key64: int, N: int = 2048, msb_order: bool = True) -> Tuple[List[List[float]], List[List[int]]]:
    """
    Повний процес статистичного аналізу ентропії DES-раундів.

    Виконується:
        1) Генерація N випадкових plaintext.
        2) Для кожного plaintext виконується DES-шифрування з колекцією R_i.
        3) Формується round_Rs_matrix: 16 списків по N значень.
        4) Для кожного раунду та кожного біта розраховуються:
               p(bit=1) та H(p)
    Повертає:
        entropies         — 16×32 матриця ентропій
        round_Rs_matrix   — зібрані R, що можуть використовуватись для графіків
    """

    plaintexts = generate_random_plaintexts(N)

    # round_Rs_matrix[i] — список R_i всіх N plaintext
    round_Rs_matrix: List[List[int]] = [[] for _ in range(16)]

    # Збір R на кожному plaintext 
    for pt in plaintexts:
        _, round_Rs = encrypt_block_and_collect(pt, key64)
        for i in range(16):
            round_Rs_matrix[i].append(round_Rs[i])

    # Обчислення ентропії 
    entropies = compute_entropy_matrix(round_Rs_matrix, msb_order=msb_order)

    return entropies, round_Rs_matrix
