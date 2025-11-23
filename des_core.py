from typing import List, Tuple
import base64
from constants.tables import IP_TABLE, FP_TABLE, E_TABLE, P_TABLE, PC1_TABLE, PC2_TABLE
from constants.shifts import SHIFTS
from constants.blocks import S_BOXES

def permute(block: int, table: List[int], input_bits: int) -> int:
    # Загальна функція перестановки.
    # Беремо біти з позицій, заданих таблицею, і формуємо нове число.
    out = 0
    for pos in table:
        bit = (block >> (input_bits - pos)) & 1
        out = (out << 1) | bit
    return out

def left_rotate(value: int, shifts: int, width: int) -> int:
    # Кільцевий зсув для генерації ключів (C і D частини).
    shifts %= width
    return ((value << shifts) & ((1 << width) - 1)) | (value >> (width - shifts))

def split_bits(value: int, size_right: int) -> Tuple[int,int]:
    # Розділяє блок на дві частини: ліву та праву.
    right = value & ((1 << size_right) - 1)
    left = value >> size_right
    return left, right

def generate_subkeys(key64: int) -> List[int]:
    # Генерація 16 підключів по 48 біт для кожного раунду DES.
    # 1) PC1 - прибираємо біти парності -> 56-бітний ключ.
    key56 = permute(key64, PC1_TABLE, 64)

    # Ділимо на C0 та D0 по 28 біт.
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)
    
    subkeys = []
    for round_no, shift in enumerate(SHIFTS, start=1):
        # Кожен раунд: циклічне обертання обох половин.
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)

        # Об'єднуємо в 56 біт -> застосовуємо PC2 для скорочення до 48 біт.
        combined = (C << 28) | D
        k48 = permute(combined, PC2_TABLE, 56)
        subkeys.append(k48)
    return subkeys

def sbox_substitution(six_bits: int, sbox_index: int) -> int:
    # S-box перетворення: 6 біт -> 4 біти.
    # Ряд визначається комбінацією першого і останнього біта.
    row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b1)
    # Колонка – середні 4 біти.
    col = (six_bits >> 1) & 0b1111
    sbox = S_BOXES[sbox_index]
    return sbox[row * 16 + col]

def f_function(R32: int, k48: int) -> int:
    # Функція F – серце DES.
    # 1) Розширення R з 32 -> 48 біт (E-table).
    expanded = permute(R32, E_TABLE, 32)

    # 2) XOR з підключем.
    x = expanded ^ k48
    
    # 3) Розбиваємо на вісім 6-бітних груп -> S-box -> 32 біти.
    s_out = 0
    for i in range(8):
        shift = (7 - i) * 6
        six = (x >> shift) & 0b111111
        four = sbox_substitution(six, i) & 0b1111
        s_out = (s_out << 4) | four
    
    # 4) P-перестановка (32 біти).
    p_out = permute(s_out, P_TABLE, 32)
    return p_out

def encrypt_block(block64: int, key64: int) -> int:
    # DES шифрування одного 64-бітного блока.
    subkeys = generate_subkeys(key64)

    # Початкова перестановка IP.
    ip = permute(block64, IP_TABLE, 64)

    # Розділення на L0 і R0.
    L, R = split_bits(ip, 32)
    
    # 16 раундів Feistel структури.
    for i in range(16):
        newL = R
        # R_i = L_{i-1} XOR F(R_{i-1}, K_i)
        newR = L ^ f_function(R, subkeys[i])
        L, R = newL, newR
    
    # Після останнього раунду відбувається свап (R16||L16).
    preoutput = (R << 32) | L

    # Завершальна перестановка FP.
    cipher = permute(preoutput, FP_TABLE, 64)
    return cipher

def decrypt_block(block64: int, key64: int) -> int:
    # Дешифрування працює ідентично шифруванню,
    # тільки підключі подаються у зворотному порядку.
    subkeys = generate_subkeys(key64)

    ip = permute(block64, IP_TABLE, 64)
    L, R = split_bits(ip, 32)
    
    for i in range(16):
        newL = R
        newR = L ^ f_function(R, subkeys[15 - i])
        L, R = newL, newR
    
    preoutput = (R << 32) | L
    plain = permute(preoutput, FP_TABLE, 64)
    return plain

def text_to_bits(text: str) -> bytes:
    return text.encode('utf-8')

def key_to_bits(key: str) -> int:
    # Конвертація текстового ключа у 64 біти.
    # Доповнення нулями до 8 байтів.
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes[:8].ljust(8, b'\x00')
    return int.from_bytes(key_bytes, byteorder='big')

def des_encrypt(plaintext: str, key: str) -> str:
    # DES працює з блоками 64 біти -> застосуємо PKCS#7 padding.
    data = text_to_bits(plaintext)
    key64 = key_to_bits(key)
    
    padding_length = 8 - (len(data) % 8)
    data = data + bytes([padding_length] * padding_length)
    
    ciphertext = b''
    for i in range(0, len(data), 8):
        block = int.from_bytes(data[i:i+8], byteorder='big')
        encrypted = encrypt_block(block, key64)
        ciphertext += encrypted.to_bytes(8, byteorder='big')
    
    # Результат кодуємо base64.
    return base64.b64encode(ciphertext).decode('ascii')

def des_decrypt(base64_ciphertext: str, key: str) -> str:
    ciphertext = base64.b64decode(base64_ciphertext)
    key64 = key_to_bits(key)

    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[i:i+8], byteorder='big')
        decrypted = decrypt_block(block, key64)
        plaintext += decrypted.to_bytes(8, byteorder='big')

    # Знімаємо PKCS#7 padding.
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    return plaintext.decode('utf-8')