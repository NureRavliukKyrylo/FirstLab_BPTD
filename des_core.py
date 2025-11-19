from typing import List, Tuple
import base64
from constants.tables import IP_TABLE,FP_TABLE,E_TABLE,P_TABLE,PC1_TABLE,PC2_TABLE
from constants.shifts import SHIFTS
from constants.blocks import S_BOXES

def permute(block: int, table: List[int], input_bits: int) -> int:
    out = 0
    for pos in table:
        bit = (block >> (input_bits - pos)) & 1
        out = (out << 1) | bit
    return out

def left_rotate(value: int, shifts: int, width: int) -> int:
    shifts %= width
    return ((value << shifts) & ((1 << width) - 1)) | (value >> (width - shifts))

def split_bits(value: int, size_right: int) -> Tuple[int,int]:
    right = value & ((1 << size_right) - 1)
    left = value >> size_right
    return left, right

def generate_subkeys(key64: int) -> List[int]:
    key56 = permute(key64, PC1_TABLE, 64)
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)
    
    subkeys = []
    for round_no, shift in enumerate(SHIFTS, start=1):
        C = left_rotate(C, shift, 28)
        D = left_rotate(D, shift, 28)
        combined = (C << 28) | D
        k48 = permute(combined, PC2_TABLE, 56)
        subkeys.append(k48)
    return subkeys

def sbox_substitution(six_bits: int, sbox_index: int) -> int:
    row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b1)
    col = (six_bits >> 1) & 0b1111
    sbox = S_BOXES[sbox_index]
    return sbox[row * 16 + col]

def f_function(R32: int, k48: int) -> int:
    expanded = permute(R32, E_TABLE, 32)
    x = expanded ^ k48
    
    s_out = 0
    for i in range(8):
        shift = (7 - i) * 6
        six = (x >> shift) & 0b111111
        four = sbox_substitution(six, i) & 0b1111
        s_out = (s_out << 4) | four
    
    p_out = permute(s_out, P_TABLE, 32)
    return p_out

def encrypt_block(block64: int, key64: int) -> int:
    subkeys = generate_subkeys(key64)
    ip = permute(block64, IP_TABLE, 64)
    L, R = split_bits(ip, 32)
    
    for i in range(16):
        newL = R
        newR = L ^ f_function(R, subkeys[i])
        L, R = newL, newR
    
    preoutput = (R << 32) | L
    cipher = permute(preoutput, FP_TABLE, 64)
    return cipher

def decrypt_block(block64: int, key64: int) -> int:
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
    key_bytes = key.encode('utf-8')
    key_bytes = key_bytes[:8].ljust(8, b'\x00')
    return int.from_bytes(key_bytes, byteorder='big')

def des_encrypt(plaintext: str, key: str) -> str:
    data = text_to_bits(plaintext)

    key64 = key_to_bits(key)
    
    padding_length = 8 - (len(data) % 8)
    data = data + bytes([padding_length] * padding_length)
    
    ciphertext = b''
    for i in range(0, len(data), 8):
        block = int.from_bytes(data[i:i+8], byteorder='big')
        encrypted = encrypt_block(block, key64)
        ciphertext += encrypted.to_bytes(8, byteorder='big')
    
    return base64.b64encode(ciphertext).decode('ascii')

def des_decrypt(base64_ciphertext: str, key: str) -> str:
    ciphertext = base64.b64decode(base64_ciphertext)

    key64 = key_to_bits(key)

    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[i:i+8], byteorder='big')
        decrypted = decrypt_block(block, key64)
        plaintext += decrypted.to_bytes(8, byteorder='big')

    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    return plaintext.decode('utf-8')