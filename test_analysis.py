from analysis import (
    is_weak_key,
    encrypt_block_and_collect,
    analyze_entropy
)

from des_core import encrypt_block, decrypt_block


# TEST 1 — Перевірка слабких ключів
print("=== TEST 1 — Weak keys ===")

keys = [
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x0101010101010101,
    0x133457799BBCDFF1
]

for k in keys:
    print(hex(k), "->", is_weak_key(k))


# TEST 2 — Інструментоване шифрування
print("\n=== TEST 2 — encrypt_block_and_collect ===")

key = 0x133457799BBCDFF1
pt  = 0x0123456789ABCDEF

ct, round_Rs = encrypt_block_and_collect(pt, key)

print("cipher =", hex(ct))
print("round_Rs count =", len(round_Rs))
print("first 3 R:", [hex(r) for r in round_Rs[:3]])

# TEST 3 — Аналіз ентропії
print("\n=== TEST 3 — analyze_entropy ===")

ent, data = analyze_entropy(key, N=50000)

print("кількість раундів =", len(ent))     
print("кількість біт =", len(ent[0]))      
print("перших 5 H раунду 1:", ent[0][:5])


# TEST 4 — Середня ентропія по раундах
print("\n=== TEST 4 — Round average entropy ===")

for i in range(16):
    avg = sum(ent[i]) / 32
    print(f"Раунд {i+1}: {avg:.8f}")

# TEST 5 — Повноцінний DES (перевірка прямого/зворотного)
print("\n=== TEST 5 — encrypt/decrypt consistency ===")

pt  = 0x4142434445464748  # ASCII "ABCDEFGH"
ct  = encrypt_block(pt, key)
pt2 = decrypt_block(ct, key)

print("pt    =", hex(pt))
print("pt2   =", hex(pt2))
print("OK?   =", pt == pt2)
