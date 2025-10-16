from binascii import unhexlify

# hex value from question
k1_hex    = "3c3f0193af37d2ebbc50cc6b91d27cf61197"
k21_hex   = "ff76edcad455b6881b92f726987cbf30c68c"
k23_hex   = "611568312c102d4d921f26199d39fe973118"
k1234_hex = "91ec5a6fa8a12f908f161850c591459c3887"
f45_hex   = "0269dd12fe3435ea63f63aef17f8362cdba8"

# convert from hex to bytes
k1    = unhexlify(k1_hex)
k21   = unhexlify(k21_hex)
k23   = unhexlify(k23_hex)
k1234 = unhexlify(k1234_hex)
f45   = unhexlify(f45_hex)

# helper
def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def xor_all(*args: bytes) -> bytes:
    from functools import reduce
    return reduce(bxor, args)

# 1. recover KEY1..KEY4 using XOR algebra
KEY1 = k1
KEY2 = bxor(k21, KEY1)             # KEY2 = (KEY2 ^ KEY1) ^ KEY1
KEY3 = bxor(KEY2, k23)             # KEY3 = KEY2 ^ (KEY2 ^ KEY3) -> KEY3
KEY4 = xor_all(k1234, KEY1, KEY2, KEY3)  # k1234 ^ KEY1 ^ KEY2 ^ KEY3 -> KEY4

# 2. compute x = f45 ^ KEY4  =>  x = FLAG ^ KEY5
X = bxor(f45, KEY4)

# 3. known prefix method: flags are cry{...} -> derive KEY5 first 4 bytes
known_prefix = b"cry{"
KEY5_first4 = bytes(X[i] ^ known_prefix[i] for i in range(4))

# 4. expand KEY5 (repeat 4-byte key) to message length and recover FLAG
msg_len = len(X)
repeat = (msg_len + 4 - 1) // 4
KEY5_full = (KEY5_first4 * repeat)[:msg_len]
FLAG = bxor(X, KEY5_full)

print("KEY5 (first 4 bytes hex):", KEY5_first4.hex())
print("FLAG:", FLAG.decode('ascii', errors='replace'))
