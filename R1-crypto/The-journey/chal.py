from Crypto.Util.number import isPrime
from secret_values import p, q, i, password

with open("flag.txt", "rb") as f:
    flag = f.read().strip()

assert isPrime(p)
assert isPrime(4*q**2 - 137*q + 1337)
assert len(password) == 5 
assert flag.startswith(b"ECSC{") and flag.endswith(b"}")

flag = flag * i

enc = b''
for j in range(len(flag)):
    x = j**p % p ^ (flag[j] * i) % (4*q**2 - 137*q + 1337) ^ password[j % len(password)]
    enc += bytes([x])

with open("encryptedflag", "wb") as f:
    f.write(enc)

