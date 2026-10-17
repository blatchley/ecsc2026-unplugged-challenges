from random import getrandbits, randint
from Crypto.Util.number import getPrime, bytes_to_long

flag = bytes_to_long(open("flag.txt", "rb").read())

p = getPrime(2048)

assert flag**4 < p

coeffs = [randint(1, p-1) for _ in range(2)]

secret = [getrandbits(64 * i) for i in range(1, 3)]

for c,s in zip(coeffs, secret):
    flag = (flag + c * s) % p

print("p =", p)
print("coeffs =", coeffs)
print("total =", flag)


