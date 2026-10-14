from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


def secure_encrypt(pt, key, nonce = os.urandom(12)):
    aes_enc = AES.new(key, AES.MODE_CTR, nonce = nonce)
    ct = aes_enc.encrypt(pt)
    return ct

def easy_encrypt(pt, key, nonce = b'mysupernonce'):
    aes_enc = AES.new(key, AES.MODE_CTR, nonce = nonce)
    ct = aes_enc.encrypt(pt)
    return ct

key = os.urandom(16)

with open("flag.txt", "rb") as f:
    flag = f.read().strip()


print(f'1 for secure_encrypt')
print(f'2 for easy_encrypt')
while True:
    choice = int(input("which mode?:"))
    msg = input("and what to encrypt?:").encode()
    assert msg
    if choice == 1:
        secure_ct = secure_encrypt(msg[:10] + flag, key)
        print(f'secure_encrypt of flag: {secure_ct.hex()}')
    elif choice == 2:
        easy_ct = easy_encrypt(msg[:10] + b"not that easy is it", key)
        print(f'easy_encrypt of flag: {easy_ct.hex()}')
    else:
        print("thats not an option")
        exit()


