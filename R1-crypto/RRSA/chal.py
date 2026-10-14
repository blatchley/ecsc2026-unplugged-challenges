from Crypto.Util.number import getPrime

p,q,r = getPrime(256), getPrime(256), getPrime(256)

m1 = b"welcome to ECSC ctf unplugged"
m2 = b"how fast can you go???"
m3 = open("flag.txt", "rb").read()

n1 = p*q
n2 = q*r
n3 = p*q*r*r
e = 65537

print(f'n1 = {hex(n1)}')
print(f'n2 = {hex(n2)}')
print(f'n3 = {hex(n3)}')

c1 = pow(int.from_bytes(m1, 'big'), e, n1)
c2 = pow(int.from_bytes(m2, 'big'), e, n2)
c3 = pow(int.from_bytes(m3, 'big'), e, n3)

print(f'c1 = {hex(c1)}')
print(f'c2 = {hex(c2)}')
print(f'c3 = {hex(c3)}')