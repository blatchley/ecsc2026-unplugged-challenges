
import struct
import sys


class Xorshift64:
    _state: int

    def __init__(self, seed: int):
        self._state = seed
    
    def u64(self) -> int:
        mask = (1 << 64) - 1
        self._state ^= self._state >> 12
        self._state ^= (self._state << 25) & mask
        self._state ^= self._state >> 27
        return (self._state * 0x2545F4914F6CDD1D) & mask

    def genbytes(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            data += struct.pack("<Q", self.u64())
        return data[:size]


class Splitmix64:
    _state: int

    def __init__(self, seed: int):
        self._state = seed

    def u64(self) -> int:
        mask = (1 << 64) - 1

        self._state = (self._state + 0x9E3779B97F4A7C15) & mask

        value = self._state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & mask
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & mask
        value ^= value >> 31
        return value


class Obfuscator:
    def obfuscate(self, data: bytes, seed: int, count: int) -> bytes:
        rng = Xorshift64(seed)
        for opcode in self._generate_opcodes(rng, count):
            data = self._apply_opcode(data, rng, opcode)
        return data

    def _generate_opcodes(self, rng: Xorshift64, count: int) -> list[int]:
        random = rng.u64()
        opcodes = []
        for i in range(count):
            opcodes.append(random & 3)
            random >>= 2
        return opcodes
    
    def _apply_opcode(self, data: bytes, rng: Xorshift64, opcode: int) -> bytes:
        if opcode == 0: return self._rotate(data, rng)
        elif opcode == 1: return self._shuffle(data, rng)
        elif opcode == 2: return self._splitmix(data, rng)
        else:
            return self._xor(data, rng)

    def _rotate(self, data: bytes, rng: Xorshift64) -> bytes:
        value = int.from_bytes(data, "big")
        bits = len(data) * 8

        random = rng.u64()
        shift = (random >> 1) % bits
        if random & 1:
            shift = bits - shift

        mask = (1 << bits) - 1
        value = (value >> (bits - shift)) | ((value << shift) & mask)
        return value.to_bytes(len(data), "big")

    def _shuffle(self, data: bytes, rng: Xorshift64) -> bytes:
        array = bytearray(data)

        randombytes = rng.genbytes(len(data) - 1)
        for i in range(1, len(data)):
            j = randombytes[i - 1] % (i + 1)
            array[i], array[j] = array[j], array[i]
    
        return bytes(array)

    def _splitmix(self, data: bytes, rng: Xorshift64) -> bytes:
        mask = (1 << 64) - 1

        output = b""
        for i in range(0, len(data) & ~7, 8):
            splitmix = Splitmix64(rng.u64())
            a = splitmix.u64()
            b = splitmix.u64()
            shift = (a ^ b) & 0xF

            value = struct.unpack_from("<Q", data, i)[0]
            value = ((value ^ (value >> 31)) * (a | 1)) & mask
            value = ((value ^ (value >> 27)) * (b | 1)) & mask
            value = ((value << shift) & mask) | (value >> (64 - shift))
            output += struct.pack("<Q", value)

        output += self._xor(data[len(data) & ~7:], rng)
        return output

    def _xor(self, data: bytes, rng: Xorshift64) -> bytes:
        mask = rng.genbytes(len(data))
        return bytes(p ^ q for p, q in zip(data, mask))


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <flag>")
        return
    
    seed = 0xE35CAA6304A467B1
    flag = sys.argv[1].encode()

    obfuscator = Obfuscator()
    data = obfuscator.obfuscate(flag, seed, 20)

    with open("flag.bin", "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
