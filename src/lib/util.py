import numpy as np


def to_linear(x, *, size=32):
    result = 0
    i = x

    for _ in range(size):
        result <<= 1
        i *= 2

        result += int(i)

        i %= 1

    return result


def xor(x: bytes, y: bytes) -> bytes:
    assert len(x) == len(y)

    res = bytearray()
    for i in range(len(x)):
        res.append(x[i] ^ y[i])

    return bytes(res)


def to_bytes_big(x: int, length: int) -> bytes:
    result = []
    i = 0

    while x > 0:
        result.append(x & 0xff)
        x >>= 8
        i += 1

    while i < length:
        result.append(0)
        i += 1

    result = reversed(result)
    return bytes(result)[:length]


def to_int_big(x: bytes) -> int:
    result = 0

    for i in range(len(x)):
        result |= x[i] << (8 * (len(x) - i - 1))

    return result
