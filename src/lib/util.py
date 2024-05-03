import numpy as np


def to_linear(x):
    res = np.asarray(((np.array(x)) * 256), dtype=np.uint8)
    return res


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
    return bytes(result)
