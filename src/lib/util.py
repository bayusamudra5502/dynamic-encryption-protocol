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
