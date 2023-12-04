import numpy as np

def to_linear(x):
  res = np.asarray(np.floor(np.multiply(x, 2 ** (32-5))), dtype=np.uint32)
  return res

def xor(x: bytes, y: bytes) -> bytes:
  assert len(x) == len(y)

  res = bytearray()
  for i in range(len(x)):
    res.append(x[i] ^ y[i])

  return bytes(res)
