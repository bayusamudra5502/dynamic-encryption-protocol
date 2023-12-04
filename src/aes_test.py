from chaos import HenonMap
from random import SystemRandom
from aes import *

def test_daes():
  cryptogen = SystemRandom()
  
  enc_map = HenonMap(cryptogen.random() * 5, cryptogen.random() * 5, cryptogen.random() * 5)
  dec_map = enc_map.copy()

  assert enc_map == dec_map

  iv = cryptogen.randbytes(16)
  message = b"A" * 256
  daes_enc = DynamicAES(enc_map, rotate_size=16, iv=iv)
  
  ct = daes_enc.encrypt(message)

  daes_dec = DynamicAES(dec_map, rotate_size=16, iv=iv)
  pt = daes_dec.decrypt(ct)

  assert pt == message

  
def test_daes_hmac():
  cryptogen = SystemRandom()
  
  enc_map = HenonMap(cryptogen.random() * 5, cryptogen.random() * 5, cryptogen.random() * 5)
  dec_map = enc_map.copy()

  assert enc_map == dec_map

  iv = cryptogen.randbytes(16)
  message = b"A" * 256
  daes_enc = DynamicAESWithHMAC(enc_map, rotate_size=64, iv=iv)
  
  ct = daes_enc.encrypt(message)

  daes_dec = DynamicAESWithHMAC(dec_map, rotate_size=64, iv=iv)
  pt = daes_dec.decrypt(ct)

  assert pt == message

def test_daes_hmac_different_rotate():
  cryptogen = SystemRandom()
  
  enc_map = HenonMap(cryptogen.random() * 5, cryptogen.random() * 5, cryptogen.random() * 5)
  dec_map = enc_map.copy()

  assert enc_map == dec_map

  iv = cryptogen.randbytes(16)
  message = b"A" * 256
  daes_enc = DynamicAESWithHMAC(enc_map, rotate_size=16*3, iv=iv)
  
  ct = daes_enc.encrypt(message)

  daes_dec = DynamicAESWithHMAC(dec_map, rotate_size=16*3, iv=iv)
  pt = daes_dec.decrypt(ct)

  assert pt == message

def test_invalid_daes_hmac():
  cryptogen = SystemRandom()
  
  enc_map = HenonMap(cryptogen.random() * 5, cryptogen.random() * 5, cryptogen.random() * 5)
  dec_map = enc_map.copy()

  assert enc_map == dec_map

  iv = cryptogen.randbytes(16)
  message = b"A" * 256
  daes_enc = DynamicAESWithHMAC(enc_map, rotate_size=64, iv=iv)
  
  ct = daes_enc.encrypt(message)
  ct = bytearray(ct)
  ct[cryptogen.randint(0, len(ct))] = cryptogen.randint(0, 256)

  daes_dec = DynamicAESWithHMAC(dec_map, rotate_size=64, iv=iv)

  try:
    pt = daes_dec.decrypt(ct)
    raise Exception("not raising an error")
  except ValueError:
    assert True

