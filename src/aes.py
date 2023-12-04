from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from util import *
from chaos import HenonMap
from random import SystemRandom
from Crypto.Util.Padding import pad, unpad


class DynamicAES:
  __chaos: HenonMap
  __last_block: bytes
  __block_size: bytes
  _AUTH_SIZE = 0

  def __init__(self, chaos: HenonMap, *, iv: bytes = None, rotate_size: int = 16) -> None:
    self.__chaos = chaos

    if rotate_size % 16 != 0:
      raise Exception("block size must be multiply of 16")

    if iv == None:
      random = SystemRandom()
      self.__last_block = random.randbytes(16)
    else:
      if len(iv) != 16:
        raise Exception("initial vector size must be 16")
      
      self.__last_block = iv

    self.__block_size = rotate_size

  def __get_current_key(self) -> bytes:
    keys = bytearray()

    for i in range(8):
      result = to_linear(self.__chaos.get_tuple()[0])
      keys.extend(result.tobytes())
      self.__chaos = self.__chaos.next()

    return bytes(keys)
  
  def _generate_auth(self, data: bytes, key: bytes):
    return b''

  def _validate_ciphertext(self, data: bytes, digest: bytes, key: bytes):
    pass

  def encrypt(self, data: bytes):
    data = pad(data, 16)

    cipertext = bytearray()

    for i in range(0, len(data), self.__block_size):
      key = self.__get_current_key()
      plaintext = data[i:i+self.__block_size]

      aes = AES.new(key, AES.MODE_CBC, iv=self.__last_block)
      res = aes.encrypt(plaintext)
      self.__last_block = res[-16:]

      cipertext.extend(res)
      cipertext.extend(self._generate_auth(res, key))

    return bytes(cipertext)
  
  def decrypt(self, data: bytes):
    plaintext = []

    for i in range(0, len(data), self.__block_size + self._AUTH_SIZE):
      key = self.__get_current_key()
      
      block_data = data[i:i+self.__block_size+self._AUTH_SIZE]

      if self._AUTH_SIZE != 0:
        ciphertext = block_data[:-self._AUTH_SIZE]
      else:
        ciphertext = block_data

      self._validate_ciphertext(ciphertext, block_data[-self._AUTH_SIZE:], key)

      aes = AES.new(key, AES.MODE_CBC, iv=self.__last_block)
      res = aes.decrypt(ciphertext)

      plaintext.extend(res)
      self.__last_block = ciphertext[-16:]

    return unpad(bytes(plaintext), 16)

class DynamicAESWithHMAC(DynamicAES):
  _AUTH_SIZE = 32

  def _generate_auth(self, data: bytes, key: bytes):
    return HMAC.new(key, data, digestmod=SHA256).digest()

  def _validate_ciphertext(self, data: bytes, digest: bytes, key: bytes):
    hmac = HMAC.new(key, data, digestmod=SHA256)
    hmac.verify(digest)
