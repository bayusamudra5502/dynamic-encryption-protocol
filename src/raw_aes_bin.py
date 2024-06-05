from lib.crypto.csprng import *
from lib.util import *
from random import random, SystemRandom
from lib.crypto.aes import *
from Crypto.Cipher import AES as CryptoAES
import os

RANDOM: CSPRNG = SineHenonMap(random(), random(), random())
IV: CSPRNG = SineHenonMap(random(), random(), random())

AES = CryptoAES.new(os.urandom(32), CryptoAES.MODE_CBC, iv=os.urandom(16))
# AES = DynamicAESCBC(RANDOM, os.urandom(16))

data = b"\xff" * 500_000_000
encrypted = AES.encrypt(data)

with open("encrypted_aes_cbc_normal.dat", "wb") as f:
    f.write(encrypted)
