from lib.crypto.csprng import *
from random import SystemRandom
from lib.crypto.aes import *


def test_tc1_1_1_2():
    cryptogen = SystemRandom()

    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    enc_iv = SineHenonMap(cryptogen.random(),
                          cryptogen.random(), cryptogen.random())
    enc_dec = enc_iv.copy()

    assert enc_map == dec_map

    message = SystemRandom().randbytes(250)
    daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

    ct1 = daes_enc.encrypt(message)

    daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)
    pt1 = daes_dec.decrypt(ct1)

    assert pt1 == message

    message = SystemRandom().randbytes(256)
    daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

    ct1 = daes_enc.encrypt(message)

    daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)
    pt1 = daes_dec.decrypt(ct1)

    assert pt1 == message


def test_tc1_3():
    cryptogen = SystemRandom()

    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    enc_iv = SineHenonMap(cryptogen.random(),
                          cryptogen.random(), cryptogen.random())
    enc_dec = enc_iv.copy()

    assert enc_map == dec_map

    message = SystemRandom().randbytes(250)
    daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

    ct1 = daes_enc.encrypt(message)

    daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)
    daes_dec.decrypt(ct1)

    try:
        daes_dec.decrypt(ct1)
        assert False
    except Exception as e:
        assert True


# def test_tc1_5():
#     cryptogen = SystemRandom()

#     enc_map = SineHenonMap(cryptogen.random(),
#                            cryptogen.random(), cryptogen.random())
#     dec_map = enc_map.copy()

#     enc_iv = SineHenonMap(cryptogen.random(),
#                           cryptogen.random(), cryptogen.random())
#     enc_dec = enc_iv.copy()

#     assert enc_map == dec_map

#     message = b"A" * 256
#     daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

#     ct1 = bytearray(daes_enc.encrypt(message))

#     # Change ciphertext in the first block
#     for i in range(16):
#         ct1[i] ^= b'B'[0]

#     daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)
#     result = daes_dec.decrypt(ct1)

#     assert result[:16] != b"A" * 16
#     assert result[16:] == b"A" * 240


# def test_tc1_6():
#     cryptogen = SystemRandom()

#     enc_map = SineHenonMap(cryptogen.random(),
#                            cryptogen.random(), cryptogen.random())
#     dec_map = enc_map.copy()

#     enc_iv = SineHenonMap(cryptogen.random(),
#                           cryptogen.random(), cryptogen.random())
#     enc_dec = enc_iv.copy()
#     enc_dec = enc_dec.next().next().next()

#     assert enc_map == dec_map

#     message = b"A" * 256
#     daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

#     ct1 = bytearray(daes_enc.encrypt(message))

#     daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)

#     try:
#         daes_dec.decrypt(ct1)
#         assert False
#     except Exception as e:
#         assert True


def test_tc1_4():
    cryptogen = SystemRandom()

    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    enc_iv = SineHenonMap(cryptogen.random(),
                          cryptogen.random(), cryptogen.random())
    enc_dec = enc_iv.copy()

    assert enc_map == dec_map

    message = b"A" * 256
    daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

    ct1 = daes_enc.encrypt(message)
    ct2 = daes_enc.encrypt(message)
    assert ct1 != ct2
