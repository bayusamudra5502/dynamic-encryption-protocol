from lib.crypto.csprng import *
from random import SystemRandom
from lib.crypto.aes import *
import os


def test_daes():
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

    daes_dec = DynamicAES(dec_map, block_size=16, iv=enc_dec)
    pt1 = daes_dec.decrypt(ct1)

    assert pt1 == message

    ct2 = daes_enc.encrypt(message)
    assert ct1 != ct2

    pt2 = daes_dec.decrypt(ct2)
    assert pt2 == message


def test_daes_cbc():
    cryptogen = SystemRandom()

    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    iv = os.urandom(16)

    assert enc_map == dec_map

    message = b"A" * 256
    daes_enc = DynamicAESCBC(enc_map, block_size=16, iv=iv)

    ct1 = daes_enc.encrypt(message)

    daes_dec = DynamicAESCBC(dec_map, block_size=16, iv=iv)
    pt1 = daes_dec.decrypt(ct1)

    assert pt1 == message

    ct2 = daes_enc.encrypt(message)
    assert ct1 != ct2

    pt2 = daes_dec.decrypt(ct2)
    assert pt2 == message


def test_dmac():
    cryptogen = SystemRandom()
    mac_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())

    message = cryptogen.randbytes(256)
    dmac = DynamicHMAC(mac_map)
    dmac_verify = DynamicHMAC(mac_map)

    result1 = dmac.generate(message)
    assert dmac_verify.verify(message, result1)
    dmac_verify.rotate()

    result2 = dmac.generate(message)
    assert result1 != result2

    assert dmac_verify.verify(message, result2)
    dmac_verify.rotate()


def test_dmac_failed():
    cryptogen = SystemRandom()
    mac_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())

    message = cryptogen.randbytes(256)
    dmac = DynamicHMAC(mac_map)

    result = dmac.generate(message)
    message += b"0"

    try:
        assert dmac.verify(message, result)
        dmac.rotate()

        assert False
    except CipherException:
        assert True
