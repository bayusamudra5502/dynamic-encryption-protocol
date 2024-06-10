import multiprocessing.queues
from lib.crypto.csprng import *
from lib.crypto.aes import *
from lib.util import *
import multiprocessing

from random import SystemRandom
from os import urandom

import time


def pack_mac_outside(chaosAes: DynamicAES, mac: MAC, data: bytes) -> tuple[bytes, bytes]:
    cipher = chaosAes.encrypt(data)
    return cipher + mac.generate(cipher)


def pack_mac_inside(chaosAes: DynamicAES, mac: MAC, data: bytes) -> tuple[bytes, bytes]:
    macValue = mac.generate(data)
    return chaosAes.encrypt(data + macValue)


def unpack_mac_outside(chaosAes: DynamicAES, mac: MAC, data: bytes) -> bytes:
    ciphertext, macValue = data[:-MAC_SIZE], data[-MAC_SIZE:]
    if not mac.verify(ciphertext, macValue):
        raise CipherException("MAC verification failed")
    return chaosAes.decrypt(ciphertext)


def unpack_mac_inside(chaosAes: DynamicAES, mac: MAC, data: bytes) -> bytes:
    payload = chaosAes.decrypt(data)
    plaintext, macValue = payload[:-MAC_SIZE], payload[-MAC_SIZE:]
    if not mac.verify(plaintext, macValue):
        raise CipherException("MAC verification failed")
    return plaintext


def do_test_mac_inside(n, size=2**14, with_bad_mac=False):
    cryptogen = SystemRandom()
    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    enc_iv = SineHenonMap(cryptogen.random(),
                          cryptogen.random(), cryptogen.random())
    enc_dec = enc_iv.copy()

    mac = TLSHMAC(urandom(32))

    if with_bad_mac:
        pair_mac = TLSHMAC(urandom(32))
    else:
        pair_mac = mac

    encrypted = []

    for i in range(n):
        data = urandom(size)
        daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

        cipher = pack_mac_inside(daes_enc, mac, data)
        encrypted.append(cipher)

    start_time = time.time()
    for i in range(n):
        try:
            unpack_mac_inside(DynamicAES(dec_map, block_size=16,
                                         iv=enc_dec), pair_mac, encrypted[i])
        except CipherException as err:
            if not with_bad_mac:
                raise err

    end_time = time.time()

    return end_time - start_time


def do_test_mac_outside(n, size=2**14, with_bad_mac=False):
    cryptogen = SystemRandom()
    enc_map = SineHenonMap(cryptogen.random(),
                           cryptogen.random(), cryptogen.random())
    dec_map = enc_map.copy()

    enc_iv = SineHenonMap(cryptogen.random(),
                          cryptogen.random(), cryptogen.random())
    enc_dec = enc_iv.copy()

    mac = TLSHMAC(urandom(32))

    if with_bad_mac:
        pair_mac = TLSHMAC(urandom(32))
    else:
        pair_mac = mac

    encrypted = []

    for i in range(n):
        data = urandom(size)
        daes_enc = DynamicAES(enc_map, block_size=16, iv=enc_iv)

        cipher = pack_mac_outside(daes_enc, mac, data)
        encrypted.append(cipher)

    start_time = time.time()
    for i in range(n):
        try:
            unpack_mac_outside(DynamicAES(dec_map, block_size=16,
                                          iv=enc_dec), pair_mac, encrypted[i])
        except CipherException as err:
            if not with_bad_mac:
                raise err

    end_time = time.time()

    return end_time - start_time


def multiprocess_kernel(n: int, stream: int, func, result: multiprocessing.Queue):
    for _ in range(stream):
        result.put(func(n, with_bad_mac=True))


def main():
    n = 10
    stream = 10

    mac_inside = multiprocessing.Queue()
    mac_outside = multiprocessing.Queue()

    inside = multiprocessing.Process(
        target=multiprocess_kernel, args=(n, stream, do_test_mac_inside, mac_inside))
    outside = multiprocessing.Process(
        target=multiprocess_kernel, args=(n, stream, do_test_mac_outside, mac_outside))

    inside.start()
    outside.start()

    inside.join()
    outside.join()

    result = []
    for _ in range(stream):
        result.append((mac_inside.get(), mac_outside.get()))

    for i, (inside, outside) in enumerate(result):
        print(f"{i},{inside},{outside}")


main()
