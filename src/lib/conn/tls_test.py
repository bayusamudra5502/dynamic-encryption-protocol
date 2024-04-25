from lib.conn.tlsrecord import *
from lib.enc.aes import *
from random import SystemRandom
from lib.conn.tls import *


def test_tls():
    alice, bob = generate_tls_record_layer_handler()
    transport = MemoryTransport()

    alice_conn = TLSConnection(transport, tls_handler=alice)
    bob_conn = TLSConnection(transport, tls_handler=bob)

    alice_conn.send(b"Hello, Bob!")
    data = bob_conn.recv(11)

    assert transport.buffer_size() == 0
    assert data == b"Hello, Bob!"


def test_tls_mega():
    alice, bob = generate_tls_record_layer_handler()
    transport = MemoryTransport()

    alice_conn = TLSConnection(transport, tls_handler=alice)
    bob_conn = TLSConnection(transport, tls_handler=bob)

    alice_conn.send(b"A" * (2**20))
    data = bob_conn.recv(2**20)

    assert transport.buffer_size() == 0
    assert data == b"A"*(2**20)


def test_tls_recv_small():
    alice, bob = generate_tls_record_layer_handler()
    transport = MemoryTransport()

    alice_conn = TLSConnection(transport, tls_handler=alice)
    bob_conn = TLSConnection(transport, tls_handler=bob)

    alice_conn.send(b"Hello, Bob!")
    data = bob_conn.recv(5)
    assert data == b"Hello"

    data = bob_conn.recv(6)
    assert data == b", Bob!"


class MemoryTransport(Transport):
    def __init__(self):
        self.__data = b""

    def send(self, data: bytes) -> None:
        self.__data += data

    def recv(self, size: int) -> bytes:
        data = self.__data[:size]
        self.__data = self.__data[size:]
        return data

    def buffer_size(self) -> int:
        return len(self.__data)


def random_henon():
    cryptogen = SystemRandom()
    mac_map = HenonMap(cryptogen.random(),
                       cryptogen.random(), cryptogen.random())

    return mac_map


def random_start():
    cryptogen = SystemRandom()
    return cryptogen.randint(0, 2**64 - 1)


def generate_tls_record_layer_handler():
    h1 = random_henon()
    h2 = random_henon()
    m1 = random_henon()
    m2 = random_henon()

    seqnum = random_start()

    alice = TLSRecordHandler(ProtocolVersion(
        4, 0), h1, h2, m1, m2, sequence_number=seqnum)
    bob = TLSRecordHandler(ProtocolVersion(4, 0), h2, h1,
                           m2, m1, sequence_number=seqnum)

    return alice, bob