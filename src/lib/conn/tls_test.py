from lib.conn.tlsrecord import *
from lib.crypto.aes import *
from random import SystemRandom
from lib.conn.tls import *
from lib.crypto.csprng import *
from lib.conn.memory import *


def test_tls():
    alice, bob = generate_tls_record_layer_handler()
    transport = MemoryTransport()

    alice_conn = TLSConnection(transport, tls_handler=alice)
    bob_conn = TLSConnection(transport, tls_handler=bob)

    alice_conn.send(b"Hello, Bob!")
    data = bob_conn.recv(11)

    assert transport.buffer_size() == 0
    assert data == b"Hello, Bob!"


def disabled_test_tls_mega():
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


def random_henon():
    cryptogen = SystemRandom()
    mac_map = SineHenonMap(cryptogen.random(),
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
    iv1 = random_henon()
    iv2 = random_henon()

    seqnum = random_start()

    alice = TLSApplicationRecordHandler(ProtocolVersion(
        4, 0),
        DynamicAES(h1, block_size=16, iv=iv1),
        DynamicAES(h2, block_size=16, iv=iv2),
        DynamicHMAC(m1),
        DynamicHMAC(m2),
        sequence_number=seqnum
    )
    bob = TLSApplicationRecordHandler(
        ProtocolVersion(4, 0),
        DynamicAES(h2, iv=iv2),
        DynamicAES(h1, iv=iv1),
        DynamicHMAC(m2),
        DynamicHMAC(m1),
        sequence_number=seqnum
    )

    return alice, bob
