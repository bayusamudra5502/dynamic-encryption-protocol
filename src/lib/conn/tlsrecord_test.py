from lib.conn.tlsrecord import *
from lib.enc.aes import *
from random import SystemRandom


def test_tlsrecord():
    h1 = random_henon()
    h2 = random_henon()
    m1 = random_henon()
    m2 = random_henon()

    seqnum = random_start()

    alice = TLSRecordHandler(ProtocolVersion(
        4, 0), h1, h2, m1, m2, sequence_number=seqnum)
    bob = TLSRecordHandler(ProtocolVersion(4, 0), h2, h1,
                           m2, m1, sequence_number=seqnum)

    # From Alice to Bob
    result = alice.pack(b"Hello, Bob!")
    data = bob.unpack(result)

    assert data == b"Hello, Bob!"

    # From Alice to Bob
    result = alice.pack(b"I would like to send you a message.")
    data = bob.unpack(result)

    assert data == b"I would like to send you a message."

    # From Bob to Alice
    result = bob.pack(b"Hello, Alice!")
    data = alice.unpack(result)

    assert data == b"Hello, Alice!"

    # From Bob to Alice
    result = bob.pack(b"Okayy, I will hear you...")
    data = alice.unpack(result)

    assert data == b"Okayy, I will hear you..."

    # Eve suddenly appears and tries to replay the message
    result_eve = result = alice.pack(b"I will send you $1000")
    data_eve = bob.unpack(result)

    assert data_eve == b"I will send you $1000"
    assert result_eve == result

    result = bob.pack(b"Woah")
    data = alice.unpack(result)

    assert data == b"Woah"

    # Eve resend the message
    try:
        alice.unpack(result_eve)
        assert False
    except CipherException:
        pass

    try:
        result_eve = TLSRecordLayer(ProtocolVersion(0, 0), result_eve.get_content_type(
        ), result_eve.get_content(), result_eve.get_mac(), content_size=result_eve.get_content_size())
        alice.unpack(result_eve)
        assert False
    except CipherException:
        pass

    # Alice and bob should able to communicate normally
    result = bob.pack(b"Thanks")
    data = alice.unpack(result)

    assert data == b"Thanks"

    result = alice.pack(b"You're welcome")
    data = bob.unpack(result)

    assert data == b"You're welcome"


def random_henon():
    cryptogen = SystemRandom()
    mac_map = HenonMap(cryptogen.random(),
                       cryptogen.random(), cryptogen.random())

    return mac_map


def random_start():
    cryptogen = SystemRandom()
    return cryptogen.randint(0, 2**64 - 1)