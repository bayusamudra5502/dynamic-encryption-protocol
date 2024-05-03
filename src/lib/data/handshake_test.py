from lib.data.handshake import *
from lib.data.hello import *
from lib.data.exchange import *
from cryptography.hazmat.primitives.asymmetric import ec


def test_handshake_client_hello():
    random = Random()
    client_hello = ClientHello(
        ProtocolVersion(3, 3),
        random,
        455,
        0,
        0,
    )

    handshake = Handshake(HandshakeType.CLIENT_HELLO, client_hello)
    result = handshake.encode()

    handshake_new = Handshake.parse(result)
    assert handshake == handshake_new
    assert handshake_new.get_payload() == client_hello


def test_handshake_server_hello():
    random = Random()
    server_hello = ServerHello(
        ProtocolVersion(3, 3),
        random,
        455,
        0,
        0,
    )

    handshake = Handshake(HandshakeType.SERVER_HELLO, server_hello)
    result = handshake.encode()

    handshake_new = Handshake.parse(result)
    assert handshake == handshake_new
    assert handshake_new.get_payload() == server_hello


def test_handshake_server_key_exchange():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    point = ECPoint(public.x, public.y)

    server_key_exchange = ServerKeyExchange(
        ECDHParameter(ECParameter(), point),
        Signature(b'\x00\x00\x00\x00'),
    )

    handshake = Handshake(
        HandshakeType.SERVER_KEY_EXCHANGE, server_key_exchange)
    result = handshake.encode()

    handshake_new = Handshake.parse(result)
    assert handshake == handshake_new
    assert handshake_new.get_payload() == server_key_exchange


def test_handshake_client_key_exchange():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    point = ECPoint(public.x, public.y)

    client_key_exchange = ClientKeyExchange(point)

    handshake = Handshake(
        HandshakeType.CLIENT_KEY_EXCHANGE, client_key_exchange)
    result = handshake.encode()

    handshake_new = Handshake.parse(result)
    assert handshake == handshake_new
    assert handshake_new.get_payload() == client_key_exchange
