from lib.data.exchange import *
from cryptography.hazmat.primitives.asymmetric import ec


def test_ec_point():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()
    point = ECPoint(public.x, public.y)

    encoded = point.encode()
    new_point = ECPoint.parse(encoded)

    assert point == new_point
    assert new_point.get_public_key() == private.public_key()

    assert point.length() == 65


def test_ec_parameter():
    parameter = ECParameter(ECCurveType.NAMED_CURVE, NamedCurve.SECP256R1)
    assert parameter.encode() == b"\x03\x17"
    assert ECParameter.parse(b"\x03\x17") == parameter
    assert len(parameter) == 2


def test_ecdh_parameter():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()

    parameter = ECDHParameter(ECParameter(), ECPoint(public.x, public.y))
    encoded = parameter.encode()

    new_parameter = ECDHParameter.parse(encoded)
    assert parameter == new_parameter
    assert new_parameter.get_public_key() == private.public_key()
    assert len(parameter) == len(encoded)


def test_server_key_exchange():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()

    parameter = ECDHParameter(ECParameter(), ECPoint(public.x, public.y))
    server_key_exchange = ServerKeyExchange(parameter, Signature(b"\x00"))

    encoded = server_key_exchange.encode()
    new_server_key_exchange = ServerKeyExchange.parse(encoded)

    assert server_key_exchange == new_server_key_exchange


def test_client_key_exchange():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_numbers()

    point = ECPoint(public.x, public.y)
    client_key_exchange = ClientKeyExchange(point)

    encoded = client_key_exchange.encode()
    new_client_key_exchange = ClientKeyExchange.parse(encoded)

    assert client_key_exchange == new_client_key_exchange
    assert new_client_key_exchange.get_public_key() == private.public_key()
