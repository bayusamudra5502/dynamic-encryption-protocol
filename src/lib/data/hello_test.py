from lib.data.hello import *


def test_random():
    client = Random()
    data = client.encode()

    assert len(data) == 4+28
    assert len(client) == len(data)

    parsed = Random.parse(data)
    assert client == parsed


def test_client_hello():
    random = Random()
    client = ClientHello(
        ProtocolVersion(3, 3),
        random,
        455,
        [12, 90],
        [89, 12],
    )

    data = client.encode()
    assert len(data) == 76

    payload = ClientHello.parse(data)

    assert payload == client


def test_server_hello():
    random = Random()
    client = ServerHello(
        ProtocolVersion(3, 3),
        random,
        455,
        0,
        0,
    )

    data = client.encode()
    assert len(data) == 70

    payload = ServerHello.parse(data)

    assert payload == client
