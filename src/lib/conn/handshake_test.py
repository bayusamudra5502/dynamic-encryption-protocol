from lib.conn.memory import MemoryTransport
from lib.conn.socket import SocketClient, SingleSocketServer
from multiprocessing import Process
from lib.conn.handshake import *
from lib.data.common import VERSION_TLS_12
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from uuid import uuid4

import queue
import threading
import datetime
import time

####################################################################################################
# Phase Test
####################################################################################################


def generate_certificate_and_key():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "sample.local")
    ])
    now = datetime.datetime.fromtimestamp(time.time())

    x509_cert = x509.CertificateBuilder()\
        .subject_name(name) \
        .issuer_name(name) \
        .public_key(public) \
        .serial_number(1000) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(hours=2)) \
        .sign(private, hashes.SHA256())

    return x509_cert, private


def test_client_hello():
    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    client2 = ClientHandshake(VERSION_TLS_12, memory)

    assert client._phase == None

    client.client_hello()
    record = client2._get_handshake()

    assert record.get_type() == HandshakeType.CLIENT_HELLO
    assert record.length() == 77
    assert isinstance(record.get_payload(), ClientHello)
    assert client._phase == 1


def test_server_hello():
    cert, key = generate_certificate_and_key()

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key)

    client.client_hello()
    server.client_hello()

    assert isinstance(server._client_hello, Handshake)
    assert isinstance(server._client_hello.get_payload(), ClientHello)

    server.server_hello()

    record = client._get_handshake()

    # Server Hello Test
    assert record.get_type() == HandshakeType.SERVER_HELLO
    assert record.length() == 74
    assert isinstance(server._server_hello.get_payload(), ServerHello)

    record = client._get_handshake()

    # Server Key Exchange test
    assert record.get_type() == HandshakeType.SERVER_KEY_EXCHANGE
    assert isinstance(
        server._server_key_exchange.get_payload(), ServerKeyExchange)

    key_ex = record.get_payload()
    sign = key_ex.get_signature()
    key.public_key().verify(sign.get_signature(),
                            key_ex.get_params().encode(), ec.ECDSA(hashes.SHA256()))

    record = client._get_handshake()

    assert record.get_type() == HandshakeType.CERTIFICATE
    assert isinstance(server._server_certificate.get_payload(), TLSCertificate)

    cert_recv: TLSCertificate = record.get_payload()
    assert cert_recv.get_certificates() == [cert]

    record = client._get_handshake()

    assert record.get_type() == HandshakeType.SERVER_HELLO_DONE
    assert isinstance(server._server_hello_done.get_payload(), ServerHelloDone)


def test_client_server_hello_exchange():
    cert, key = generate_certificate_and_key()

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key)

    client.client_hello()
    server.client_hello()
    server.server_hello()
    client.server_hello()

    assert isinstance(client._client_hello.get_payload(), ClientHello)
    assert isinstance(client._server_hello.get_payload(), ServerHello)
    assert isinstance(
        client._server_key_exchange.get_payload(), ServerKeyExchange)
    assert isinstance(client._server_hello_done.get_payload(), ServerHelloDone)
    assert client._phase == ClientHandshake.Phase.KEY_EXCHANGE


def test_client_server_hello_with_bad_cert():
    cert, key = generate_certificate_and_key()
    _, key_bad = generate_certificate_and_key()

    assert key != key_bad

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key_bad)

    client.client_hello()
    server.client_hello()
    server.server_hello()
    client.server_hello()

    assert client._phase == ClientHandshake.Phase.FAILED

    is_exception = False
    try:
        client.run()
    except Exception:
        is_exception = True

    if not is_exception:
        raise Exception("Should throw an exception")


def test_client_key_exchange():
    cert, key = generate_certificate_and_key()

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key)

    client.client_hello()
    server.client_hello()
    server.server_hello()
    client.server_hello()
    client.key_exchange()

    record = server._get_handshake()
    assert isinstance(record.get_payload(), ClientKeyExchange)

    record = server._get_handshake()
    assert isinstance(record, ChangeCipherSpec)

    record = server._get_handshake()
    assert isinstance(record.get_payload(), Finished)

    assert not client._master_secret is None
    finished_payload: Finished = record.get_payload()

    digest = finished_payload.get_verify_data()
    handshake_msg = [
        client._client_hello,
        client._server_hello,
        client._server_key_exchange,
        client._server_certificate,
        client._server_hello_done,
        client._client_key_exchange
    ]

    msg = b""
    for i in handshake_msg:
        msg += TLSRecordLayer(VERSION_TLS_12,
                              ContentType.HANDSHAKE, i).encode()

    calc = generate_finished_payload(
        client._master_secret,
        msg,
        True
    )

    assert compare_digest(calc, digest)


def test_server_finished():
    cert, key = generate_certificate_and_key()

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key)

    client.client_hello()
    server.client_hello()
    server.server_hello()
    client.server_hello()
    client.key_exchange()

    assert client._client_hello == server._client_hello
    assert client._server_hello == client._server_hello

    server.key_exchange()

    assert not server._master_secret is None
    assert server._master_secret == client._master_secret

    server.finished()

    record = client._get_handshake()
    assert isinstance(record, ChangeCipherSpec)

    record = client._get_handshake()
    assert isinstance(record.get_payload(), Finished)


def test_client_finished():
    cert, key = generate_certificate_and_key()

    memory = MemoryTransport()
    client = ClientHandshake(VERSION_TLS_12, memory)
    server = ServerHandshake(VERSION_TLS_12, memory, [cert], key)

    client.client_hello()
    server.client_hello()
    server.server_hello()
    client.server_hello()
    client.key_exchange()
    server.key_exchange()
    server.finished()
    client.finished()

    client_app_rec = client.get_tls_application_record()
    server_app_rec = server.get_tls_application_record()

    enc = client_app_rec.pack(b"Hello")
    dec = server_app_rec.unpack(enc)

    assert dec == b"Hello"

    enc = client_app_rec.pack(b"Haii")
    dec = server_app_rec.unpack(enc)

    assert dec == b"Haii"

    enc = server_app_rec.pack(b"Halo, Dunia")
    dec = client_app_rec.unpack(enc)

    assert dec == b"Halo, Dunia"

####################################################################################################
# Integration Test
####################################################################################################


def test_handshake_integration():
    cert, key = generate_certificate_and_key()

    socket_path = "/tmp/"+uuid4().hex
    server_res = queue.Queue()
    client_res = None

    semaphore = threading.Semaphore(0)

    def handler(socket, conn, addr):
        server = ServerHandshake(VERSION_TLS_12, socket, [cert], key)
        server.run()

        server_res.put(server.get_tls_application_record())

    def start_server():
        ss = SingleSocketServer(socket_path, handler)
        ss.start(semaphore.release)

    p = threading.Thread(target=start_server)
    p.start()

    semaphore.acquire()

    client = ClientHandshake(VERSION_TLS_12, SocketClient(socket_path))
    client.run()
    client_res = client.get_tls_application_record()
    server_res = server_res.get()

    p.join()

    assert not client_res is None
    assert not server_res is None

    enc = client_res.pack(b"Hello")
    dec = server_res.unpack(enc)

    assert dec == b"Hello"

    enc = server_res.pack(b"Haii")
    dec = client_res.unpack(enc)

    assert dec == b"Haii"
