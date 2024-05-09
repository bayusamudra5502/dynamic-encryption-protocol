from lib.crypto.csprng import *
from lib.crypto.aes import *
from lib.util import *
from lib.conn.tcp import *
from lib.conn.tls import *
from lib.conn.tlsrecord import *
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import os
import argparse


# Server Chaos
c1 = SineHenonMap(0.67, 0.12)
c2 = SineHenonMap(0.11, 0.17)

# Client Chaos
c3 = SineHenonMap(0.19, 0.23)
c4 = SineHenonMap(0.29, 0.31)

parser = argparse.ArgumentParser(
    prog='main.py',
    description='This is chatbot application using Dynamic Encryption')
parser.add_argument(
    '--mode', '-m', help="Application mode (client or server)", required=True)
parser.add_argument(
    '--address', '-a', help="Bind Address (Server) or Target Address (Client)", required=True)
parser.add_argument(
    '--port', '-p', help="Port to bind or connect", required=True)
parser.add_argument(
    "--cert", "-c", help="Certificate file (Server only)")
parser.add_argument(
    "--key", "-k", help="Private key file (Server only)")

args = vars(parser.parse_args())
print(args)
mode = args['mode']
address = args['address']
port = args['port']

if mode == 'server':
    cert_path = args['cert']
    key_path = args['key']

    if not os.path.exists(cert_path):
        print(f"Certificate file {cert_path} not found")
        exit(1)

    if not os.path.exists(key_path):
        print(f"Private key file {key_path} not found")
        exit(1)

    with open(cert_path, 'rb') as f:
        cert = load_pem_x509_certificate(f.read())

    with open(key_path, 'rb') as f:
        key = load_pem_private_key(f.read(), password=None)


def receive(conn: TLSConnection):
    size = conn.recv(8)
    length = struct.unpack("<Q", size)[0]

    data = conn.recv(length)

    return data


def send(conn: TLSConnection, data: bytes):
    length = len(data)
    payload = struct.pack("<Q", length) + data

    conn.send(payload)


def server(listen_addr: str, port: int):
    assert cert is not None
    assert key is not None

    def handler(transport: Transport, _: socket.socket, addr: tuple):
        print(f"Connection from {addr}")
        conn = TLSConnection(transport, is_server=True,
                             certificates=[cert], private_key=key)
        print(f"Session id: {conn.get_session_id()}")

        while True:
            data = receive(conn)

            print(f"Received: {data}")
            send(conn, b"From server: " + data)

    tcp = TCPServer(listen_addr, port, handler)

    print("Server listened at {}:{}".format(listen_addr, port))
    tcp.start()


def client(target_addr: str, port: int):
    transport = TCPClient(target_addr, port)
    conn = TLSConnection(transport)

    print(f"Session id: {conn.get_session_id()}")

    while True:
        data = input("Send: ")
        send(conn, data.encode())
        data = receive(conn)
        print(f"Received: {data}")


if mode == 'server':
    server(address, int(port))
else:
    client(address, int(port))
