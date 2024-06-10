from lib.crypto.csprng import *
from lib.crypto.aes import *
from lib.util import *
from lib.conn.tcp import *
from lib.conn.tls import *
from lib.conn.tlsrecord import *
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import os.path as path
from pathlib import Path


import os
import argparse


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
    "--cert", "-c", help="Certificate file", required=True)
parser.add_argument(
    "--key", "-k", help="Private key file (Server only)")
parser.add_argument(
    "--folder", "-f", help="Folder to store received files", default=".")


args = vars(parser.parse_args())
print(args)
mode = args['mode']
address = args['address']
port = args['port']
folder = args['folder']

if mode == 'server':
    key_path = args['key']

    if not os.path.exists(key_path):
        print(f"Private key file {key_path} not found")
        exit(1)

    cert_path = args['cert']
    if not os.path.exists(cert_path):
        print(f"Certificate file {cert_path} not found")
        exit(1)

    with open(cert_path, 'rb') as f:
        cert = load_pem_x509_certificate(f.read())

    with open(key_path, 'rb') as f:
        key = load_pem_private_key(f.read(), password=None)


def receive(conn: TLSConnection):
    size = conn.recv(8)
    length = struct.unpack("<Q", size)[0]
    Log.debug(f"Length: {length}")

    data_raw = conn.recv(length + 1)
    data = data_raw[1:]
    type = data_raw[0]

    return (type, data)


def send(conn: TLSConnection, data: bytes, type=0):
    length = len(data)
    payload = struct.pack("<Q", length) + struct.pack("<B", type) + data

    conn.send(payload)


def server(listen_addr: str, port: int, folder: str = "."):
    assert cert is not None
    assert key is not None

    def handler(transport: Transport, _: socket.socket, addr: tuple):
        try:
            print(f"Connection from {addr}")
            conn = TLSConnection(transport, is_server=True,
                                 certificates=[cert], private_key=key)
            print(f"Session id: {conn.get_session_id()}")

            while True:
                type, data = receive(conn)

                if type == 0:
                    Log.info(f"Received Message: {data}")
                    send(conn, b"From server: " + data)
                else:
                    filepath = (data.decode("ascii")).split(" ")[-1]
                    fullpath = path.join(folder, filepath)
                    Log.info(f"Sending File: {filepath}")
                    try:
                        with open(fullpath, 'rb') as f:
                            data = f.read()
                            send(conn, data, type=1)
                    except FileNotFoundError as e:
                        Log.error(f"File not found: {fullpath}")
                        send(conn, b'File not found', type=2)
                    except Exception as e:
                        send(conn, str(e).encode(), type=2)
        except ConnectionResetError:
            print(f"Connection from {addr} closed")
        except ConnectionAbortedError:
            print(f"Connection from {addr} closed")
        except Exception as e:
            raise e

    tcp = TCPServer(listen_addr, port, handler)

    print("Server listened at {}:{}".format(listen_addr, port))
    tcp.start()


def client(target_addr: str, port: int, folder="."):
    cert_path = args['cert']
    if not os.path.exists(cert_path):
        print(f"Certificate file {cert_path} not found")
        exit(1)

    with open(cert_path, 'rb') as f:
        cert = load_pem_x509_certificate(f.read())

    transport = TCPClient(target_addr, port)
    conn = TLSConnection(transport, certificates=[cert])

    print(f"Session id: {conn.get_session_id()}")

    try:
        while True:
            data = input("> ")

            if data.startswith("get "):
                send(conn, data.encode(), type=1)
                type, res = receive(conn)

                if type == 1:
                    print(f"Received File: {data}")

                    parent = Path(folder, data).parent.absolute()
                    os.makedirs(parent, exist_ok=True)

                    with open(path.join(folder, data.split()[1]), 'wb') as f:
                        f.write(res)
                else:
                    print(f"Error retrieve file {data.split()[1]}: {res}")
            else:
                send(conn, data.encode())
                data = receive(conn)
                print(f"Received: {data}")
    except KeyboardInterrupt:
        print("End of conversation")


if mode == 'server':
    server(address, int(port), folder)
else:
    client(address, int(port), folder)
