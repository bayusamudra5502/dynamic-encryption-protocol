from lib.enc.chaos import *
from lib.enc.aes import *
from lib.util import *
from lib.enc.aes_chaos import *
from lib.conn.tcp import *
from lib.conn.tls import *
from lib.conn.tlsrecord import *

import argparse

# Server Chaos
c1 = HenonMap(0.67, 0.12, 0.86)
c2 = HenonMap(0.11, 0.17, 0.91)

# Client Chaos
c3 = HenonMap(0.19, 0.23, 0.97)
c4 = HenonMap(0.29, 0.31, 0.37)

parser = argparse.ArgumentParser(
    prog='main.py',
    description='This is chatbot application using Dynamic Encryption')
parser.add_argument(
    '--mode', '-m', help="Application mode (client or server)", required=True)
parser.add_argument(
    '--address', '-a', help="Bind Address (Server) or Target Address (Client)", required=True)
parser.add_argument(
    '--port', '-p', help="Port to bind or connect", required=True)

args = vars(parser.parse_args())
print(args)
mode = args['mode']
address = args['address']
port = args['port']


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
    def handler(transport: Transport, conn: socket.socket, addr: tuple):
        print(f"Connection from {addr}")
        conn = TLSConnection(transport, tls_handler=TLSRecordHandler(
            ProtocolVersion(2, 0), c1, c3, c2, c4
        ))

        while True:
            data = receive(conn)

            print(f"Received: {data}")
            send(conn, b"From server: " + data)

    tcp = TCPServer(listen_addr, port, handler)

    print("Server listened at {}:{}".format(listen_addr, port))
    tcp.start()


def client(target_addr: str, port: int):
    transport = TCPClient(target_addr, port)
    conn = TLSConnection(transport, tls_handler=TLSRecordHandler(
        ProtocolVersion(2, 0), c3, c1, c4, c2
    ))

    while True:
        data = input("Send: ")
        send(conn, data.encode())
        data = receive(conn)
        print(f"Received: {data}")


if mode == 'server':
    server(address, int(port))
else:
    client(address, int(port))
