from chaos import *
from aes import *
from util import *
from aes_chaos import *
from tcp import *

import argparse

chaos = HenonMap(1.00, 2.00, 3.00)
iv = b'abcdefghijklmnop'
system = AESChaos(chaos, iv, True)

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


def data(data: bytes) -> bytes:
    data = system.decrypt(data)
    print(f"Received: {data}")

    return system.encrypt(b"from server: " + data)


if mode == 'server':
    tcp = TCPServer(address, int(port), data)
    tcp.start()
else:
    while True:
        message = input("> ")
        client = TCPClient(address, int(port))
        data = client.send(system.encrypt(message.encode()))
        print(f"Received: {system.decrypt(data)}")
