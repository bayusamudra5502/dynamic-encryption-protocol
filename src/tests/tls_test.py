from lib.conn.memory import MemoryTransport
from lib.conn.socket import SocketClient, SingleSocketServer
from lib.crypto.csprng import *
from lib.conn.tls import TLSConnection
from tests.lib import *

import multiprocessing
import threading
import random


def test_tc_2_1():
    cert, key = generate_certificate_and_key()

    socket_path = "/tmp/"+uuid4().hex
    server_queue = Queue()
    semaphore = multiprocessing.Semaphore(0)

    def handler(socket, conn, addr):
        server = TLSConnection(socket, is_server=True,
                               certificates=[cert], private_key=key)

        server_queue.put(server._get_tls_application_handler()._get_params())
        server.close()

    def start_server():
        ss = SingleSocketServer(socket_path, handler)
        ss.start(semaphore.release)

    p = multiprocessing.Process(target=start_server)
    p.start()

    semaphore.acquire()

    client = TLSConnection(SocketClient(socket_path),
                           certificates=[cert], is_server=False)

    p.join()

    try:
        client.recv(1)
    except ConnectionResetError as e:
        pass

    client_params = client._get_tls_application_handler()._get_params()
    server_params = server_queue.get()

    assert server_params[:2] == client_params[:2]
    assert server_params[2] == client_params[3]
    assert server_params[3] == client_params[2]

    assert server_params[4] == client_params[5]
    assert server_params[5] == client_params[4]


def test_tc_2_2():
    cert, key = generate_certificate_and_key()

    socket_path = "/tmp/"+uuid4().hex
    semaphore = multiprocessing.Semaphore(0)
    server_queue = multiprocessing.Queue()

    def handler(socket, conn, addr):
        server = TLSConnection(socket, is_server=True,
                               certificates=[cert], private_key=key)

        for _ in range(5):
            data = server.recv(len(b"Hello, Server!"))
            server_queue.put(data)

        for _ in range(5):
            server.send(b"Hello, Client!")

        server.close()

    def start_server():
        ss = SingleSocketServer(socket_path, handler)
        ss.start(semaphore.release)

    p = multiprocessing.Process(target=start_server)
    p.start()

    semaphore.acquire()

    client = TLSConnection(SocketClient(socket_path),
                           certificates=[cert], is_server=False)

    for _ in range(5):
        client.send(b"Hello, Server!")

    client_queue = Queue()
    for _ in range(5):
        client_queue.put(client.recv(len(b"Hello, Client!")))

    p.join()

    assert client_queue.qsize() == 5
    assert server_queue.qsize() == 5

    for _ in range(5):
        assert client_queue.get() == b"Hello, Client!"
        assert server_queue.get() == b"Hello, Server!"

    try:
        client.recv(1)
    except ConnectionResetError as e:
        pass


def test_tc_2_3():
    cert, key = generate_certificate_and_key()

    socket_path = "/tmp/"+uuid4().hex
    semaphore = multiprocessing.Semaphore(0)

    server_recv_queue = multiprocessing.Queue()
    server_send_queue = multiprocessing.Queue()

    def handler(socket, conn, addr):
        server = TLSConnection(socket, is_server=True,
                               certificates=[cert], private_key=key)

        for _ in range(5):
            data = server.recv(1024)
            server_recv_queue.put(data)

        for _ in range(5):
            data = random.randbytes(1024)
            server.send(data)
            server_send_queue.put(data)

        server.close()

    def start_server():
        ss = SingleSocketServer(socket_path, handler)
        ss.start(semaphore.release)

    p = multiprocessing.Process(target=start_server)
    p.start()

    semaphore.acquire()

    client = TLSConnection(SocketClient(socket_path),
                           certificates=[cert], is_server=False)

    client_send_queue = Queue()
    for _ in range(5):
        data = random.randbytes(1024)
        client.send(data)
        client_send_queue.put(data)

    client_recv_queue = Queue()
    for _ in range(5):
        client_recv_queue.put(client.recv(1024))

    p.join()

    assert client_send_queue.qsize() == 5
    assert client_recv_queue.qsize() == 5

    server_send = [server_send_queue.get() for _ in range(5)]
    server_recv = [server_recv_queue.get() for _ in range(5)]

    client_send = [client_send_queue.get() for _ in range(5)]
    client_recv = [client_recv_queue.get() for _ in range(5)]

    assert server_send == client_recv
    assert server_recv == client_send

    try:
        client.recv(1)
    except ConnectionResetError as e:
        pass
