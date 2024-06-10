from lib.conn.memory import MemoryTransport
from lib.conn.socket import SocketClient, SingleSocketServer
from lib.crypto.csprng import *
from lib.conn.tls import *
from tests.lib import *

from uuid import uuid4

import multiprocessing


def test_tc_2_13():
    cert1, key1 = generate_certificate_and_key()
    cert2, _ = generate_certificate_and_key()

    socket_path = "/tmp/"+uuid4().hex
    semaphore = multiprocessing.Semaphore(0)

    def handler(socket, conn, addr):
        server = TLSConnection(socket, is_server=True,
                               certificates=[cert1], private_key=key1)

        server.close()

    def start_server():
        ss = SingleSocketServer(socket_path, handler)
        ss.start(semaphore.release)

    p = multiprocessing.Process(target=start_server)
    p.start()

    semaphore.acquire()

    try:
        TLSConnection(SocketClient(socket_path),
                      certificates=[cert2], is_server=False)
        assert False
    except Exception as e:
        assert e.args[0] == "Handshake failed"

    p.terminate()
