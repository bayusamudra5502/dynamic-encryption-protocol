from lib.conn.memory import MemoryTransport
from lib.conn.socket import SocketClient, SingleSocketServer
from lib.crypto.csprng import *
from lib.conn.tls import *
from tests.lib import *
from lib.conn.QueueSocket import QueueSocketTransport

from uuid import uuid4

import multiprocessing


def test_tc_2_4():
    cert, key = generate_certificate_and_key()

    s1 = "/tmp/"+uuid4().hex
    s2 = "/tmp/"+uuid4().hex

    semaphore = multiprocessing.Semaphore(0)
    mitm = MITMTLSProxy()

    def server_handler(socket, conn, addr):
        server = TLSConnection(socket, is_server=True,
                               certificates=[cert], private_key=key)
        server.close()

    def start_server():
        ss = SingleSocketServer(s2, server_handler)
        ss.start(semaphore.release)

    ps = multiprocessing.Process(target=start_server)
    ps.start()

    semaphore.acquire()
    mitm_2_p1, mitm_2_p2 = mitm.start_worker(SocketClient(s2), 2)

    shutdown_queue = multiprocessing.Queue()

    def callback(socket, conn, addr):
        p1, p2 = mitm.start_worker(socket, 1)
        shutdown_queue.get()

        p1.terminate()
        p2.terminate()

    def start_mitm_server():
        ss = SingleSocketServer(s1, callback)
        ss.start(semaphore.release)

    pmitm = multiprocessing.Process(target=start_mitm_server)
    pmitm.start()

    semaphore.acquire()

    def mitm_controller(mitm: MITMTLSProxy):
        try:
            mitm.continue_fragment(1, 2)
            mitm.continue_fragment(2, 1)
            data = mitm.get_intercepted_tls_fragment(2)
            server_kex: ServerKeyExchange = data.get_content().get_payload()
            new_kex = ServerKeyExchange(
                ECDHParameter(
                    server_kex.get_params().get_curve_params(),
                    ECPoint(
                        server_kex.get_params().get_public().get_x(),
                        -server_kex.get_params().get_public().get_y()
                    )
                ), server_kex.get_signature()
            )
            data.set_content(Handshake(
                HandshakeType.SERVER_KEY_EXCHANGE, new_kex
            ))
            mitm.send_fragment(1, data.encode())
            mitm.continue_fragment(2, 1)
            mitm.continue_fragment(2, 1)
        finally:
            mitm.stop()

    pmitm_controller = multiprocessing.Process(
        target=mitm_controller, args=(mitm,))
    pmitm_controller.start()

    try:
        TLSConnection(SocketClient(s1), is_server=False,
                      certificates=[cert], private_key=key)
        assert False
    except Exception as e:
        pass

    data = mitm.get_intercepted_tls_fragment(1)
    assert data.get_content_type() == ContentType.ALERT

    alert = data.get_content()
    assert alert.get_alert_description() == AlertDescription.HANDSHAKE_FAILURE

    mitm.send_fragment(2, data.encode())

    shutdown_queue.put(1)
    pmitm.join()

    mitm_2_p1.kill()
    mitm_2_p2.kill()
    ps.kill()
    mitm.stop()

    pmitm_controller.join()
