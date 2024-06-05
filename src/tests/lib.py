from lib.conn.transport import Transport
from multiprocessing import Process, Queue


from typing import Literal
from lib.conn.tls import TLSRecordLayer

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

import datetime
import time


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


class MITMTLSProxy:
    __recv1_queue: Queue = Queue()
    __recv2_queue: Queue = Queue()
    __send1_queue: Queue = Queue()
    __send2_queue: Queue = Queue()

    def stop(self):
        self.__recv1_queue.close()
        self.__recv2_queue.close()
        self.__send1_queue.close()
        self.__send2_queue.close()

    def start_worker(self, transport: Transport, user_id: Literal[1, 2]):
        p1 = Process(target=self.__recv_tls_worker, args=(transport, user_id))
        p2 = Process(target=self.__send_tls_worker, args=(transport, user_id))

        p1.start()
        p2.start()

        return p1, p2

    def __recv_tls_worker(self, transport: Transport, user_id: Literal[1, 2]):
        while True:
            data = transport.recv(5)
            record = TLSRecordLayer.parse(data, with_data=False)
            raw_data = transport.recv(record.get_content_size())

            if user_id == 1:
                self.__recv1_queue.put(data+raw_data)
            else:
                self.__recv2_queue.put(data+raw_data)

    def __send_tls_worker(self, transport: Transport, user_id: Literal[1, 2]):
        while True:
            record = self.__send1_queue.get() if user_id == 1 else self.__send2_queue.get()

            print(record, user_id)
            transport.send(record)

    def continue_fragment(self, from_user: Literal[1, 2], to_user: Literal[1, 2]):
        record = self.__recv1_queue.get() if from_user == 1 else self.__recv2_queue.get()

        if to_user == 1:
            self.__send1_queue.put(record)
        else:
            self.__send2_queue.put(record)

    def get_intercepted_tls_fragment(self, user_id: Literal[1, 2]):
        bytes_data = self.__recv1_queue.get() if user_id == 1 else self.__recv2_queue.get()
        return TLSRecordLayer.parse(bytes_data)

    def send_fragment(self, to_user: Literal[1, 2], fragment: bytes):
        if to_user == 1:
            self.__send1_queue.put(fragment)
        else:
            self.__send2_queue.put(fragment)
