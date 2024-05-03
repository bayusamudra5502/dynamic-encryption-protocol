from abc import ABC, abstractmethod
from lib.conn.tlsrecord import TLSApplicationRecordHandler
from lib.conn.transport import Transport
from lib.data.hello import *
from lib.data.layer import TLSRecordLayer
from lib.data.crypto import *
from lib.data.exchange import *


class TLSHandshake(ABC):
    _transport: Transport = None
    _version: ProtocolVersion = None

    def __init__(self, version: ProtocolVersion, transport: Transport) -> None:
        self._transport = transport
        self._version = version

    @abstractmethod
    def get_tls_application_record(self) -> TLSApplicationRecordHandler:
        pass

    @abstractmethod
    def run(self) -> None:
        pass


class ClientHandshake(TLSHandshake):
    class Phase:
        CLIENT_HELLO = 0
        SERVER_HELLO = 1
        KEY_EXCHANGE = 2
        FINISHED = 3

    def run(self) -> None:
        self.__phase = ClientHandshake.Phase.CLIENT_HELLO

        while self.__phase != ClientHandshake.Phase.FINISHED:
            if self.__phase == ClientHandshake.Phase.CLIENT_HELLO:
                self.client_hello()

    def client_hello(self) -> None:
        data = TLSRecordLayer(
            self._version,
            ContentType.HANDSHAKE,

            ClientHello(
                self._version,
                Random(),
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CHAOS_SHA256,
                CompressionMethod.NULL,
            )
        )
        self._transport.send(data.encode())
        self.__phase = ClientHandshake.Phase.SERVER_HELLO

    def server_hello(self) -> None:
        pass


class ServerHandshake(TLSHandshake):
    def run(self) -> None:
        pass
