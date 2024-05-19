from lib.conn.transport import Transport
from lib.conn.tlsrecord import TLSApplicationRecordHandler
from lib.exception.CipherException import CipherException
from lib.data.text import TLSCiphertext
from lib.conn.handshake import *
from cryptography.x509 import Certificate
from lib.log import Log


class ConnectionState:
    HANDSHAKE = 0
    ESTABLISHED = 1


class TLSConnection:
    __transport: Transport = None
    __tls_app_handler: TLSApplicationRecordHandler = None
    __certificates: list[Certificate] = []
    __private_key: ec.EllipticCurvePrivateKey = None
    __version: ProtocolVersion = None
    __session_id: int = None
    __closed_by_peer: bool = False

    def __init__(self, transport: Transport, *, tls_handler: TLSApplicationRecordHandler = None, is_server=False, certificates: list[Certificate] = [], version=ProtocolVersion(3, 3), private_key: ec.EllipticCurvePrivateKey = None) -> None:
        self.__transport = transport
        self.__certificates = certificates
        self.__version = version
        self.__private_key = private_key

        if tls_handler is None:
            self.__state = ConnectionState.HANDSHAKE
            self.handshake(is_server)
        else:
            self.__state: ConnectionState = ConnectionState.ESTABLISHED
            self.__tls_app_handler = tls_handler

    def __del__(self):
        if not self.__closed_by_peer:
            data = TLSRecordLayer(
                self.__version,
                ContentType.ALERT,
                Alert(
                    alert_type=AlertLevel.FATAL,
                    alert_description=AlertDescription.CLOSE_NOTIFY
                )
            )
            self.__transport.send(data.encode())

        self.__transport.close()

    def get_state(self) -> ConnectionState:
        return self.__state

    def get_session_id(self) -> int:
        return self.__session_id

    def handshake(self, is_server) -> None:
        if not is_server:
            handshake: TLSHandshake = ClientHandshake(
                self.__version, self.__transport)
        else:
            handshake: TLSHandshake = ServerHandshake(
                self.__version, self.__transport, self.__certificates, self.__private_key)

        handshake.run()
        self.__tls_app_handler = handshake.get_tls_application_record()
        self.__state = ConnectionState.ESTABLISHED
        self.__session_id = handshake.get_session_id()

    def send(self, data: bytes) -> None:
        length = len(data)

        while length > 0:
            chunk_size = min(length, 2**14)
            chunk = data[:chunk_size]
            data = data[chunk_size:]

            record = self.__tls_app_handler.pack(chunk)
            self.__transport.send(record.encode())

            length -= chunk_size

    __buffered_data = b""

    def recv(self, size: int) -> bytes:
        __waited_size = size
        data = b""

        if len(self.__buffered_data) > 0:
            data += self.__buffered_data[:size]
            self.__buffered_data = self.__buffered_data[size:]
            __waited_size -= len(data)

        while __waited_size > 0:
            try:
                # Get the header first
                header_bytes = self.__transport.recv(5)
                parsed_header = self.__tls_app_handler.parse(
                    header_bytes, with_data=False
                )

                payload_size = parsed_header.get_content_size()
                payload_bytes = self.__transport.recv(payload_size)

                payload = parsed_header
                Log.debug("Received payload:" + str(payload))

                if payload.get_content_type() == ContentType.ALERT:
                    payload.set_content(Alert.parse(payload_bytes))

                    Log.debug("Alert received:" + str(payload))

                    if payload.get_content().get_alert_description() == AlertDescription.CLOSE_NOTIFY:
                        self.__closed_by_peer = True
                        raise ConnectionResetError(
                            "Connection closed by peer")

                    if payload.get_content().get_alert_type() == AlertLevel.FATAL:
                        self.__closed_by_peer = True
                        raise ConnectionAbortedError(
                            "Connection closed because unexpected error happened")

                    continue

                payload.set_content(TLSCiphertext.parse(payload_bytes))

                received = self.__tls_app_handler.unpack(payload)

                data += received
                __waited_size -= len(received)
            except CipherException as err:
                data = TLSRecordLayer(
                    self.__version,
                    ContentType.ALERT,
                    Alert(
                        alert_type=AlertLevel.WARNING,
                        alert_description=AlertDescription.BAD_RECORD_MAC
                    )
                )
                self.__transport.send(data.encode())
                Log.debug(err)
                continue
            except ConnectionAbortedError as err:
                Log.debug("Aborted " + err)
                raise err
            except ConnectionResetError as err:
                Log.debug(err)
                raise err
            except Exception as err:
                Log.debug(err)
                continue

        self.__buffered_data = data[size:]
        return data[:size]
