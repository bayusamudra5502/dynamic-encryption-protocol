from lib.conn.transport import Transport
from lib.conn.tlsrecord import TLSApplicationRecordHandler
from lib.exception.CipherException import CipherException
from lib.enc.aes import MAC_SIZE
from lib.data.text import TLSCiphertext


class ConnectionState:
    HANDSHAKE = 0
    ESTABLISHED = 1


TLS_DEBUG = False


class TLSConnection:
    __transport: Transport = None
    __tls_handler: TLSApplicationRecordHandler = None

    def __init__(self, transport: Transport, *, tls_handler: TLSApplicationRecordHandler = None, is_server=False) -> None:
        self.__transport = transport

        if tls_handler is None:
            self.__state = ConnectionState.HANDSHAKE
            self.handshake(is_server)
        else:
            __state: ConnectionState = ConnectionState.ESTABLISHED
            self.__tls_handler = tls_handler

    def get_state(self) -> ConnectionState:
        return self.__state

    def handshake(self, is_server) -> None:
        # TODO
        pass

    def send(self, data: bytes) -> None:
        length = len(data)

        while length > 0:
            chunk_size = min(length, 2**14)
            chunk = data[:chunk_size]
            data = data[chunk_size:]

            record = self.__tls_handler.pack(chunk)
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
                if TLS_DEBUG:
                    print(f"Waited size: {__waited_size}")
                # Get the header first
                header_bytes = self.__transport.recv(5)
                parsed_header = self.__tls_handler.parse(
                    header_bytes, with_data=False
                )

                payload_size = parsed_header.get_content_size()
                payload_bytes = self.__transport.recv(payload_size)

                payload = parsed_header
                payload.set_content(TLSCiphertext.parse(payload_bytes))

                received = self.__tls_handler.unpack(payload)

                data += received
                __waited_size -= len(received)
            except CipherException as err:
                print(f"Error: {err}")
                continue

        self.__buffered_data = data[size:]
        return data[:size]
