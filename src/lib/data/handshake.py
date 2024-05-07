from lib.data.common import TLSPayload


class HandshakeType:
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    SERVER_HELLO_DONE = 14
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20


class Handshake(TLSPayload):
    __type: int
    __length: int
    __payload: TLSPayload

    def __init__(self, handshake_type: int, payload: TLSPayload, *, length=None) -> None:
        self.__type = handshake_type
        self.__payload = payload

        if length is None:
            self.__length = payload.length()
        else:
            self.__length = length

    def encode(self) -> bytes:
        return self.__type.to_bytes(1, "big") + self.__length.to_bytes(3, "big") + self.__payload.encode()

    @staticmethod
    def parse(data: bytes, *, header_only=False) -> 'Handshake':
        handshake_type = int(data[0])
        length = int.from_bytes(data[1:4], "big")
        payload = data[4:]

        if header_only:
            return Handshake(handshake_type, None, length=length)

        if handshake_type == HandshakeType.CLIENT_HELLO:
            from lib.data.hello import ClientHello
            return Handshake(handshake_type, ClientHello.parse(payload), length=length)
        elif handshake_type == HandshakeType.SERVER_HELLO:
            from lib.data.hello import ServerHello
            return Handshake(handshake_type, ServerHello.parse(payload), length=length)
        elif handshake_type == HandshakeType.CERTIFICATE:
            from lib.data.certificate import TLSCertificate
            return Handshake(handshake_type, TLSCertificate.parse(payload), length=length)
        elif handshake_type == HandshakeType.SERVER_KEY_EXCHANGE:
            from lib.data.exchange import ServerKeyExchange
            return Handshake(handshake_type, ServerKeyExchange.parse(payload), length=length)
        elif handshake_type == HandshakeType.SERVER_HELLO_DONE:
            from lib.data.hello import ServerHelloDone
            return Handshake(handshake_type, ServerHelloDone.parse(payload), length=length)
        elif handshake_type == HandshakeType.CLIENT_KEY_EXCHANGE:
            from lib.data.exchange import ClientKeyExchange
            return Handshake(handshake_type, ClientKeyExchange.parse(payload), length=length)
        elif handshake_type == HandshakeType.FINISHED:
            from lib.data.finish import Finished
            return Handshake(handshake_type, Finished.parse(payload), length=length)
        else:
            raise Exception("Unknown type " + handshake_type)

    def __eq__(self, other: 'Handshake') -> bool:
        return self.__type == other.__type and self.__length == other.__length and self.__payload == other.__payload

    def length(self) -> int:
        return 4 + self.__length

    def get_payload(self) -> TLSPayload:
        return self.__payload

    def get_type(self):
        return self.__type
