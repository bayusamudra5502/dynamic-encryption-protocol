import struct


class ProtocolVersion:
    __major: int
    __minor: int

    def __init__(self, major: int, minor: int) -> None:
        self.__major = major
        self.__minor = minor

    def encode(self) -> bytes:
        return struct.pack("BB", self.__major, self.__minor)

    @staticmethod
    def parse(data: bytes) -> 'ProtocolVersion':
        return ProtocolVersion(data[0], data[1])

    def __eq__(self, other: 'ProtocolVersion') -> bool:
        return self.__major == other.__major and self.__minor == other.__minor


class ContentType:
    CHANGE_CIPHER_SPEC = struct.pack("B", 20)
    ALERT = struct.pack("B", 21)
    HANDSHAKE = struct.pack("B", 22)
    APPLICATION_DATA = struct.pack("B", 23)
