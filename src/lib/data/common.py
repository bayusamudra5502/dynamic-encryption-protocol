import struct
import abc


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
        return ProtocolVersion(int(data[0]), int(data[1]))

    def __eq__(self, other: 'ProtocolVersion') -> bool:
        return self.__major == other.__major and self.__minor == other.__minor


class ContentType:
    CHANGE_CIPHER_SPEC = struct.pack("B", 20)
    ALERT = struct.pack("B", 21)
    HANDSHAKE = struct.pack("B", 22)
    APPLICATION_DATA = struct.pack("B", 23)


class TLSPayload(abc.ABC):
    @abc.abstractmethod
    def encode(self) -> bytes:
        pass

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        pass

    @abc.abstractmethod
    def __eq__(self, other: 'TLSPayload') -> bool:
        pass

    @abc.abstractmethod
    def length(self) -> int:
        pass

    def __len__(self) -> int:
        return self.length()
