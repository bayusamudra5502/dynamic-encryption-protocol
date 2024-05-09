from lib.data.common import *
from time import time
from secrets import randbits
import struct
from lib.util import to_bytes_big


class Random(TLSPayload):
    __time = None
    __random_bytes = None

    def __init__(self, current_time: int = None, random_bytes: bytes = None) -> None:
        if current_time is None:
            current_time = int(time())

        if random_bytes is None:
            random_bytes = bytes([randbits(8) for _ in range(28)])

        self.__time = current_time
        self.__random_bytes = random_bytes

    def encode(self) -> bytes:
        time = struct.pack(">I", self.__time)
        random = self.__random_bytes

        return time + random

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        time = struct.unpack(">I", data[:4])[0]
        random_bytes = data[4:]

        return Random(time, random_bytes)

    def __eq__(self, other: 'Random') -> bool:
        return self.__time == other.__time and self.__random_bytes == other.__random_bytes

    def length(self) -> int:
        return 4+28

    def get_time(self) -> int:
        return self.__time

    def get_bytes(self) -> bytes:
        return self.__random_bytes


class ClientHello(TLSPayload):
    __version: ProtocolVersion = None
    __random: Random = None
    __session_ids: int = 0
    __cipher_suites: list[int] = []
    __compression_methods: list[int] = []
    __extensions: int | None = None

    def __init__(self,
                 version: ProtocolVersion,
                 random: Random,
                 session_id: int,
                 cipher_suite: int,
                 compression_method: int,
                 extensions=b''
                 ) -> None:
        super().__init__()
        self.__version = version
        self.__random = random

        self.__session_ids = session_id

        self.__cipher_suites = [cipher_suite]
        self.__compression_methods = [compression_method]
        self.__extensions = extensions

    def encode(self) -> bytes:
        version = self.__version.encode()
        random = self.__random.encode()

        session_id_length = int(32).to_bytes(1)
        cipher_suites_length = len(self.__cipher_suites).to_bytes(2)
        compression_methods_length = len(
            self.__compression_methods).to_bytes(1)

        encoded_session_id = to_bytes_big(i, 32)

        encoded_cipher_suite = b""
        for i in self.__cipher_suites:
            encoded_cipher_suite += struct.pack(">H", i)

        encoded_compression = b""
        for i in self.__compression_methods:
            encoded_compression += struct.pack(">B",
                                               self.__compression_methods)

        return version + random + session_id_length \
            + encoded_session_id + cipher_suites_length \
            + encoded_cipher_suite + compression_methods_length + \
            encoded_compression + self.__extensions

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        version = ProtocolVersion.parse(data[:2])
        random = Random.parse(data[2:34])

        session_id = struct.unpack(">I", data[34:38])[0]
        cipher_suites = struct.unpack(">H", data[38:40])[0]
        compression_methods = struct.unpack(">B", data[40:41])[0]
        extensions = data[41:]

        return ClientHello(version, random, session_id, cipher_suites, compression_methods, extensions=extensions)

    def __eq__(self, other: 'ClientHello') -> bool:
        return self.__version == other.__version and self.__random == other.__random \
            and self.__session_ids == other.__session_ids and self.__cipher_suites == other.__cipher_suites \
            and self.__compression_methods == other.__compression_methods and self.__extensions == other.__extensions

    def length(self) -> int:
        return len(self.encode())

    def get_random(self) -> Random:
        return self.__random

    def get_session_id(self) -> int:
        return self.__session_id


class ServerHello(ClientHello):
    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        version = ProtocolVersion.parse(data[:2])
        random = Random.parse(data[2:34])
        session_id = struct.unpack(">I", data[34:38])[0]
        cipher_suites = struct.unpack(">H", data[38:40])[0]
        compression_methods = struct.unpack(">B", data[40:41])[0]
        extensions = data[41:]

        return ServerHello(version, random, session_id, cipher_suites, compression_methods, extensions=extensions)


class ServerHelloDone(TLSPayload):
    def encode(self) -> bytes:
        return b''

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        return ServerHelloDone()

    def __eq__(self, other: 'ServerHelloDone') -> bool:
        return other is ServerHelloDone

    def length(self) -> int:
        return 0
