from lib.data.common import *
from time import time
from secrets import randbits
import struct
from lib.util import to_bytes_big, to_int_big


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
    __session_id: int = 0
    __cipher_suites: list[int] = []
    __compression_methods: list[int] = []
    __extensions: int | None = None

    def __init__(self,
                 version: ProtocolVersion,
                 random: Random,
                 session_id: int,
                 cipher_suites: list[int],
                 compression_methods: list[int],
                 extensions=b''
                 ) -> None:
        super().__init__()
        self.__version = version
        self.__random = random

        self.__session_id = session_id

        if not isinstance(cipher_suites, list):
            raise Exception("Cipher suites must be a list")

        self.__cipher_suites = cipher_suites

        if not isinstance(compression_methods, list):
            raise Exception("Compression methods must be a list")

        self.__compression_methods = compression_methods
        self.__extensions = extensions

    def encode(self) -> bytes:
        version = self.__version.encode()
        random = self.__random.encode()

        session_id_length = int(32).to_bytes(1)
        cipher_suites_length = (len(self.__cipher_suites) * 2).to_bytes(2)
        compression_methods_length = len(
            self.__compression_methods).to_bytes(1)

        encoded_session_id = to_bytes_big(self.__session_id, 32)

        encoded_cipher_suite = b""
        for i in self.__cipher_suites:
            encoded_cipher_suite += struct.pack(">H", i)

        encoded_compression = b""
        for i in self.__compression_methods:
            encoded_compression += struct.pack(">B", i)

        return version + random + session_id_length \
            + encoded_session_id + cipher_suites_length \
            + encoded_cipher_suite + compression_methods_length + \
            encoded_compression + self.__extensions

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        version = ProtocolVersion.parse(data[:2])
        random = Random.parse(data[2:34])

        session_id_length = struct.unpack(">B", data[34:35])[0]
        session_id_end = 35 + session_id_length
        session_id = to_int_big(data[35:session_id_end])

        cipher_suites_length = struct.unpack(
            ">H", data[session_id_end:session_id_end+2])[0]
        cipher_suites_end = session_id_end + 2 + cipher_suites_length
        cipher_suites = []

        for i in range(session_id_end+2, cipher_suites_end, 2):
            cipher_suites.append(struct.unpack(">H", data[i:i+2])[0])

        compression_methods_length = struct.unpack(
            ">B", data[cipher_suites_end:cipher_suites_end+1])[0]
        compression_methods_end = cipher_suites_end + 1 + compression_methods_length
        compression_methods = []

        for i in range(cipher_suites_end+1, compression_methods_end):
            compression_methods.append(struct.unpack(">B", data[i:i+1])[0])

        extensions = data[compression_methods_end:]

        return ClientHello(version, random, session_id, cipher_suites, compression_methods, extensions=extensions)

    def __eq__(self, other: 'ClientHello') -> bool:
        return self.__version == other.__version and self.__random == other.__random \
            and self.__session_id == other.__session_id and self.__cipher_suites == other.__cipher_suites \
            and self.__compression_methods == other.__compression_methods and self.__extensions == other.__extensions

    def length(self) -> int:
        return len(self.encode())

    def get_random(self) -> Random:
        return self.__random

    def get_session_id(self) -> int:
        return self.__session_id


class ServerHello(TLSPayload):
    __version: ProtocolVersion = None
    __random: Random = None
    __session_id: int = 0
    __cipher_suite: int = 0
    __compression_method: int = 0
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

        self.__session_id = session_id

        if not isinstance(cipher_suite, int):
            raise Exception("Cipher suites must be an int")

        self.__cipher_suite = cipher_suite

        if not isinstance(compression_method, int):
            raise Exception("Compression methods must be an int")

        self.__compression_method = compression_method
        self.__extensions = extensions

    def encode(self) -> bytes:
        version = self.__version.encode()
        random = self.__random.encode()

        session_id_length = int(32).to_bytes(1)
        encoded_session_id = to_bytes_big(self.__session_id, 32)

        encoded_cipher_suite = struct.pack(">H", self.__cipher_suite)
        encoded_compression = struct.pack(">B", self.__compression_method)

        return version + random + session_id_length \
            + encoded_session_id + encoded_cipher_suite + \
            encoded_compression + self.__extensions

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        version = ProtocolVersion.parse(data[:2])
        random = Random.parse(data[2:34])

        session_id_length = struct.unpack(">B", data[34:35])[0]
        session_id_end = 35 + session_id_length
        session_id = to_int_big(data[35:session_id_end])

        cipher_suites = struct.unpack(
            ">H", data[session_id_end:session_id_end+2])[0]
        compression_methods = struct.unpack(
            ">B", data[session_id_end+2:session_id_end+3])[0]
        extensions = data[session_id_end+3:]

        return ServerHello(version, random, session_id, cipher_suites, compression_methods, extensions=extensions)

    def __eq__(self, other: 'ServerHello') -> bool:
        return self.__version == other.__version and self.__random == other.__random \
            and self.__session_id == other.__session_id and self.__cipher_suite == other.__cipher_suite \
            and self.__compression_method == other.__compression_method and self.__extensions == other.__extensions

    def length(self) -> int:
        return len(self.encode())

    def get_random(self) -> Random:
        return self.__random

    def get_session_id(self) -> int:
        return self.__session_id


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
