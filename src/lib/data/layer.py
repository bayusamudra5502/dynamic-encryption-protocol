from lib.data.common import *


class TLSRecordLayer:
    __version = None
    __content_type = None
    __content = None
    __mac = None
    __content_size = None

    def __init__(self, version: ProtocolVersion, content_type: bytes, content: bytes, mac: bytes, *, content_size=None) -> None:
        self.__version = version
        self.__content_type = content_type
        self.__content = content
        self.__mac = mac

        if content_size is not None:
            self.__content_size = content_size
        else:
            self.__content_size = len(content)

        if len(content) > 2**14 + 2048:
            raise ValueError("content size must be less than 2**14 + 2048")

    def encode(self) -> bytes:
        return self.__content_type + self.__version.encode() + struct.pack(">H", self.__content_size) + self.__content + self.__mac

    def get_mac(self) -> bytes:
        return self.__mac

    def get_content(self) -> bytes:
        return self.__content

    def get_content_type(self) -> bytes:
        return self.__content_type

    def get_version(self) -> ProtocolVersion:
        return self.__version

    def get_content_size(self) -> int:
        return self.__content_size

    def set_content(self, content: bytes) -> None:
        if self.__content_size != len(content):
            raise ValueError("content size must be the same")

        self.__content = content

    def set_mac(self, mac: bytes) -> None:
        self.__mac = mac

    @staticmethod
    def parse(data: bytes) -> 'TLSRecordLayer':
        content_type = data[0:1]
        version = ProtocolVersion.parse(data[1:3])
        content_size = struct.unpack(">H", data[3:5])[0]
        content = data[5:5+content_size]
        mac = data[5+content_size:]

        return TLSRecordLayer(version, content_type, content, mac, content_size=content_size)
