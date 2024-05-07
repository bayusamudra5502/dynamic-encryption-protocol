from lib.data.common import *
from lib.crypto.aes import MAC_SIZE
from lib.data.text import *
from lib.data.handshake import Handshake
from lib.data.cipherspec import ChangeCipherSpec


class TLSRecordLayer:
    __version = None
    __content_type = None
    __content = None
    __content_size = None

    def __init__(self, version: ProtocolVersion, content_type: bytes, data: TLSPayload, *, content_size=None) -> None:
        self.__version = version
        self.__content_type = content_type

        if content_size is not None:
            self.__content_size = content_size
        else:
            self.__content_size = data.length()

        self.__content = data

        if self.__content_size > 2**14 + 2048:
            raise ValueError("content size must be less than 2**14 + 2048")

    def encode(self) -> bytes:
        return self.__content_type + self.__version.encode() + struct.pack(">H", self.__content_size) + self.__content.encode()

    def get_content(self) -> TLSPayload:
        return self.__content

    def get_payload(self) -> bytes:
        return self.get_content()

    def get_content_type(self) -> bytes:
        return self.__content_type

    def get_version(self) -> ProtocolVersion:
        return self.__version

    def get_content_size(self) -> int:
        return self.__content_size

    def set_content(self, content: TLSPayload) -> None:
        self.__content = content

    @staticmethod
    def parse(data: bytes, *, mac_size=MAC_SIZE, with_data=True) -> 'TLSRecordLayer':
        content_type = data[0:1]
        version = ProtocolVersion.parse(data[1:3])
        content_size = struct.unpack(">H", data[3:5])[0]

        if with_data:
            if content_type == ContentType.APPLICATION_DATA:
                data = TLSCiphertext.parse(data=data[5:], mac_size=mac_size)
                if data.length() != content_size:
                    raise ValueError("content size does not match data size")
            elif content_type == ContentType.HANDSHAKE:
                data = Handshake.parse(data=data[5:])
            elif content_type == ContentType.CHANGE_CIPHER_SPEC:
                data = ChangeCipherSpec.parse(data=data[5:])
            else:
                raise Exception("Unknown content type " + content_type)

            return TLSRecordLayer(version, content_type, data, content_size=content_size)
        else:
            return TLSRecordLayer(version, content_type, None, content_size=content_size)
