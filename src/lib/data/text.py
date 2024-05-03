from lib.data.common import TLSPayload
from lib.crypto.aes import MAC_SIZE


class TLSCiphertext(TLSPayload):
    __data = None
    __mac = None

    def __init__(self, data: bytes, mac: bytes) -> None:
        self.__data = data
        self.__mac = mac

    def encode(self) -> bytes:
        return self.__data + self.__mac

    @staticmethod
    def parse(data: bytes, *, mac_size=MAC_SIZE) -> 'TLSCiphertext':
        if len(data) < mac_size:
            raise ValueError("data size must be greater than mac size")

        content = data[:-mac_size]
        mac = data[-mac_size:]

        return TLSCiphertext(content, mac)

    def __eq__(self, other: 'TLSCiphertext') -> bool:
        return self.__data == other.__data and self.__mac == other.__mac

    def length(self) -> int:
        return len(self.__data) + len(self.__mac)

    def __len__(self) -> int:
        return self.length()

    def mac_length(self) -> int:
        return len(self.__mac)

    def content_length(self) -> int:
        return len(self.__data)

    def get_mac(self) -> bytes:
        return self.__mac

    def get_data(self) -> bytes:
        return self.__data
