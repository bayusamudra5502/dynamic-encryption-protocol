from lib.data.common import TLSPayload
from lib.crypto.aes import MAC_SIZE


class TLSCiphertext(TLSPayload):
    __data = None

    def __init__(self, data: bytes) -> None:
        self.__data = data

    def encode(self) -> bytes:
        return self.__data

    @staticmethod
    def parse(data: bytes) -> 'TLSCiphertext':
        return TLSCiphertext(data)

    def __eq__(self, other: 'TLSCiphertext') -> bool:
        return self.__data == other.__data

    def length(self) -> int:
        return len(self.__data)

    def __len__(self) -> int:
        return self.length()

    def content_length(self) -> int:
        return len(self.__data)

    def get_data(self) -> bytes:
        return self.__data
