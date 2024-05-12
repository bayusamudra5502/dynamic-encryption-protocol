from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from lib.util import *
from lib.crypto.csprng import CSPRNG
from Crypto.Util.Padding import pad, unpad
from lib.exception.CipherException import CipherException
from abc import ABC, abstractmethod

MAC_SIZE = 32


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass


class MAC(ABC):
    @abstractmethod
    def generate(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, data: bytes, mac: bytes) -> bool:
        pass


class DynamicState:
    __next_chaos: CSPRNG
    __current_key: bytes

    def __init__(self, chaos=None) -> None:
        if not chaos is None:
            self.__current_key, self.__next_chaos = self._generate_bytes(chaos)

    def _generate_bytes(self, chaos: CSPRNG, *, length=32) -> tuple[bytes, CSPRNG]:
        keys = bytearray()
        new_chaos = chaos.copy()

        for _ in range(length):
            result = to_linear(new_chaos.get_value())
            keys.extend(result.tobytes())
            new_chaos = new_chaos.next()

        return bytes(keys), new_chaos

    def _get_current_key(self) -> bytes:
        return self.__current_key

    def rotate(self):
        self.__current_key, self.__next_chaos = self._generate_bytes(
            self.__next_chaos)

    def _copy(self):
        result = DynamicState()
        result.__current_key = self.__current_key
        result.__next_chaos = self.__next_chaos

        return result

    def __eq__(self: object, other: object) -> bool:
        return self._get_current_key() == other._get_current_key()


class DynamicAES(DynamicState, Cipher):
    __block_size: bytes
    __ctr: CSPRNG

    def __init__(self, chaos, iv: CSPRNG, *, block_size: int = 16) -> None:
        super().__init__(chaos)

        if block_size % 16 != 0:
            raise Exception("block size must be multiply of 16")

        self.__block_size = block_size
        self.__ctr = iv

    def __calculate_ctr(self) -> bytes:
        val, next = self._generate_bytes(self.__ctr, length=self.__block_size)
        self.__ctr = next

        return val

    def encrypt(self, data: bytes):
        data = pad(data, 16)
        cipertext = bytearray()

        for i in range(0, len(data), self.__block_size):
            key = self._get_current_key()
            self.rotate()

            ctr = self.__calculate_ctr()

            plaintext = data[i:i+self.__block_size]

            aes = AES.new(key, AES.MODE_ECB)
            stream_key = aes.encrypt(ctr)

            res = xor(plaintext, stream_key)
            cipertext.extend(res)

        return bytes(cipertext)

    def decrypt(self, data: bytes):
        plaintext = []

        for i in range(0, len(data), self.__block_size):
            key = self._get_current_key()
            self.rotate()

            ctr = self.__calculate_ctr()

            block_data = data[i:i+self.__block_size]
            ciphertext = block_data

            aes = AES.new(key, AES.MODE_ECB)
            stream_key = aes.encrypt(ctr)

            res = xor(ciphertext, stream_key)
            plaintext.extend(res)

        return unpad(bytes(plaintext), 16)


class DynamicHMAC(DynamicState, MAC):
    def __init__(self, chaos) -> None:
        super().__init__(chaos)

    def __generate(self, data: bytes) -> bytes:
        key = self._get_current_key()
        hmac = HMAC.new(key, data, digestmod=SHA256)
        return hmac.digest()

    def generate(self, data: bytes) -> bytes:
        result = self.__generate(data)
        self.rotate()

        return result

    def verify(self, data: bytes, mac: bytes) -> bool:
        if mac != self.__generate(data):
            raise CipherException("MAC verification failed")
        self.rotate()

        return True
