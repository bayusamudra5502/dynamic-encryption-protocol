from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from lib.util import *
from lib.enc.chaos import HenonMap
from Crypto.Util.Padding import pad, unpad
from lib.exception.CipherException import CipherException


class DynamicState:
    __next_chaos: HenonMap
    __current_key: bytes

    def __init__(self, chaos=None) -> None:
        if not chaos is None:
            self.__current_key, self.__next_chaos = self.__calculate_key(chaos)

    def __calculate_key(self, chaos: HenonMap) -> tuple[bytes, HenonMap]:
        keys = bytearray()
        new_chaos = chaos.copy()

        for _ in range(32):
            result = to_linear(new_chaos.get_tuple()[0])
            keys.extend(result.tobytes())
            new_chaos = new_chaos.next()

        return bytes(keys), new_chaos

    def _get_current_key(self) -> bytes:
        return self.__current_key

    def rotate(self):
        self.__current_key, self.__next_chaos = self.__calculate_key(
            self.__next_chaos)

    def _copy(self):
        result = DynamicState()
        result.__current_key = self.__current_key
        result.__next_chaos = self.__next_chaos

        return result


class DynamicAES(DynamicState):
    __block_size: bytes

    def __init__(self) -> None:
        pass

    def __init__(self, chaos, *, block_size: int = 16) -> None:
        super().__init__(chaos)

        if block_size % 16 != 0:
            raise Exception("block size must be multiply of 16")

        self.__block_size = block_size

    def encrypt(self, data: bytes):
        data = pad(data, 16)

        cipertext = bytearray()

        for i in range(0, len(data), self.__block_size):
            key = self._get_current_key()
            self.rotate()

            plaintext = data[i:i+self.__block_size]

            aes = AES.new(key, AES.MODE_ECB)
            res = aes.encrypt(plaintext)

            cipertext.extend(res)

        return bytes(cipertext)

    def decrypt(self, data: bytes):
        plaintext = []

        for i in range(0, len(data), self.__block_size):
            key = self._get_current_key()
            self.rotate()

            block_data = data[i:i+self.__block_size]
            ciphertext = block_data

            aes = AES.new(key, AES.MODE_ECB)
            res = aes.decrypt(ciphertext)

            plaintext.extend(res)

        return unpad(bytes(plaintext), 16)


class DynamicHMAC(DynamicState):
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
