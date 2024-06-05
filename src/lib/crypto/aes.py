from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from lib.util import *
from lib.crypto.csprng import CSPRNG
from Crypto.Util.Padding import pad, unpad
from lib.exception.CipherException import CipherException
from abc import ABC, abstractmethod
from secrets import compare_digest

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
    _next_chaos: CSPRNG
    _current_key: bytes

    def __init__(self, chaos=None) -> None:
        if not chaos is None:
            self._current_key, self._next_chaos = self._generate_bytes(chaos)

    def _generate_bytes(self, chaos: CSPRNG, *, length=32) -> tuple[bytes, CSPRNG]:
        new_chaos = chaos.copy()
        key = bytearray()

        for _ in range(length//4):
            result = to_linear(new_chaos.get_value(), size=4 * 8)
            subkey = to_bytes_big(result, 4)
            key.extend(subkey)

            new_chaos = new_chaos.next()

        return bytes(key), new_chaos

    def _get_current_key(self) -> bytes:
        return self._current_key

    def rotate(self):
        self._current_key, self._next_chaos = self._generate_bytes(
            self._next_chaos)

    def _get_state(self):
        return self._current_key, self._next_chaos

    def _copy(self):
        result = DynamicState()
        result._current_key = self._current_key
        result._next_chaos = self._next_chaos

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

        start_state, start_next_chaos = self._get_state()
        start_ctr = self.__ctr

        try:
            for i in range(0, len(data), self.__block_size):

                key = self._get_current_key()
                self.rotate()

                ctr = self.__calculate_ctr()

                plaintext = data[i:i+self.__block_size]

                aes = AES.new(key, AES.MODE_ECB)
                stream_key = aes.encrypt(ctr)

                res = xor(plaintext, stream_key)
                cipertext.extend(res)
        except Exception as e:
            # Rollback
            self._current_key = start_state
            self._next_chaos = start_next_chaos
            self.__ctr = start_ctr
            raise e

        return bytes(cipertext)

    def decrypt(self, data: bytes):
        plaintext = []

        start_state, start_next_chaos = self._get_state()
        start_ctr = self.__ctr

        try:
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
        except Exception as e:
            # Rollback
            self._current_key = start_state
            self._next_chaos = start_next_chaos
            self.__ctr = start_ctr
            raise e

        return unpad(bytes(plaintext), 16)


class DynamicAESCBC(DynamicState, Cipher):
    __block_size: bytes
    __last_block: CSPRNG

    def __init__(self, chaos, iv: bytes, *, block_size: int = 16) -> None:
        super().__init__(chaos)

        if block_size % 16 != 0:
            raise Exception("block size must be multiply of 16")

        self.__block_size = block_size
        self.__last_block = iv

    def encrypt(self, data: bytes):
        data = pad(data, 16)
        cipertext = bytearray()

        start_state, start_next_chaos = self._get_state()
        start_iv = self.__last_block

        try:
            for i in range(0, len(data), self.__block_size):
                key = self._get_current_key()
                self.rotate()

                plaintext = data[i:i+self.__block_size]

                aes = AES.new(key, AES.MODE_ECB)
                xored_pt = xor(plaintext, self.__last_block)

                encrypted = aes.encrypt(xored_pt)
                cipertext.extend(encrypted)
                self.__last_block = encrypted
        except Exception as e:
            # Rollback
            self._current_key = start_state
            self._next_chaos = start_next_chaos
            self.__last_block = start_iv
            raise e

        return bytes(cipertext)

    def decrypt(self, data: bytes):
        plaintext = []

        start_state, start_next_chaos = self._get_state()
        start_iv = self.__last_block

        try:
            for i in range(0, len(data), self.__block_size):
                key = self._get_current_key()
                self.rotate()

                block_data = data[i:i+self.__block_size]
                ciphertext = block_data

                aes = AES.new(key, AES.MODE_ECB)
                decrypted = aes.decrypt(ciphertext)

                res = xor(decrypted, self.__last_block)
                self.__last_block = block_data

                plaintext.extend(res)
        except Exception as e:
            # Rollback
            self._current_key = start_state
            self._next_chaos = start_next_chaos
            self.__last_block = start_iv
            raise e

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
        if not compare_digest(mac, self.__generate(data)):
            raise CipherException("MAC verification failed")

        return True


class TLSHMAC(MAC):
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise CipherException("Key must be bytes")

        self.__key = key

    def generate(self, data: bytes) -> bytes:
        hmac = HMAC.new(self.__key, data, digestmod=SHA256)
        return hmac.digest()

    def verify(self, data: bytes, mac: bytes) -> bool:
        result = self.generate(data)

        if not compare_digest(result, mac):
            raise CipherException("MAC verification failed")

        return True

    def rotate(self):
        # Backward compatibility
        pass

    def __eq__(self, value: object) -> bool:
        return compare_digest(self.__key, value.__key)
