from lib.enc.chaos import *
from lib.enc.aes import *
from lib.util import *


class AESChaos:
    def __init__(self, chaos: HenonMap, iv: bytes, auth=True):
        self.__chaos = chaos
        self.__iv = iv
        if auth:
            self.__daes = DynamicAESWithHMAC(
                self.__chaos, iv=self.__iv, rotate_size=128)
        else:
            self.__daes = DynamicAES(
                self.__chaos, iv=self.__iv, rotate_size=128)

    def encrypt(self, data: bytes):
        result = self.__daes.encrypt(data)
        return result

    def decrypt(self, data: bytes):
        result = self.__daes.decrypt(data)
        return result
