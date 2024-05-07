from lib.data.common import TLSPayload


class Finished(TLSPayload):
    __verify_data = None

    def __init__(self, verify_data: bytes) -> None:
        self.__verify_data = verify_data

    def encode(self) -> bytes:
        return self.__verify_data

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        return Finished(data)

    def __eq__(self, other: 'Finished') -> bool:
        return self.__verify_data == other.__verify_data

    def length(self) -> int:
        return len(self.__verify_data)

    def get_verify_data(self):
        return self.__verify_data
