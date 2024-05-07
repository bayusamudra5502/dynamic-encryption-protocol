from lib.conn.transport import Transport


class MemoryTransport(Transport):
    def __init__(self):
        self.__data = b""

    def send(self, data: bytes) -> None:
        self.__data += data

    def recv(self, size: int) -> bytes:
        data = self.__data[:size]
        self.__data = self.__data[size:]
        return data

    def buffer_size(self) -> int:
        return len(self.__data)
