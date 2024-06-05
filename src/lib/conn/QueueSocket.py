from lib.conn.transport import Transport
from multiprocessing import Queue


class QueueSocketTransport(Transport):
    __is_closed: bool = False

    def __init__(self):
        self.__queue = Queue()

    def send(self, data: bytes) -> None:
        for i in data:
            self.__queue.put(i)

    def recv(self, size: int) -> bytes:
        result = b""
        for i in range(size):
            result += (self.__queue.get()).to_bytes(1, "big")
        return result

    def close(self) -> None:
        self.__is_closed = True
        self.__queue.close()

    def buffer_size(self) -> int:
        return self.__queue.qsize()

    def is_closed(self) -> bool:
        return self.__is_closed
