import socket
import os
from lib.conn.transport import Transport
from lib.log import Log


class SingleSocketServer:
    def __init__(self, path,  handler) -> None:
        self.__path = path
        self.__handler = handler

    def start(self, on_started=None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(self.__path)
            s.listen()

            if on_started is not None and callable(on_started):
                on_started()

            try:
                conn, addr = s.accept()
                self.__handler(Socket(conn), conn, addr)
            except Exception as err:
                Log.error(err)


MAX_SIZE = 1024


class Socket(Transport):
    def __init__(self, socket: socket.socket) -> None:
        self.__socket = socket

    def send(self, data: bytes) -> None:
        send_data = 0

        while send_data < len(data):
            send_size = min(len(data) - send_data, MAX_SIZE)
            result = self.__socket.send(data[send_data:send_data + send_size])

            if result == 0:
                raise RuntimeError("Socket connection broken")

            send_data += send_size

    def recv(self, size: int) -> bytes:
        buffer = b""
        buffer_size = 0

        while buffer_size < size:
            recv_size = min(size - buffer_size, MAX_SIZE)
            data = self.__socket.recv(recv_size)

            buffer += data
            buffer_size += len(data)

        return buffer

    def close(self) -> None:
        self.__socket.close()


class SocketClient(Socket):
    def __init__(self, path: str) -> None:
        __socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        __socket.connect(path)

        super().__init__(__socket)
