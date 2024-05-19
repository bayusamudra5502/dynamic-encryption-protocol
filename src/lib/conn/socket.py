import socket
import os
from lib.conn.transport import Transport
from lib.log import Log


class SingleSocketServer:
    def __init__(self, path,  handler) -> None:
        self.__path = path
        self.__handler = handler

    def start(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(self.__path)
            s.listen()

            try:
                conn, addr = s.accept()
                self.__handler(Socket(conn), conn, addr)
            except Exception as err:
                Log.error(err)


class Socket(Transport):
    def __init__(self, socket: socket.socket) -> None:
        self.__socket = socket

    def send(self, data: bytes) -> None:
        self.__socket.sendall(data)

    def recv(self, size: int) -> bytes:
        return self.__socket.recv(size)

    def close(self) -> None:
        self.__socket.close()


class SocketClient(Socket):
    def __init__(self, path: str) -> None:
        __socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        __socket.connect(path)

        super().__init__(__socket)
