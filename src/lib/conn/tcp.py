import socket
import multiprocessing as mp
from lib.conn.transport import Transport


class TCPServer:
    def __init__(self, listen_address, port, handler) -> None:
        self.__host = listen_address
        self.__port = port
        self.__handler = handler
        self.__process = []
        self.__process_lock = mp.Lock()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.__host, self.__port))
            s.listen()

            try:
                while True:
                    try:
                        conn, addr = s.accept()

                        process = mp.Process(
                            target=self.__handler, args=(TCP(conn), conn, addr))

                        with self.__process_lock:
                            self.__process.append(process)
                            process.start()

                    except Exception as err:
                        print(f"Error: {err}")
            finally:
                for i in self.__process:
                    i.join()
                s.close()


class TCP(Transport):
    def __init__(self, socket: socket.socket) -> None:
        self.__socket = socket

    def send(self, data: bytes) -> bytes:
        self.__socket.sendall(data)

    def recv(self, size: int) -> bytes:
        return self.__socket.recv(size)


class TCPClient(TCP):
    def __init__(self, host_address: str, port: int) -> None:
        __host = host_address
        __port = port
        __socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        __socket.connect((__host, __port))

        super().__init__(__socket)
