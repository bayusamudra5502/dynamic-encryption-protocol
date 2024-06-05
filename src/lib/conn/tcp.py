import socket
import multiprocessing as mp
from lib.conn.transport import Transport
from lib.log import Log


class TCPServer:
    def __init__(self, listen_address, port, handler) -> None:
        self.__host = listen_address
        self.__port = port
        self.__handler = handler
        self.__process: list[mp.Process] = []
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
                        Log.error(err)
            except KeyboardInterrupt:
                for i in self.__process:
                    i.kill()
            finally:
                for i in self.__process:
                    i.join()
                s.close()


MAX_SIZE = 1024


class TCP(Transport):
    def __init__(self, socket: socket.socket) -> None:
        self.__socket = socket

    def send(self, data: bytes) -> bytes:
        sent_data = 0

        while sent_data < len(data):
            send_size = min(len(data) - sent_data, MAX_SIZE)
            result = self.__socket.send(
                data[sent_data:sent_data + send_size]
            )

            if result == 0:
                raise RuntimeError("Socket connection broken")

            sent_data += send_size

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


class TCPClient(TCP):
    def __init__(self, host_address: str, port: int) -> None:
        __host = host_address
        __port = port
        __socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        __socket.connect((__host, __port))

        super().__init__(__socket)
