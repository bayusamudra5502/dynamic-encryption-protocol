import socket
import multiprocessing as mp


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
                            target=self.__handler, args=(conn, addr))

                        with self.__process_lock:
                            self.__process.append(process)
                            process.start()

                    except Exception as err:
                        print(f"Error: {err}")
            finally:
                for i in self.__process:
                    i.join()
                s.close()


class TCPClient:
    def __init__(self, host_address, port) -> None:
        self.__host = host_address
        self.__port = port
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect((self.__host, self.__port))

    def send(self, data: bytes) -> bytes:
        self.__socket.sendall(data)

    def recv(self, size: int) -> bytes:
        return self.__socket.recv(size)
