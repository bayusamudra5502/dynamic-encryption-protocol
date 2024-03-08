import socket


class TCPServer:
    def __init__(self, listen_address, port, handler) -> None:
        self.__host = listen_address
        self.__port = port
        self.__handler = handler

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.__host, self.__port))
            s.listen()
            while True:
                try:
                    conn, addr = s.accept()
                    with conn:
                        print(f"Connected by {addr}")
                        while True:
                            data = conn.recv(1024)

                            if not data:
                                break

                            conn.sendall(self.__handler(data))
                except Exception as err:
                    print(f"Error: {err}")


class TCPClient:
    def __init__(self, host_address, port) -> None:
        self.__host = host_address
        self.__port = port

    def send(self, data: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.__host, self.__port))
            s.sendall(data)
            return s.recv(1024)
