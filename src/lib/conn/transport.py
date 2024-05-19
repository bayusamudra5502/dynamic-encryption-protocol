from abc import ABC, abstractmethod


class Transport(ABC):
    @abstractmethod
    def send(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def recv(self, size: int) -> bytes:
        pass

    @abstractmethod
    def close(self) -> None:
        pass
