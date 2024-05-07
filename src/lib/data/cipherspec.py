from lib.data.common import TLSPayload


class ChangeCipherSpec(TLSPayload):
    def encode(self) -> bytes:
        return b'\x01'

    def parse(data: bytes) -> 'TLSPayload':
        if data != b'\x01':
            raise ValueError("Invalid ChangeCipherSpec message")

        return ChangeCipherSpec()

    def __eq__(self, other: 'TLSPayload') -> bool:
        return isinstance(other, ChangeCipherSpec)

    def length(self) -> int:
        return 1
