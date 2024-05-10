from lib.data.common import TLSPayload


class CipherSuite:
    TLS_ECDHE_ECDSA_WITH_AES_256_CHAOS_SHA256 = 0xFF01
    TLS_NULL_WITH_NULL_NULL = 0x0000


class CompressionMethod:
    NULL = 0x00


class HashAlgorithm:
    SHA256 = b"\x04"


class SignatureAlgorithm:
    ANONYMOUS = b"\x00"
    ECDSA = b"\x03"


class Signature(TLSPayload):
    __hash_algorithm = None
    __signature_algorithm = None
    __signature = None

    def __init__(self, signature: bytes, hash_algorithm: bytes = HashAlgorithm.SHA256, signature_algorithm: bytes = SignatureAlgorithm.ECDSA) -> None:
        self.__hash_algorithm = hash_algorithm
        self.__signature_algorithm = signature_algorithm
        self.__signature = signature

    def encode(self) -> bytes:
        return self.__hash_algorithm + self.__signature_algorithm + self.__signature

    @staticmethod
    def parse(data: bytes) -> 'Signature':
        hash_algorithm = data[0:1]
        signature_algorithm = data[1:2]
        signature = bytes(data[2:])

        return Signature(signature, hash_algorithm, signature_algorithm)

    def __eq__(self, other: 'Signature') -> bool:
        return self.__hash_algorithm == other.__hash_algorithm and self.__signature_algorithm == other.__signature_algorithm and self.__signature == other.__signature

    def length(self) -> int:
        return 2 + len(self.__signature)

    def get_hash_algorithm(self) -> bytes:
        return self.__hash_algorithm

    def get_signature_algorithm(self) -> bytes:
        return self.__signature_algorithm

    def get_signature(self) -> bytes:
        return self.__signature
