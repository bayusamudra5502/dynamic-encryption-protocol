from lib.data.common import *
from lib.util import to_bytes_big
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization.base import load_der_public_key
from lib.data.crypto import Signature
from abc import ABC, abstractmethod


class ECPoint(TLSPayload):
    __x = None
    __y = None

    def __init__(self, x: int, y: int) -> None:
        self.__x = x
        self.__y = y

    def encode(self) -> bytes:
        return b"\x04" + to_bytes_big(self.__x, 32) + to_bytes_big(self.__y, 32)

    @staticmethod
    def parse(data: bytes) -> 'ECPoint':
        if data[0] != 0x04:
            raise ValueError("unsupported ECPoint encoding")

        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")

        return ECPoint(x, y)

    def __eq__(self, other: 'ECPoint') -> bool:
        return self.__x == other.__x and self.__y == other.__y

    def length(self) -> int:
        return 65

    def get_public_key(self, curve="secp256r1") -> ec.EllipticCurvePublicKey:
        if curve != "secp256r1":
            raise ValueError("unsupported curve")

        magic = b"0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x04"
        x = to_bytes_big(self.__x, 32)
        y = to_bytes_big(self.__y, 32)

        return load_der_public_key(magic + x + y)

    def get_x(self) -> int:
        return self.__x

    def get_y(self) -> int:
        return self.__y


class ECCurveType:
    NAMED_CURVE = b"\x03"


class NamedCurve:
    SECP256R1 = b"\x17"


class ECParameter(TLSPayload):
    __curve_type = None
    __named_curve = None

    def __init__(self, curve_type: bytes = ECCurveType.NAMED_CURVE, named_curve: bytes = NamedCurve.SECP256R1) -> None:
        self.__curve_type = curve_type
        self.__named_curve = named_curve

    def encode(self) -> bytes:
        return self.__curve_type + self.__named_curve

    @staticmethod
    def parse(data: bytes) -> 'ECParameter':
        curve_type = data[0:1]
        named_curve = data[1:]

        return ECParameter(curve_type, named_curve)

    def __eq__(self, other: 'ECParameter') -> bool:
        return self.__curve_type == other.__curve_type and self.__named_curve == other.__named_curve

    def length(self) -> int:
        return 2


class ECDHParameter(TLSPayload):
    __curve_params = None
    __public = None

    def __init__(self, curve_params: ECParameter, public: ECPoint) -> None:
        self.__curve_params = curve_params
        self.__public = public

    def encode(self) -> bytes:
        return self.__curve_params.encode() + self.__public.encode()

    @staticmethod
    def parse(data: bytes) -> 'ECDHParameter':
        curve_params = ECParameter.parse(data[0:2])
        public = ECPoint.parse(data[2:])

        return ECDHParameter(curve_params, public)

    def __eq__(self, other: 'ECDHParameter') -> bool:
        return self.__curve_params == other.__curve_params and self.__public == other.__public

    def length(self) -> int:
        return self.__curve_params.length() + self.__public.length()

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self.__public.get_public_key()

    def get_curve_params(self):
        return self.__curve_params

    def get_public(self):
        return self.__public


class KeyExchange(TLSPayload):
    @abstractmethod
    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        pass


class ServerKeyExchange(KeyExchange):
    __ecdh_params = None
    __signature = None

    def __init__(self, ecdh_params: ECDHParameter, signature: Signature) -> None:
        super().__init__()
        self.__ecdh_params = ecdh_params
        self.__signature = signature

    def encode(self) -> bytes:
        return self.__ecdh_params.encode() + self.__signature.encode()

    @staticmethod
    def parse(data: bytes) -> 'ServerKeyExchange':
        ecdh_params = ECDHParameter.parse(data[0:67])
        signature = Signature.parse(data[67:])

        return ServerKeyExchange(ecdh_params, signature)

    def __eq__(self, other: 'ServerKeyExchange') -> bool:
        return self.__ecdh_params == other.__ecdh_params and self.__signature == other.__signature

    def length(self) -> int:
        return self.__ecdh_params.length() + self.__signature.length()

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self.__ecdh_params.get_public_key()

    def get_params(self):
        return self.__ecdh_params

    def get_signature(self):
        return self.__signature


class ClientKeyExchange(KeyExchange):
    __public = None

    def __init__(self, public: ECPoint) -> None:
        self.__public = public

    def encode(self) -> bytes:
        return self.__public.encode()

    @staticmethod
    def parse(data: bytes) -> 'ClientKeyExchange':
        public = ECPoint.parse(data)

        return ClientKeyExchange(public)

    def __eq__(self, other: 'ClientKeyExchange') -> bool:
        return self.__public == other.__public

    def length(self) -> int:
        return self.__public.length()

    def get_public_key(self) -> ec.EllipticCurvePublicKey:
        return self.__public.get_public_key()
