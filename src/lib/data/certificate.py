from lib.data.common import TLSPayload
from cryptography.x509 import load_der_x509_certificate, Certificate
from cryptography.hazmat.primitives.serialization import Encoding


class TLSCertificate(TLSPayload):
    __certificate_list: list[Certificate] = []

    def __init__(self, certificates: list[Certificate]) -> None:
        super().__init__()
        self.__certificate_list = certificates

    def encode(self) -> bytes:
        parsed = self.__certificate_list[0].public_bytes(encoding=Encoding.DER)
        return parsed

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        certs = load_der_x509_certificate(data)
        return TLSCertificate([certs])

    def __eq__(self, other: 'TLSCertificate') -> bool:
        return self.__certificate_list == other.__certificate_list

    def length(self) -> int:
        return len(self.encode())

    def get_certificates(self) -> list[Certificate]:
        return self.__certificate_list
