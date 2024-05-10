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
        parsed_length = (len(parsed)).to_bytes(3, "big")

        asn1_parsed = parsed_length + parsed
        asn1_parsed_length = len(asn1_parsed).to_bytes(3, "big")

        return asn1_parsed_length + asn1_parsed

    @staticmethod
    def parse(data: bytes) -> 'TLSPayload':
        certs = []
        processed = 0
        certificate_length = int.from_bytes(data[:3], "big")
        asn1_parsed = data[3:]

        while processed < certificate_length:
            cert_length = int.from_bytes(
                asn1_parsed[processed:processed+3], "big")
            cert_der = asn1_parsed[processed+3:processed+3+cert_length]
            certificate = load_der_x509_certificate(cert_der)

            certs.append(certificate)
            processed += 3 + cert_length

        return TLSCertificate(certs)

    def __eq__(self, other: 'TLSCertificate') -> bool:
        return self.__certificate_list == other.__certificate_list

    def length(self) -> int:
        return len(self.encode())

    def get_certificates(self) -> list[Certificate]:
        return self.__certificate_list
