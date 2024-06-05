from lib.conn.transport import Transport
from multiprocessing import Process, Queue

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from uuid import uuid4

import datetime
import time


def generate_certificate_and_key():
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "sample.local")
    ])
    now = datetime.datetime.fromtimestamp(time.time())

    x509_cert = x509.CertificateBuilder()\
        .subject_name(name) \
        .issuer_name(name) \
        .public_key(public) \
        .serial_number(1000) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(hours=2)) \
        .sign(private, hashes.SHA256())

    return x509_cert, private
