from cryptography.hazmat.primitives.asymmetric import ec
from lib.crypto.sign import sign, verify


def test_signature():
    private = ec.generate_private_key(ec.SECP256R1())
    private2 = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()

    message = b"Hello, World"
    signature = sign(message, private)
    signature2 = sign(message, private2)

    assert verify(message, signature, public)
    assert not verify(message, signature2, public)
