from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from lib.log import Log


def sign(data: bytes, private_key: ec.EllipticCurvePrivateKey, *, alg=ec.ECDSA(SHA256())):
    return private_key.sign(data, alg)


def verify(data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey, *, alg=ec.ECDSA(SHA256())):
    try:
        public_key.verify(signature, data, alg)
        return True
    except Exception as err:
        Log.debug(err)
        return False
