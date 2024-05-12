from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Hash import HMAC, SHA256
from lib.crypto.csprng import SineHenonMap
from lib.crypto.aes import DynamicAES, DynamicHMAC


def generate_shared_secret(server_public: ec.EllipticCurvePublicKey, client_secret: ec.EllipticCurvePrivateKey) -> bytes:
    return client_secret.exchange(ec.ECDH(), server_public)


def tls_prf(secret: bytes, label: bytes, seed: bytes, length: int, *, digestmod=SHA256) -> bytes:
    a = seed
    result = b""

    while len(result) < length:
        a = HMAC.new(secret, a, digestmod=digestmod).digest()
        result += HMAC.new(secret, a + label + seed,
                           digestmod=digestmod).digest()

    return result[:length]


def generate_master_secret(pre_master_secret: bytes, client_random: bytes, server_random: bytes) -> bytes:
    return tls_prf(pre_master_secret, b"master secret", client_random + server_random, 48)


def generate_chaos_parameter(master_secret: bytes, client_random: bytes, server_random: bytes) -> tuple[DynamicAES, DynamicAES, DynamicHMAC, DynamicHMAC]:
    result = tls_prf(master_secret, b"key expansion",
                     server_random + client_random, 32 * 18)

    key11 = int.from_bytes(result[:32]) / (2 ** 256)
    key12 = int.from_bytes(result[32:64]) / (2 ** 256)
    key13 = int.from_bytes(result[64:96]) / (2 ** 256)

    key21 = int.from_bytes(result[96:128]) / (2 ** 256)
    key22 = int.from_bytes(result[128:160]) / (2 ** 256)
    key23 = int.from_bytes(result[160:192]) / (2 ** 256)

    key31 = int.from_bytes(result[192:224]) / (2 ** 256)
    key32 = int.from_bytes(result[224:256]) / (2 ** 256)
    key33 = int.from_bytes(result[256:288]) / (2 ** 256)

    key41 = int.from_bytes(result[288:320]) / (2 ** 256)
    key42 = int.from_bytes(result[320:352]) / (2 ** 256)
    key43 = int.from_bytes(result[352:384]) / (2 ** 256)

    key51 = int.from_bytes(result[384:416]) / (2 ** 256)
    key52 = int.from_bytes(result[416:448]) / (2 ** 256)
    key53 = int.from_bytes(result[448:480]) / (2 ** 256)

    key61 = int.from_bytes(result[480:512]) / (2 ** 256)
    key62 = int.from_bytes(result[512:544]) / (2 ** 256)
    key63 = int.from_bytes(result[544:576]) / (2 ** 256)

    # Participant A chaos system
    c1 = SineHenonMap(key11, key12, key13)
    c2 = SineHenonMap(key21, key22, key23)
    iv1 = SineHenonMap(key51, key52, key33)

    # Participant B chaos system
    c3 = SineHenonMap(key31, key32, key43)
    c4 = SineHenonMap(key41, key42, key53)
    iv2 = SineHenonMap(key61, key62, key63)

    aes1 = DynamicAES(c1, iv1)
    aes2 = DynamicAES(c3, iv2)

    hmac1 = DynamicHMAC(c2)
    hmac2 = DynamicHMAC(c4)

    return aes1, aes2, hmac1, hmac2


def generate_finished_payload(master_secret: bytes, handshake_messages: bytes, is_client: bool) -> bytes:
    if is_client:
        return tls_prf(master_secret, b"client finished", handshake_messages, 12)
    else:
        return tls_prf(master_secret, b"server finished", handshake_messages, 12)
