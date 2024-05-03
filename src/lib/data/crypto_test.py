from lib.data.crypto import *


def test_signature():
    signature = Signature(b"\x00")
    assert signature.encode() == b"\x04\x03\x00"
    assert Signature.parse(b"\x04\x03\x00") == signature
