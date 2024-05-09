from lib.util import to_bytes_big, to_int_big


def test_big_int_conversion():
    res = to_bytes_big(0x0102030405060708090a0b0c0d0e0f, 16)
    assert res == b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    assert len(res) == 16
    assert (
        to_int_big(to_bytes_big(0x1234567890abcdef, 16)) == 0x1234567890abcdef
    )
