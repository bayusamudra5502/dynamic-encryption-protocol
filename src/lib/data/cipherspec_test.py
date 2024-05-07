from lib.data.cipherspec import ChangeCipherSpec


def test_cipherspec():
    data = ChangeCipherSpec()
    assert data.encode() == b'\x01'
    assert ChangeCipherSpec.parse(b'\x01') == ChangeCipherSpec()

    try:
        ChangeCipherSpec.parse(b'\x02')
        assert False
    except ValueError:
        pass

    assert data.length() == 1
