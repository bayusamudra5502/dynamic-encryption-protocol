from lib.data.layer import TLSRecordLayer, ProtocolVersion
from lib.data.text import TLSCiphertext


def test_parse():
    data = b"\x17\x01\x02\x00\x04BACA"
    result = TLSRecordLayer.parse(data)

    assert result.get_content().get_data() == b"BACA"
    assert result.get_version() == ProtocolVersion(1, 2)
    assert result.get_content_type() == b"\x17"


def test_encode():
    layer = TLSRecordLayer(
        ProtocolVersion(1, 2),
        b"\x17",
        TLSCiphertext(
            b"BACA")
    )
    result = layer.encode()

    assert result == b"\x17\x01\x02\x00\x04BACA"


def test_parse_headonly():
    data = b"\x17\x01\x02\x00\x24"
    result = TLSRecordLayer.parse(data, with_data=False)

    assert result.get_content() == None
    assert result.get_version() == ProtocolVersion(1, 2)
    assert result.get_content_type() == b"\x17"
    assert result.get_content_size() == 36
