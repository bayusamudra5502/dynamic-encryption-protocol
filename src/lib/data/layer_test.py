from lib.data.layer import TLSRecordLayer, ProtocolVersion


def test_parse():
    data = b"\x17\x01\x02\x00\x24BACA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    result = TLSRecordLayer.parse(data)

    assert result.get_content() == b"BACA"
    assert result.get_mac() == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert result.get_version() == ProtocolVersion(1, 2)
    assert result.get_content_type() == b"\x17"


def test_encode():
    layer = TLSRecordLayer(
        ProtocolVersion(1, 2),
        b"\x17",
        b"BACA",
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    result = layer.encode()

    assert result == b"\x17\x01\x02\x00\x24BACA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_parse_headonly():
    data = b"\x17\x01\x02\x00\x24"
    result = TLSRecordLayer.parse(data)

    assert result.get_content() == b""
    assert result.get_mac() == b""
    assert result.get_version() == ProtocolVersion(1, 2)
    assert result.get_content_type() == b"\x17"
    assert result.get_content_size() == 4
