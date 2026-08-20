from src.parsers.config_parser import ParsedConfig
from src.testing.protocol_validator import validate


def test_valid_vmess():
    config = ParsedConfig(
        protocol="vmess",
        host="1.2.3.4",
        port=443,
        identifier="b831381d-6324-4d53-ad4f-8cda48b30811",
        encryption="auto",
    )
    assert validate(config)


def test_invalid_vmess_bad_uuid():
    config = ParsedConfig(
        protocol="vmess", host="1.2.3.4", port=443, identifier="not-a-uuid", encryption="auto"
    )
    assert not validate(config)


def test_invalid_port():
    config = ParsedConfig(protocol="trojan", host="1.2.3.4", port=0, identifier="password123")
    assert not validate(config)


def test_shadowsocks_unsupported_cipher():
    config = ParsedConfig(
        protocol="shadowsocks", host="1.2.3.4", port=8388, identifier="pw", encryption="rc4-md5"
    )
    assert not validate(config)


def test_mtproto_invalid_secret():
    config = ParsedConfig(protocol="mtproto", host="1.2.3.4", port=443, identifier="not-hex")
    assert not validate(config)


def test_mtproto_valid_secret():
    config = ParsedConfig(
        protocol="mtproto",
        host="1.2.3.4",
        port=443,
        identifier="dd" + "aa" * 16,
    )
    assert validate(config)
