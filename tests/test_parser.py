import base64
import json

import pytest

from src.parsers.config_parser import (
    ConfigParseError,
    extract_candidate_uris,
    parse_any,
    parse_mtproto,
    parse_shadowsocks,
    parse_trojan,
    parse_vless,
    parse_vmess,
)


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def test_parse_vmess_valid():
    payload = {
        "add": "example.com",
        "port": 443,
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "aid": "0",
        "net": "ws",
        "path": "/ray",
        "tls": "tls",
        "ps": "test-node",
    }
    uri = "vmess://" + _b64(json.dumps(payload))
    config = parse_vmess(uri)
    assert config.protocol == "vmess"
    assert config.host == "example.com"
    assert config.port == 443
    assert config.tls is True
    assert config.network_type == "ws"


def test_parse_vmess_missing_field_raises():
    payload = {"add": "example.com", "port": 443}  # missing id
    uri = "vmess://" + _b64(json.dumps(payload))
    with pytest.raises(ConfigParseError):
        parse_vmess(uri)


def test_parse_vless_reality():
    uri = (
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443"
        "?security=reality&sni=example.com&pbk=abc123&sid=de&fp=chrome&type=tcp"
        "#my-node"
    )
    config = parse_vless(uri)
    assert config.protocol == "vless"
    assert config.encryption == "reality"
    assert config.tls is True
    assert config.extra["pbk"] == "abc123"
    assert config.remark == "my-node"


def test_parse_trojan():
    uri = "trojan://s3cr3t@1.2.3.4:443?sni=example.com#node1"
    config = parse_trojan(uri)
    assert config.identifier == "s3cr3t"
    assert config.tls is True


def test_parse_shadowsocks_sip002():
    userinfo = _b64("aes-256-gcm:password123")
    uri = f"ss://{userinfo}@1.2.3.4:8388#node"
    config = parse_shadowsocks(uri)
    assert config.encryption == "aes-256-gcm"
    assert config.identifier == "password123"
    assert config.port == 8388


def test_parse_shadowsocks_legacy():
    decoded = "chacha20-ietf-poly1305:hunter2@5.6.7.8:8080"
    uri = f"ss://{_b64(decoded)}"
    config = parse_shadowsocks(uri)
    assert config.host == "5.6.7.8"
    assert config.port == 8080


def test_parse_mtproto():
    uri = "tg://proxy?server=1.2.3.4&port=443&secret=dd0011223344556677889900aabbccddee"
    config = parse_mtproto(uri)
    assert config.protocol == "mtproto"
    assert config.host == "1.2.3.4"


def test_parse_any_unrecognized_scheme():
    with pytest.raises(ConfigParseError):
        parse_any("http://not-a-proxy.com")


def test_extract_candidate_uris_mixed_text():
    text = (
        "🔥 New configs today!\n"
        "vless://uuid@1.2.3.4:443?security=tls#node1\n"
        "some prose about the channel https://t.me/somechannel\n"
        "trojan://pw@5.6.7.8:443#node2 extra text here"
    )
    found = extract_candidate_uris(text)
    assert len(found) == 2
    assert found[0].startswith("vless://")
    assert found[1].startswith("trojan://")
