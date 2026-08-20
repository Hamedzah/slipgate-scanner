from cryptography.fernet import Fernet

from src.parsers.config_parser import ParsedConfig
from src.security.crypto import SecretBox
from src.utils.hashing import compute_config_hash


def test_dedup_hash_ignores_remark():
    a = ParsedConfig(protocol="vless", host="1.2.3.4", port=443, identifier="uuid", remark="node-A")
    b = ParsedConfig(protocol="vless", host="1.2.3.4", port=443, identifier="uuid", remark="node-B")
    assert compute_config_hash(a) == compute_config_hash(b)


def test_dedup_hash_differs_for_different_host():
    a = ParsedConfig(protocol="vless", host="1.2.3.4", port=443, identifier="uuid")
    b = ParsedConfig(protocol="vless", host="5.6.7.8", port=443, identifier="uuid")
    assert compute_config_hash(a) != compute_config_hash(b)


def test_secret_box_roundtrip():
    key = Fernet.generate_key().decode()
    box = SecretBox(key)
    token = box.encrypt("1.2.3.4")
    assert box.decrypt(token) == "1.2.3.4"
    assert token != "1.2.3.4"


def test_secret_box_wrong_key_fails():
    box1 = SecretBox(Fernet.generate_key().decode())
    box2 = SecretBox(Fernet.generate_key().decode())
    token = box1.encrypt("secret-host")
    try:
        box2.decrypt(token)
        assert False, "expected ValueError"
    except ValueError:
        pass
