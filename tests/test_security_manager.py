"""Unit tests for SecurityManager wrap/unwrap -- no ROS graph required.

These need ``rclpy`` importable (for CDR serialization) and the built
``ros2_security_msgs`` package, but do NOT require ``rclpy.init()``.
"""

import time

import pytest
from std_msgs.msg import String

from ros2_security.security_manager import SecurityLevel, SecurityManager


def _make_msg(data="hello world"):
    return String(data=data)


@pytest.fixture
def pub_sub(test_certs_dir):
    """A publisher manager (node_a) and a subscriber manager (node_b)."""
    def _build(pub_level):
        pub = SecurityManager()
        pub.load("node_a", pub_level, test_certs_dir)
        sub = SecurityManager()
        sub.load("node_b", SecurityLevel.SIGN_ENCRYPT, test_certs_dir)
        return pub, sub
    return _build


# ---------------------------------------------------------------- wrap ----

def test_wrap_none_level(test_certs_dir):
    mgr = SecurityManager()
    mgr.load("node_a", SecurityLevel.NONE, test_certs_dir)
    env = mgr.wrap(_make_msg())
    assert env.level == "none"
    assert env.sig == ""
    assert env.nonce == ""
    assert len(bytes(env.payload)) > 0


def test_wrap_sign_only(test_certs_dir):
    mgr = SecurityManager()
    mgr.load("node_a", SecurityLevel.SIGN_ONLY, test_certs_dir)
    env = mgr.wrap(_make_msg())
    assert env.level == "sign"
    assert env.sig != ""
    assert env.nonce == ""


def test_wrap_sign_encrypt(test_certs_dir):
    mgr = SecurityManager()
    mgr.load("node_a", SecurityLevel.SIGN_ENCRYPT, test_certs_dir)
    env = mgr.wrap(_make_msg())
    assert env.level == "sign+encrypt"
    assert env.sig != ""
    assert env.nonce != ""


def test_content_type_preserved(test_certs_dir):
    mgr = SecurityManager()
    mgr.load("node_a", SecurityLevel.SIGN_ONLY, test_certs_dir)
    env = mgr.wrap(_make_msg())
    assert env.content_type == "std_msgs/msg/String"


# -------------------------------------------------------------- unwrap ----

def test_unwrap_valid_sign_only(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    env = pub.wrap(_make_msg("abc"))
    out = sub.unwrap(env, SecurityLevel.SIGN_ONLY, String)
    assert out is not None and out.data == "abc"


def test_unwrap_valid_sign_encrypt(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ENCRYPT)
    env = pub.wrap(_make_msg("secret"))
    out = sub.unwrap(env, SecurityLevel.SIGN_ENCRYPT, String)
    assert out is not None and out.data == "secret"


def test_unwrap_bad_signature(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    env = pub.wrap(_make_msg())
    # Flip a byte in the signature.
    sig = bytearray.fromhex(env.sig)
    sig[0] ^= 0xFF
    env.sig = sig.hex()
    assert sub.unwrap(env, SecurityLevel.SIGN_ONLY, String) is None


def test_unwrap_tampered_payload(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    env = pub.wrap(_make_msg())
    payload = bytearray(bytes(env.payload))
    payload[-1] ^= 0xFF
    env.payload = list(payload)
    assert sub.unwrap(env, SecurityLevel.SIGN_ONLY, String) is None


def test_unwrap_replay(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    sub.replay_window = 30.0
    env = pub.wrap(_make_msg())
    env.ts = time.time() - 1000.0
    assert sub.unwrap(env, SecurityLevel.SIGN_ONLY, String) is None


def test_unwrap_replay_disabled(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    sub.replay_window = None
    env = pub.wrap(_make_msg("old"))
    env.ts = time.time() - 1000.0
    out = sub.unwrap(env, SecurityLevel.SIGN_ONLY, String)
    assert out is not None and out.data == "old"


def test_unwrap_unknown_sender(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ONLY)
    env = pub.wrap(_make_msg())
    env.sender = "ghost_node"
    assert sub.unwrap(env, SecurityLevel.SIGN_ONLY, String) is None


def test_mixed_trust_gate(pub_sub):
    pub, sub = pub_sub(SecurityLevel.NONE)
    env = pub.wrap(_make_msg())
    # NONE message rejected when subscription requires SIGN_ONLY.
    assert sub.unwrap(env, SecurityLevel.SIGN_ONLY, String) is None


def test_sign_encrypt_accepted_at_sign_only(pub_sub):
    pub, sub = pub_sub(SecurityLevel.SIGN_ENCRYPT)
    env = pub.wrap(_make_msg("hi"))
    out = sub.unwrap(env, SecurityLevel.SIGN_ONLY, String)
    assert out is not None and out.data == "hi"


@pytest.mark.parametrize(
    "level",
    [SecurityLevel.NONE, SecurityLevel.SIGN_ONLY, SecurityLevel.SIGN_ENCRYPT],
)
def test_wrap_unwrap_round_trip(pub_sub, level):
    pub, sub = pub_sub(level)
    msg = _make_msg("round-trip-{}".format(level.value))
    env = pub.wrap(msg)
    out = sub.unwrap(env, SecurityLevel.NONE, String)
    assert out is not None
    assert out.data == msg.data
