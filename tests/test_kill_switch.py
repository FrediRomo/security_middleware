"""Kill-switch (native passthrough) tests -- no ROS graph required.

The env var ``ROS2_SECURITY_DISABLED=1`` is set BEFORE the security modules are
(re)imported, because ``SECURITY_ENABLED`` is evaluated once at import time.
A fake node stands in for an rclpy Node so these tests need no ``rclpy.init()``.
"""

import importlib
import os
import sys
from types import SimpleNamespace

import pytest
from std_msgs.msg import String


@pytest.fixture
def disabled():
    """Reload the security modules with the kill switch active, then restore."""
    os.environ["ROS2_SECURITY_DISABLED"] = "1"
    import ros2_security.security_manager as sm
    import ros2_security.secure_node_mixin as mixin
    importlib.reload(sm)
    importlib.reload(mixin)
    try:
        yield sm, mixin
    finally:
        os.environ.pop("ROS2_SECURITY_DISABLED", None)
        importlib.reload(sm)
        importlib.reload(mixin)


def _make_fake_node(mixin_mod):
    class FakeNode(mixin_mod.SecureNodeMixin):
        def __init__(self):
            self.created_pubs = []
            self.created_subs = []

        def get_name(self):
            return "node_a"

        def create_publisher(self, msg_type, topic, qos):
            pub = SimpleNamespace(msg_type=msg_type, topic=topic, qos=qos, sent=[])
            pub.publish = pub.sent.append
            self.created_pubs.append(pub)
            return pub

        def create_subscription(self, msg_type, topic, callback, qos):
            sub = SimpleNamespace(msg_type=msg_type, topic=topic, callback=callback, qos=qos)
            self.created_subs.append(sub)
            return sub

        def get_logger(self):
            return SimpleNamespace(warning=lambda *a, **k: None)

    return FakeNode()


def test_security_enabled_is_false(disabled):
    sm, mixin = disabled
    assert sm.SECURITY_ENABLED is False
    assert mixin.SECURITY_ENABLED is False


def test_publisher_type_is_native(disabled):
    sm, mixin = disabled
    node = _make_fake_node(mixin)
    node.security_init()
    pub = node.create_secure_publisher("/camera/frame", String)
    assert pub.msg_type is String  # native, not SecureEnvelope


def test_subscriber_type_is_native(disabled):
    sm, mixin = disabled
    node = _make_fake_node(mixin)
    node.security_init()

    def cb(msg):
        pass

    sub = node.create_secure_subscription("/camera/frame", String, cb)
    assert sub.msg_type is String
    # Callback wired straight through -- no _secure_cb wrapper.
    assert sub.callback is cb


def test_publish_sends_native_msg(disabled):
    sm, mixin = disabled
    node = _make_fake_node(mixin)
    node.security_init()
    pub = node.create_secure_publisher("/t", String)
    msg = String(data="x")
    node.secure_publish(pub, msg)
    assert pub.sent == [msg]  # exact same object, no envelope


def test_callback_receives_native_msg(disabled):
    sm, mixin = disabled
    node = _make_fake_node(mixin)
    node.security_init()
    received = []
    node.create_secure_subscription("/t", String, received.append)
    sub = node.created_subs[0]
    msg = String(data="payload")
    sub.callback(msg)
    assert received == [msg]
    assert isinstance(received[0], String)


def test_no_secureenvelope_import(disabled):
    sm, mixin = disabled
    sys.modules.pop("ros2_security_msgs.msg", None)
    sys.modules.pop("ros2_security_msgs", None)
    node = _make_fake_node(mixin)
    node.security_init()
    pub = node.create_secure_publisher("/t", String)
    node.secure_publish(pub, String(data="x"))
    node.create_secure_subscription("/t", String, lambda m: None)
    assert "ros2_security_msgs.msg" not in sys.modules


def test_security_manager_not_called(disabled, monkeypatch):
    sm, mixin = disabled
    calls = {"wrap": 0, "unwrap": 0}
    monkeypatch.setattr(
        sm.SecurityManager, "wrap",
        lambda self, m: calls.__setitem__("wrap", calls["wrap"] + 1),
    )
    monkeypatch.setattr(
        sm.SecurityManager, "unwrap",
        lambda self, e, ml, mt: calls.__setitem__("unwrap", calls["unwrap"] + 1),
    )
    node = _make_fake_node(mixin)
    node.security_init()
    pub = node.create_secure_publisher("/t", String)
    node.secure_publish(pub, String(data="x"))
    node.create_secure_subscription("/t", String, lambda m: None)
    node.created_subs[0].callback(String(data="y"))
    assert calls == {"wrap": 0, "unwrap": 0}


def test_policy_not_loaded_when_disabled(disabled, monkeypatch):
    sm, mixin = disabled
    instantiated = {"count": 0}
    real_init = mixin.SecurityPolicyLoader.__init__

    def spy_init(self, *a, **k):
        instantiated["count"] += 1
        return real_init(self, *a, **k)

    monkeypatch.setattr(mixin.SecurityPolicyLoader, "__init__", spy_init)
    node = _make_fake_node(mixin)
    node.security_init()
    assert instantiated["count"] == 0
