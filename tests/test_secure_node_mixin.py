"""Policy-resolution integration tests -- require ROS2 (ros_context fixture)."""

from types import SimpleNamespace

import pytest
from rclpy.node import Node
from std_msgs.msg import String

from ros2_security import SecureNodeMixin, SecurityLevel


class ProbeNode(SecureNodeMixin, Node):
    """Node that captures the internal _secure_cb wrapper for inspection."""

    def __init__(self, name, certs_dir, policy_path, level=None):
        super().__init__(name)
        self.captured_cb = None
        self.security_init(level=level, certs_dir=certs_dir, policy_path=policy_path)

    def create_subscription(self, msg_type, topic, cb, qos):  # noqa: D401
        self.captured_cb = cb
        return super().create_subscription(msg_type, topic, cb, qos)


@pytest.fixture
def make_node(ros_context, test_certs_dir, policy_file):
    created = []

    def _make(name, level=None):
        node = ProbeNode(name, test_certs_dir, policy_file, level=level)
        created.append(node)
        return node

    yield _make
    for node in created:
        node.destroy_node()


def test_policy_level_applied_to_publisher(make_node):
    # policy_file: node_a publish_level = sign
    node = make_node("node_a")
    assert node._sec.level == SecurityLevel.SIGN_ONLY


def test_explicit_level_overrides_policy(make_node):
    node = make_node("node_a", level=SecurityLevel.SIGN_ENCRYPT)
    assert node._sec.level == SecurityLevel.SIGN_ENCRYPT


def test_policy_min_level_applied_to_subscription(make_node):
    node = make_node("node_a")
    captured = {}
    node._sec.unwrap = lambda env, ml, mt: captured.__setitem__("min", ml) or None
    # /topic_a has min_level=sign in the policy; no explicit arg here.
    node.create_secure_subscription("/topic_a", String, lambda m: None)
    node.captured_cb(SimpleNamespace(level="none", sender="x"))
    assert captured["min"] == SecurityLevel.SIGN_ONLY


def test_explicit_min_level_overrides_policy(make_node):
    node = make_node("node_a")
    captured = {}
    node._sec.unwrap = lambda env, ml, mt: captured.__setitem__("min", ml) or None
    node.create_secure_subscription(
        "/topic_a", String, lambda m: None, min_level=SecurityLevel.SIGN_ENCRYPT
    )
    node.captured_cb(SimpleNamespace(level="none", sender="x"))
    assert captured["min"] == SecurityLevel.SIGN_ENCRYPT


def test_security_init_idempotent(make_node):
    node = make_node("node_a")
    sec1 = node._sec
    # Second call must be a no-op (same manager instance, no error).
    node.security_init()
    assert node._sec is sec1
