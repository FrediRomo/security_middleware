"""End-to-end mixed-trust integration tests -- require ROS2 (ros_context)."""

import time

import pytest
from rclpy.executors import SingleThreadedExecutor
from rclpy.node import Node
from std_msgs.msg import String

from ros2_security import SecureNodeMixin, SecurityLevel
from ros2_security.legacy_relay import LegacyRelayNode


class PubNode(SecureNodeMixin, Node):
    def __init__(self, name, topic, certs_dir, level):
        super().__init__(name)
        self.security_init(level=level, certs_dir=certs_dir)
        self._pub = self.create_secure_publisher(topic, String)

    def tick(self, data):
        self.secure_publish(self._pub, String(data=data))


class SubNode(SecureNodeMixin, Node):
    def __init__(self, name, topic, certs_dir, init_level, min_level):
        super().__init__(name)
        self.security_init(level=init_level, certs_dir=certs_dir)
        self.received = []
        self.create_secure_subscription(
            topic, String, self.received.append, min_level=min_level
        )


class NativePub(Node):
    def __init__(self, name, topic):
        super().__init__(name)
        self._pub = self.create_publisher(String, topic, 10)

    def tick(self, data):
        self._pub.publish(String(data=data))


def _run(executor, tickers, predicate, timeout=5.0):
    """Repeatedly tick publishers and spin until predicate() or timeout."""
    end = time.time() + timeout
    while time.time() < end and not predicate():
        for t in tickers:
            t()
        executor.spin_once(timeout_sec=0.05)
    return predicate()


@pytest.fixture
def executor(ros_context):
    ex = SingleThreadedExecutor()
    nodes = []
    yield ex, nodes
    for n in nodes:
        ex.remove_node(n)
        n.destroy_node()


def test_none_to_none_delivered(executor, test_certs_dir):
    ex, nodes = executor
    pub = PubNode("lidar_node", "/n2n", test_certs_dir, SecurityLevel.NONE)
    sub = SubNode("planner_node", "/n2n", test_certs_dir,
                  SecurityLevel.NONE, SecurityLevel.NONE)
    nodes += [pub, sub]
    ex.add_node(pub)
    ex.add_node(sub)
    delivered = _run(ex, [lambda: pub.tick("hello")], lambda: len(sub.received) > 0)
    assert delivered
    assert sub.received[0].data == "hello"


def test_none_to_sign_dropped(executor, test_certs_dir):
    ex, nodes = executor
    pub = PubNode("lidar_node", "/n2s", test_certs_dir, SecurityLevel.NONE)
    sub = SubNode("planner_node", "/n2s", test_certs_dir,
                  SecurityLevel.SIGN_ENCRYPT, SecurityLevel.SIGN_ONLY)
    nodes += [pub, sub]
    ex.add_node(pub)
    ex.add_node(sub)
    # NONE publisher cannot satisfy a SIGN_ONLY subscriber: never delivered.
    delivered = _run(ex, [lambda: pub.tick("x")],
                     lambda: len(sub.received) > 0, timeout=2.0)
    assert not delivered
    assert sub.received == []


def test_sign_encrypt_to_sign_only_delivered(executor, test_certs_dir):
    ex, nodes = executor
    pub = PubNode("camera_node", "/se2so", test_certs_dir, SecurityLevel.SIGN_ENCRYPT)
    sub = SubNode("planner_node", "/se2so", test_certs_dir,
                  SecurityLevel.SIGN_ENCRYPT, SecurityLevel.SIGN_ONLY)
    nodes += [pub, sub]
    ex.add_node(pub)
    ex.add_node(sub)
    delivered = _run(ex, [lambda: pub.tick("frame-data")],
                     lambda: len(sub.received) > 0)
    assert delivered
    assert sub.received[0].data == "frame-data"


def test_relay_pattern_end_to_end(executor, test_certs_dir):
    ex, nodes = executor
    native = NativePub("legacy_source", "/diag_raw")
    relay = LegacyRelayNode([(String, "/diag_raw", "/diagnostics")])
    sub = SubNode("planner_node", "/diagnostics", test_certs_dir,
                  SecurityLevel.NONE, SecurityLevel.NONE)
    nodes += [native, relay, sub]
    for n in (native, relay, sub):
        ex.add_node(n)
    delivered = _run(ex, [lambda: native.tick("diag-ok")],
                     lambda: len(sub.received) > 0)
    assert delivered
    assert sub.received[0].data == "diag-ok"


def test_policy_drives_mixed_trust(executor, test_certs_dir, tmp_path):
    # Policy sets min_level=sign on planner_node's /lidar/scan subscription;
    # an unsigned (NONE) message must be dropped without any explicit code arg.
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "global_min_level: none\n"
        "nodes:\n"
        "  planner_node:\n"
        "    publish_level: sign\n"
        "    subscriptions:\n"
        "      /lidar/scan:\n"
        "        min_level: sign\n"
    )

    ex, nodes = executor
    pub = PubNode("lidar_node", "/lidar/scan", test_certs_dir, SecurityLevel.NONE)

    class PolicySub(SecureNodeMixin, Node):
        def __init__(self):
            super().__init__("planner_node")
            self.security_init(certs_dir=test_certs_dir, policy_path=str(policy))
            self.received = []
            # No explicit min_level -> resolved from policy (sign).
            self.create_secure_subscription("/lidar/scan", String, self.received.append)

    sub = PolicySub()
    nodes += [pub, sub]
    ex.add_node(pub)
    ex.add_node(sub)
    delivered = _run(ex, [lambda: pub.tick("scan")],
                     lambda: len(sub.received) > 0, timeout=2.0)
    assert not delivered
    assert sub.received == []
