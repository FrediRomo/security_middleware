"""Demo subscriber — tutorial showing how to add ros2_security to a plain node.

Read the diff between the commented-out lines and the active lines below: that
is the entire change needed to secure any existing ROS2 subscriber.

BEFORE (plain ROS2):               AFTER (secured):
──────────────────────────────     ──────────────────────────────────────────
class DemoSubscriber(Node):        class DemoSubscriber(SecureNodeMixin, Node):
                                   self.security_init(...)
create_subscription(String, ...)   create_secure_subscription(topic, String,
                                       ..., min_level=...)
callback(msg)                      callback(msg)   ← signature unchanged

The callback signature is identical: it still receives a plain typed message.
All verification, decryption, and drop logic happens inside the mixin.

Run
---
# Default (reads level and min_level from security_policy.yaml):
ros2 run ros2_security_demo demo_subscriber --ros-args -p certs_dir:=./certs

# Relay demo — accept any level (overrides policy):
ros2 run ros2_security_demo demo_subscriber \\
    --ros-args -p certs_dir:=./certs -p min_level:=none

# Strict mode — require signed+encrypted:
ros2 run ros2_security_demo demo_subscriber \\
    --ros-args -p certs_dir:=./certs -p min_level:=sign+encrypt
"""

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

# ── (1) import the mixin and the level enum ────────────────────────────────
from ros2_security import SecureNodeMixin, SecurityLevel
# ──────────────────────────────────────────────────────────────────────────


# ── (2) add SecureNodeMixin as the FIRST base class ───────────────────────
# BEFORE: class DemoSubscriber(Node):
class DemoSubscriber(SecureNodeMixin, Node):
# ──────────────────────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__('demo_subscriber')

        self.declare_parameter('certs_dir', './certs')
        self.declare_parameter('topic',     '/chatter')
        # min_level=None means "read from security_policy.yaml".
        # Pass an explicit value to override the policy for this instance.
        self.declare_parameter('min_level', '')

        certs_dir = self.get_parameter('certs_dir').value
        topic     = self.get_parameter('topic').value
        ml_param  = self.get_parameter('min_level').value

        # Resolve min_level: explicit parameter > policy file.
        min_level = SecurityLevel(ml_param) if ml_param else None

        # ── (3) initialise security ──────────────────────────────────────────
        self.security_init(certs_dir=certs_dir)
        # ─────────────────────────────────────────────────────────────────────

        # ── (4) create a secure subscription ────────────────────────────────
        # BEFORE: self.create_subscription(String, topic, self._on_message, 10)
        self.create_secure_subscription(
            topic, String, self._on_message,
            min_level=min_level,   # None → reads from policy; explicit → overrides
        )
        # ─────────────────────────────────────────────────────────────────────

        effective = (
            min_level.value if min_level is not None
            else self._policy_loader.min_level(self.get_name(), topic).value
        )
        self.get_logger().info(
            'demo_subscriber ready  topic={!r}  min_level={}  '
            'node_level={}'.format(topic, effective, self._sec.level.value)
        )

    # ── (5) callback is unchanged ────────────────────────────────────────────
    # The mixin verifies/decrypts the envelope and calls this with the plain
    # typed message, exactly as if security were not present.
    def _on_message(self, msg: String):
        self.get_logger().info('Received: {}'.format(msg.data))
    # ─────────────────────────────────────────────────────────────────────────


def main(args=None):
    rclpy.init(args=args)
    node = DemoSubscriber()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
