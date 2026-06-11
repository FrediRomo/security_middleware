"""Demo publisher — tutorial showing how to add ros2_security to a plain node.

Read the diff between the commented-out lines and the active lines below: that
is the entire change needed to secure any existing ROS2 publisher.

BEFORE (plain ROS2):               AFTER (secured):
──────────────────────────────     ──────────────────────────────────────────
class DemoPublisher(Node):         class DemoPublisher(SecureNodeMixin, Node):
                                   self.security_init(...)
create_publisher(String, ...)      create_secure_publisher(topic, String)
publisher.publish(msg)             self.secure_publish(publisher, msg)

Run
---
# Generate certs once, then:
ros2 run ros2_security_demo demo_publisher --ros-args -p certs_dir:=./certs
"""

import rclpy
from rclpy.node import Node
from std_msgs.msg import String

# ── (1) import the mixin and the level enum ────────────────────────────────
from ros2_security import SecureNodeMixin, SecurityLevel
# ──────────────────────────────────────────────────────────────────────────


# ── (2) add SecureNodeMixin as the FIRST base class ───────────────────────
# BEFORE: class DemoPublisher(Node):
class DemoPublisher(SecureNodeMixin, Node):
# ──────────────────────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__('demo_publisher')

        self.declare_parameter('certs_dir', './certs')
        certs_dir = self.get_parameter('certs_dir').value

        # ── (3) initialise security (reads level from security_policy.yaml) ──
        self.security_init(certs_dir=certs_dir)
        # ─────────────────────────────────────────────────────────────────────

        # ── (4) create a secure publisher ────────────────────────────────────
        # BEFORE: self._pub = self.create_publisher(String, '/security/chatter', 10)
        self._pub = self.create_secure_publisher('/chatter', String)
        # ─────────────────────────────────────────────────────────────────────

        self._seq = 0
        self.create_timer(1.0, self._publish)
        self.get_logger().info(
            'demo_publisher ready  level={}'.format(self._sec.level.value)
        )

    def _publish(self):
        self._seq += 1
        msg = String(data='Hello #{}'.format(self._seq))

        # ── (5) publish through the mixin ────────────────────────────────────
        # BEFORE: self._pub.publish(msg)
        self.secure_publish(self._pub, msg)
        # ─────────────────────────────────────────────────────────────────────

        self.get_logger().info('Publishing: {}'.format(msg.data))


def main(args=None):
    rclpy.init(args=args)
    node = DemoPublisher()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
