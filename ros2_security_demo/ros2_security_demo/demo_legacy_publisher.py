"""Legacy publisher — a plain ROS2 node with no security at all.

This represents a node that cannot be modified: a third-party binary, a
compiled C++ node, or simply a node that has not been migrated yet.  It
publishes ``std_msgs/String`` as a raw native message on ``/legacy/chatter``.

No ros2_security imports, no mixin, no SecureEnvelope.  When security is
active in the rest of the system, the only way to bring this node's traffic
into the secured graph is via a relay (see demo_relay.py).

Run
---
ros2 run ros2_security_demo demo_legacy_publisher
"""

import rclpy
from rclpy.node import Node
from std_msgs.msg import String


class DemoLegacyPublisher(Node):
    """Minimal plain publisher — no security layer whatsoever."""

    def __init__(self):
        super().__init__('demo_legacy_publisher')

        self._pub = self.create_publisher(String, '/legacy/chatter', 10)
        self._seq = 0
        self.create_timer(1.0, self._publish)
        self.get_logger().info('demo_legacy_publisher ready (no security)')

    def _publish(self):
        self._seq += 1
        msg = String(data='[LEGACY] Hello #{}'.format(self._seq))
        self._pub.publish(msg)
        self.get_logger().info('Publishing: {}'.format(msg.data))


def main(args=None):
    rclpy.init(args=args)
    node = DemoLegacyPublisher()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
