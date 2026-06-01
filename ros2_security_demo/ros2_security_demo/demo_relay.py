"""Demo relay node — bridges a native topic into the secured graph.

Wraps ``LegacyRelayNode`` from ``ros2_security`` and exposes the bridge
configuration as ROS2 parameters so it can be driven from a launch file
without CLI argument hackery.

The node name is ``legacy_relay`` so it matches the entry in
``security_policy.yaml`` and (if certs exist) the corresponding cert CN.
SecurityLevel.NONE means no cert is required — the relay vouches for nothing,
it merely wraps the native payload in an unsigned envelope.

Parameters
----------
native_topic    (string, default "/legacy/chatter")   Source topic (native type).
secure_topic    (string, default "/chatter")          Destination topic (SecureEnvelope).
certs_dir       (string, default "./certs")           Cert directory path.

Run
---
ros2 run ros2_security_demo demo_relay \\
    --ros-args -p native_topic:=/legacy/chatter -p secure_topic:=/chatter
"""

import rclpy
from std_msgs.msg import String

from ros2_security.legacy_relay import LegacyRelayNode
from ros2_security.security_manager import SecurityLevel


class DemoRelay(LegacyRelayNode):
    """Parameter-driven relay: reads bridge config from ROS2 parameters."""

    # Override __init__ so we can declare params before handing off to
    # LegacyRelayNode.  The parent expects (bridges, node_name) positional args;
    # we build those from parameters here.
    def __new__(cls):
        # Instantiate WITHOUT calling __init__ so we can do param setup first.
        return object.__new__(cls)

    def __init__(self):
        # Bootstrap as a plain Node to read parameters.
        import rclpy.node
        rclpy.node.Node.__init__(self, 'legacy_relay')

        self.declare_parameter('native_topic', '/legacy/chatter')
        self.declare_parameter('secure_topic', '/chatter')
        self.declare_parameter('certs_dir',    './certs')

        native  = self.get_parameter('native_topic').value
        secure  = self.get_parameter('secure_topic').value
        certs   = self.get_parameter('certs_dir').value

        # Now initialise security (NONE level — no cert needed for a relay).
        from ros2_security.secure_node_mixin import SecureNodeMixin
        SecureNodeMixin.security_init(self, level=SecurityLevel.NONE,
                                      certs_dir=certs)

        # Wire the bridge: subscribe to native, republish as SecureEnvelope.
        self._pubs = {}
        pub = SecureNodeMixin.create_secure_publisher(self, secure, String)
        self._pubs[secure] = pub
        self.create_subscription(String, native,
                                 self._make_relay_cb(pub), 10)

        self.get_logger().info(
            'demo_relay ready  {} → {}  (level=none)'.format(native, secure)
        )

    def _make_relay_cb(self, pub):
        from ros2_security.secure_node_mixin import SecureNodeMixin
        def _relay(msg):
            SecureNodeMixin.secure_publish(self, pub, msg)
        return _relay


def main(args=None):
    rclpy.init(args=args)
    node = DemoRelay()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
