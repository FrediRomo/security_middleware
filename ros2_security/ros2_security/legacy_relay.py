"""Relay node: bridges a legacy node's native topic into the secured graph.

The legacy node is completely untouched -- suitable for binary-only or
third-party nodes.  The relay subscribes to the legacy *native* topic and
republishes each message as a ``NONE``-level ``SecureEnvelope`` on the secured
topic.  No certificate is required (the relay operates at ``SecurityLevel.NONE``).

A single relay instance can bridge multiple (native_topic -> secure_topic) pairs.

Run directly::

    ros2 run ros2_security legacy_relay
"""

import importlib

import rclpy
from rclpy.node import Node

from .secure_node_mixin import SecureNodeMixin
from .security_manager import SecurityLevel


class LegacyRelayNode(SecureNodeMixin, Node):
    """Bridge one or more native topics into the secured topic graph.

    Parameters
    ----------
    bridges:
        Iterable of ``(msg_type, native_topic, secure_topic)`` tuples.  ``msg_type``
        is the ROS2 message class to relay.  Topic names are NOT hardcoded.
    node_name:
        Node name (must match a cert CN only if a non-NONE level is ever used;
        for the default NONE level no cert is needed).
    """

    def __init__(self, bridges, node_name="legacy_relay"):
        super().__init__(node_name)
        self.security_init(level=SecurityLevel.NONE)

        self._pubs = {}
        for msg_type, native_topic, secure_topic in bridges:
            pub = self.create_secure_publisher(secure_topic, msg_type)
            self._pubs[secure_topic] = pub
            # Bind the publisher into the native subscription callback.
            self.create_subscription(
                msg_type,
                native_topic,
                self._make_relay_cb(pub),
                10,
            )
            self.get_logger().info(
                "Relaying {} -> {} (NONE level)".format(native_topic, secure_topic)
            )

    def _make_relay_cb(self, pub):
        def _relay(msg):
            self.secure_publish(pub, msg)
        return _relay


def _import_msg_type(type_str):
    """Resolve ``pkg/msg/Type`` (or ``pkg.msg.Type``) into the message class."""
    parts = type_str.replace("/", ".").split(".")
    if len(parts) == 3:
        pkg, sub, name = parts
    elif len(parts) == 2:
        pkg, name = parts
        sub = "msg"
    else:
        raise ValueError("Bad message type string: {!r}".format(type_str))
    module = importlib.import_module("{}.{}".format(pkg, sub))
    return getattr(module, name)


def main(args=None):
    """CLI entry point.

    Example::

        ros2 run ros2_security legacy_relay \\
            --bridge std_msgs/msg/String /diagnostics_raw /diagnostics
    """
    import argparse

    parser = argparse.ArgumentParser(description="Legacy -> secured topic relay.")
    parser.add_argument(
        "--bridge",
        nargs=3,
        action="append",
        metavar=("TYPE", "NATIVE_TOPIC", "SECURE_TOPIC"),
        help="Add a bridge, e.g. --bridge std_msgs/msg/String /diag_raw /diagnostics",
    )
    parser.add_argument("--node-name", default="legacy_relay")
    parsed = parser.parse_args(args=args)

    if not parsed.bridge:
        parser.error("at least one --bridge is required")

    bridges = [
        (_import_msg_type(t), native, secure) for t, native, secure in parsed.bridge
    ]

    rclpy.init(args=args)
    node = LegacyRelayNode(bridges, node_name=parsed.node_name)
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
