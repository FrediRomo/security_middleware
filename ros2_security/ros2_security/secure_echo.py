"""CLI debug tool: verify + decode + pretty-print any secured topic.

Subscribes to a secured topic as ``SecureEnvelope``, uses ``SecurityManager``
to verify/decrypt the envelope, deserializes the inner message and prints it.
Works with all security levels including ``SIGN_ENCRYPT``.

Usage::

    ros2 run ros2_security secure_echo --topic /camera/frame --type sensor_msgs/msg/Image
"""

import argparse
import importlib

import rclpy
from rclpy.node import Node

from .security_manager import SecurityLevel, SecurityManager


def _import_msg_type(type_str):
    """Resolve ``pkg/msg/Type`` into the message class."""
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


class SecureEchoNode(Node):
    def __init__(self, topic, msg_type, certs_dir, node_name, min_level):
        super().__init__(node_name)
        self._topic = topic
        self._msg_type = msg_type
        self._min_level = min_level

        self._sec = SecurityManager()
        # Load at SIGN_ENCRYPT so this node owns a key + the full trusted set,
        # enabling verification and decryption of every level.
        self._sec.load(node_name, SecurityLevel.SIGN_ENCRYPT, certs_dir, replay_window=None)

        from ros2_security_msgs.msg import SecureEnvelope
        self.create_subscription(SecureEnvelope, topic, self._on_envelope, 10)
        self.get_logger().info("secure_echo listening on {}".format(topic))

    def _on_envelope(self, envelope):
        typed = self._sec.unwrap(envelope, self._min_level, self._msg_type)
        if typed is None:
            self.get_logger().warning(
                "[SECURITY] could not verify/decode message on {} "
                "(level={}, sender={})".format(self._topic, envelope.level, envelope.sender)
            )
            return
        print("--- {} | level={} sender={} ts={:.3f} ---".format(
            self._topic, envelope.level, envelope.sender, envelope.ts))
        print(typed)


def main(args=None):
    parser = argparse.ArgumentParser(description="Verify + decode a secured topic.")
    parser.add_argument("--topic", required=True)
    parser.add_argument("--type", required=True, help="e.g. sensor_msgs/msg/Image")
    parser.add_argument("--certs-dir", default="./certs")
    parser.add_argument("--node-name", default="secure_echo")
    parser.add_argument(
        "--min-level", default="none", choices=[lvl.value for lvl in SecurityLevel],
        help="minimum level to accept (default: none)")
    parsed = parser.parse_args(args=args)

    msg_type = _import_msg_type(parsed.type)

    rclpy.init(args=args)
    node = SecureEchoNode(
        parsed.topic, msg_type, parsed.certs_dir,
        parsed.node_name, SecurityLevel(parsed.min_level),
    )
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
