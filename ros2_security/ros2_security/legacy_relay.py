"""Relay node: bridges native topics across the secured-graph trust boundary.

The bridged node is completely untouched -- suitable for binary-only or
third-party nodes.  A single relay instance can bridge multiple topic pairs and
crosses the boundary in one of two ``direction`` modes:

``inbound`` (default, native -> secure)
    Subscribe to a legacy *native* topic and republish each message as a
    ``SecureEnvelope`` on the secured topic.  At the default ``NONE`` level no
    certificate is required.  Raise the relay's own ``level`` (with a cert) to
    **vouch** for the legacy traffic -- it then re-signs at its own identity so
    subscribers requiring ``sign``/``sign+encrypt`` will accept it.

``outbound`` (secure -> native)
    Subscribe to a secured topic (verifying / decrypting per ``min_level``) and
    republish the typed inner message on a *native* topic, so an unmigrated or
    third-party subscriber can consume trusted traffic.  Verifying signatures
    requires the relay to load certs, which only happens when ``level`` is
    non-``NONE``.

Run directly::

    ros2 run ros2_security legacy_relay
"""

import importlib

import rclpy
from rclpy.node import Node

from .secure_node_mixin import SecureNodeMixin
from .security_manager import SecurityLevel


class LegacyRelayNode(SecureNodeMixin, Node):
    """Bridge one or more native topics across the secured-graph trust boundary.

    Parameters
    ----------
    bridges:
        Iterable of ``(msg_type, native_topic, secure_topic)`` tuples.  ``msg_type``
        is the ROS2 message class to relay.  Topic names are NOT hardcoded.  The
        tuple shape is identical for both directions -- only the data-flow
        direction flips.
    node_name:
        Node name.  Must match a cert CN whenever ``level`` is non-``NONE``
        (i.e. when vouching inbound or verifying outbound); for the default
        ``NONE`` level no cert is needed.
    direction:
        ``"inbound"`` (default) relays native -> secure; ``"outbound"`` relays
        secure -> native.
    level:
        The relay's own publish/identity level (defaults to ``SecurityLevel.NONE``
        -- the original no-cert behavior).  Set to a non-``NONE`` level (with a
        matching ``<node_name>.{key,crt}`` in ``certs_dir``) to vouch for inbound
        traffic or to verify outbound traffic.  Pass ``None`` to let the policy
        file drive it.
    certs_dir:
        Directory holding the CA + per-node certs (only loaded when ``level`` is
        non-``NONE``).
    policy_path:
        Explicit ``security_policy.yaml`` path; ``None`` uses the standard
        resolution (``ROS2_SECURITY_POLICY`` env > ``./config/security_policy.yaml``).
    min_level:
        Outbound only -- the minimum security level inbound secured traffic must
        meet to be re-published natively.  ``None`` (default) reads it from the
        policy file, matching ``create_secure_subscription``.  Ignored inbound.
    """

    def __init__(self, bridges, node_name="legacy_relay",
                 direction="inbound",
                 level=SecurityLevel.NONE,
                 certs_dir="./certs",
                 policy_path=None,
                 min_level=None):
        super().__init__(node_name)
        self.security_init(level=level, certs_dir=certs_dir, policy_path=policy_path)

        self._pubs = {}
        if direction == "inbound":
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
                    "Relaying {} -> {} (native->secure)".format(
                        native_topic, secure_topic)
                )
        elif direction == "outbound":
            for msg_type, native_topic, secure_topic in bridges:
                pub = self.create_publisher(msg_type, native_topic, 10)
                self._pubs[native_topic] = pub
                # Bind the native publisher into the verified secure callback.
                self.create_secure_subscription(
                    secure_topic,
                    msg_type,
                    self._make_native_cb(pub),
                    min_level=min_level,
                )
                self.get_logger().info(
                    "Relaying {} -> {} (secure->native)".format(
                        secure_topic, native_topic)
                )
        else:
            raise ValueError(
                "direction must be 'inbound' or 'outbound', got {!r}".format(direction)
            )

    def _make_relay_cb(self, pub):
        def _relay(msg):
            self.secure_publish(pub, msg)
        return _relay

    def _make_native_cb(self, pub):
        # create_secure_subscription already verifies/decrypts and hands us the
        # typed inner message, so re-publishing it natively is all that's left.
        def _to_native(msg):
            pub.publish(msg)
        return _to_native


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

    Examples::

        # inbound (native -> secure), no cert (default)
        ros2 run ros2_security legacy_relay \\
            --bridge std_msgs/msg/String /diagnostics_raw /diagnostics

        # inbound vouching: re-sign at the relay's own identity
        ros2 run ros2_security legacy_relay --level sign --certs-dir ./certs \\
            --bridge std_msgs/msg/String /diagnostics_raw /diagnostics

        # outbound (secure -> native), verifying signatures first
        ros2 run ros2_security legacy_relay --direction outbound \\
            --level sign --certs-dir ./certs \\
            --bridge std_msgs/msg/String /diagnostics /diagnostics_native
    """
    import argparse

    levels = [lvl.value for lvl in SecurityLevel]

    parser = argparse.ArgumentParser(description="Secured-graph trust-boundary relay.")
    parser.add_argument(
        "--bridge",
        nargs=3,
        action="append",
        metavar=("TYPE", "NATIVE_TOPIC", "SECURE_TOPIC"),
        help="Add a bridge, e.g. --bridge std_msgs/msg/String /diag_raw /diagnostics",
    )
    parser.add_argument("--node-name", default="legacy_relay")
    parser.add_argument(
        "--direction",
        choices=("inbound", "outbound"),
        default="inbound",
        help="inbound: native->secure (default); outbound: secure->native",
    )
    parser.add_argument(
        "--level",
        choices=levels,
        default=SecurityLevel.NONE.value,
        help="The relay's own identity level (default: none). Non-none requires "
             "a matching <node-name>.{key,crt} in --certs-dir.",
    )
    parser.add_argument("--certs-dir", default="./certs")
    parser.add_argument(
        "--policy-path",
        default=None,
        help="Explicit security_policy.yaml path (default: standard resolution).",
    )
    parser.add_argument(
        "--min-level",
        choices=levels,
        default=None,
        help="Outbound only: minimum level inbound secured traffic must meet "
             "(default: read from policy).",
    )
    parsed = parser.parse_args(args=args)

    if not parsed.bridge:
        parser.error("at least one --bridge is required")

    bridges = [
        (_import_msg_type(t), native, secure) for t, native, secure in parsed.bridge
    ]
    min_level = SecurityLevel(parsed.min_level) if parsed.min_level is not None else None

    rclpy.init(args=args)
    node = LegacyRelayNode(
        bridges,
        node_name=parsed.node_name,
        direction=parsed.direction,
        level=SecurityLevel(parsed.level),
        certs_dir=parsed.certs_dir,
        policy_path=parsed.policy_path,
        min_level=min_level,
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
