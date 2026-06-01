"""Drop-in mixin that adds the security layer to any ``rclpy`` Node.

Place the mixin FIRST in the MRO::

    class MyNode(SecureNodeMixin, Node): ...           # correct
    class MyNode(SecureNodeMixin, LifecycleNode): ...   # correct
    class MyNode(Node, SecureNodeMixin): ...            # WRONG -- mixin shadowed

When the global kill switch is active (``ROS2_SECURITY_DISABLED=1``) every
method below degrades to plain ROS2: native message types on the wire, no
envelope, no crypto, no policy loading.
"""

from .policy_loader import SecurityPolicyLoader, resolve_policy_path
from .security_manager import SECURITY_ENABLED, SecurityLevel, SecurityManager


class SecureNodeMixin:
    """Mixin providing secure publisher/subscriber helpers for a Node subclass."""

    def security_init(self,
                      level=None,
                      certs_dir="./certs",
                      policy_path=None,
                      replay_window=30.0):
        """Initialise this node's security context.

        ``level=None`` means "read publish_level from the policy file"; passing
        an explicit ``SecurityLevel`` overrides the policy.  Idempotent: a second
        call (e.g. lifecycle reconfigure) is a no-op.

        Policy path resolution: explicit ``policy_path`` arg > ``ROS2_SECURITY_POLICY``
        env var > ``./config/security_policy.yaml``.
        """
        if hasattr(self, "_sec"):
            return

        if not SECURITY_ENABLED:
            # Kill switch: no policy file is read, no certs loaded. We still
            # build a (cheap) manager so secure_publish has a node_id, but it
            # performs no file I/O. The policy loader is NOT instantiated.
            self._policy_loader = None
            self._sec = SecurityManager()
            self._sec.load(self.get_name(), SecurityLevel.NONE, certs_dir, replay_window)
            return

        loader = SecurityPolicyLoader(resolve_policy_path(policy_path))

        # Explicit arg wins over policy; policy wins over the hardcoded default.
        resolved_level = level if level is not None else loader.publish_level(self.get_name())

        self._policy_loader = loader
        self._sec = SecurityManager()
        self._sec.load(self.get_name(), resolved_level, certs_dir, replay_window)

    # ------------------------------------------------------------------
    def create_secure_publisher(self, topic, msg_type, qos=10):
        """Create a publisher.

        Security enabled  -> ``Publisher[SecureEnvelope]`` (wire type is the envelope).
        Security disabled -> ``Publisher[msg_type]`` (native type, full tooling).
        """
        if not SECURITY_ENABLED:
            return self.create_publisher(msg_type, topic, qos)

        from ros2_security_msgs.msg import SecureEnvelope
        pub = self.create_publisher(SecureEnvelope, topic, qos)
        # Keep the intended inner type around for reference/debugging.
        pub._secure_inner_type = msg_type
        return pub

    def secure_publish(self, publisher, ros_msg):
        """Publish ``ros_msg``.

        Security enabled  -> wrap (serialize/sign/encrypt) then publish the envelope.
        Security disabled -> publish the native message directly.
        """
        if not SECURITY_ENABLED:
            publisher.publish(ros_msg)
            return
        envelope = self._sec.wrap(ros_msg)
        publisher.publish(envelope)

    def create_secure_subscription(self,
                                   topic,
                                   msg_type,
                                   callback,
                                   min_level=None,
                                   qos=10):
        """Create a subscription that enforces ``min_level``.

        Security enabled  -> subscribes to ``SecureEnvelope``; an internal
        ``_secure_cb`` verifies/decodes each message and invokes ``callback``
        with the typed inner message (dropping anything below ``min_level``).
        Security disabled -> native ``msg_type`` subscription wired straight to
        ``callback``; ``min_level`` is ignored.
        """
        if not SECURITY_ENABLED:
            return self.create_subscription(msg_type, topic, callback, qos)

        from ros2_security_msgs.msg import SecureEnvelope

        resolved_min = (
            min_level if min_level is not None
            else self._policy_loader.min_level(self.get_name(), topic)
        )

        def _secure_cb(envelope):
            typed_msg = self._sec.unwrap(envelope, resolved_min, msg_type)
            if typed_msg is None:
                self.get_logger().warning(
                    "[SECURITY] Dropped message on '{}' -- required={}, got={}, "
                    "sender={}".format(
                        topic,
                        SecurityLevel(resolved_min).value,
                        envelope.level,
                        envelope.sender,
                    )
                )
                return
            callback(typed_msg)

        return self.create_subscription(SecureEnvelope, topic, _secure_cb, qos)
