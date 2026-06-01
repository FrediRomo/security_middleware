"""Loader for the system-wide ``security_policy.yaml``.

Separates the security posture (who publishes at what level, what each
subscription minimally accepts) from node source code.  Read once at
``security_init()`` time.
"""

import logging
import os

import yaml

from .security_manager import SecurityLevel

_LOG = logging.getLogger("ros2_security.policy")

DEFAULT_POLICY_PATH = "./config/security_policy.yaml"

# Maps the YAML level strings to SecurityLevel. Note the YAML uses the same
# canonical strings as SecurityLevel values ("none" | "sign" | "sign+encrypt").
_VALID_LEVELS = {lvl.value: lvl for lvl in SecurityLevel}


def resolve_policy_path(policy_path=None):
    """Resolve the policy path: explicit arg > env var > default.

    ``ROS2_SECURITY_POLICY`` is consulted only when ``policy_path`` is None.
    """
    if policy_path is not None:
        return policy_path
    return os.environ.get("ROS2_SECURITY_POLICY", DEFAULT_POLICY_PATH)


def _parse_level(value, where):
    """Map a YAML level string to SecurityLevel, raising ValueError on garbage."""
    try:
        return _VALID_LEVELS[value]
    except KeyError:
        raise ValueError(
            "Invalid security level {!r} in policy ({}). "
            "Valid values: none | sign | sign+encrypt".format(value, where)
        )


class SecurityPolicyLoader:
    """Reads and queries ``security_policy.yaml``.

    Failure modes (per spec):
      * file not found   -> warning, behave as ``global_min_level: none``
      * malformed YAML   -> ValueError
      * invalid level    -> ValueError
    """

    def __init__(self, policy_path):
        self.policy_path = policy_path
        self._found = False
        self._global = SecurityLevel.NONE
        self._nodes = {}

        if not policy_path or not os.path.isfile(policy_path):
            _LOG.warning(
                "[SECURITY] Policy file not found at %r -- falling back to "
                "global_min_level=none. No policy is being enforced.",
                policy_path,
            )
            return

        with open(policy_path, "r") as fh:
            try:
                data = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                raise ValueError(
                    "Malformed security policy YAML at {!r}: {}".format(policy_path, exc)
                )

        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(
                "Malformed security policy at {!r}: top-level must be a mapping".format(
                    policy_path
                )
            )

        self._found = True

        global_raw = data.get("global_min_level", "none")
        self._global = _parse_level(global_raw, "global_min_level")

        nodes = data.get("nodes") or {}
        if not isinstance(nodes, dict):
            raise ValueError(
                "Malformed security policy at {!r}: 'nodes' must be a mapping".format(
                    policy_path
                )
            )

        for node_name, node_cfg in nodes.items():
            node_cfg = node_cfg or {}
            pub_raw = node_cfg.get("publish_level", self._global.value)
            pub_level = _parse_level(pub_raw, "nodes.{}.publish_level".format(node_name))

            subs = {}
            sub_cfg = node_cfg.get("subscriptions") or {}
            if not isinstance(sub_cfg, dict):
                raise ValueError(
                    "Malformed security policy at {!r}: "
                    "nodes.{}.subscriptions must be a mapping".format(policy_path, node_name)
                )
            for topic, topic_cfg in sub_cfg.items():
                topic_cfg = topic_cfg or {}
                min_raw = topic_cfg.get("min_level", self._global.value)
                subs[topic] = _parse_level(
                    min_raw, "nodes.{}.subscriptions.{}.min_level".format(node_name, topic)
                )

            self._nodes[node_name] = {"publish_level": pub_level, "subscriptions": subs}

    # ------------------------------------------------------------------
    def publish_level(self, node_name):
        """publish_level for ``node_name``; falls back to global_min_level.

        Returns SecurityLevel.NONE if the policy file was not found.
        """
        node = self._nodes.get(node_name)
        if node is None:
            return self._global
        return node["publish_level"]

    def min_level(self, node_name, topic):
        """min_level for (``node_name``, ``topic``); falls back to global_min_level.

        Returns SecurityLevel.NONE if the node is unlisted or the file is missing.
        """
        node = self._nodes.get(node_name)
        if node is None:
            return self._global
        return node["subscriptions"].get(topic, self._global)
