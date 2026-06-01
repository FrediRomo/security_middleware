"""Launch file for the ros2_security demo nodes.

Starts demo_publisher and demo_subscriber with matching security configuration.

Arguments
---------
certs_dir           Path to the cert directory produced by generate_certs.sh.
                    Default: ./certs  (relative to the working directory where
                    ros2 launch is invoked).

security_disabled   Set to '1' to activate the global kill switch
                    (ROS2_SECURITY_DISABLED=1).  Both nodes then publish and
                    subscribe the native std_msgs/String directly — no
                    SecureEnvelope, no crypto, all standard tooling works.
                    Default: '0'  (security active).

Usage
-----
# Security enabled (default) — certs in ./certs:
ros2 launch ros2_security_demo demo.launch.py

# Explicit certs directory:
ros2 launch ros2_security_demo demo.launch.py certs_dir:=/abs/path/to/certs

# Kill switch — native ROS2, no crypto:
ros2 launch ros2_security_demo demo.launch.py security_disabled:=1

Notes
-----
* The kill switch (ROS2_SECURITY_DISABLED) must reach BOTH nodes simultaneously.
  A mixed state — one node with security on, the other off — causes a DDS type
  mismatch (SecureEnvelope vs std_msgs/String) and the nodes will not connect.
  SetEnvironmentVariable is used here so the env var is inherited by every
  process spawned in this launch context before their Python import runs.

* Node names (demo_publisher, demo_subscriber) must match the CN in the
  certificates AND the names listed in config/security_policy.yaml.  Both files
  are checked at security_init() time.

* The security level is NOT hardcoded here.  It is read from security_policy.yaml
  at startup (demo_publisher: sign+encrypt, demo_subscriber: sign+encrypt).
  Pass security_init(level=...) explicitly in the node if you want to override
  the policy for a specific run.
"""

import os

from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, SetEnvironmentVariable
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():

    # ── launch arguments ──────────────────────────────────────────────────────

    certs_dir_arg = DeclareLaunchArgument(
        'certs_dir',
        default_value='./certs',
        description=(
            'Path to the directory containing ca.crt and per-node .key/.crt '
            'files produced by scripts/generate_certs.sh.'
        ),
    )

    security_disabled_arg = DeclareLaunchArgument(
        'security_disabled',
        default_value='0',
        description=(
            "Set to '1' to activate the global kill switch "
            "(ROS2_SECURITY_DISABLED=1).  All nodes degrade to native ROS2 — "
            "no SecureEnvelope, no crypto.  Must be '0' or '1'."
        ),
    )

    # ── kill switch ───────────────────────────────────────────────────────────
    # SetEnvironmentVariable propagates to every child process in this launch
    # context BEFORE they start, so SECURITY_ENABLED is evaluated correctly at
    # Python import time.  This is the only correct way to use the kill switch
    # from a launch file — do NOT use additional_env on individual nodes, as
    # that risks a mixed state (some nodes secured, others not) which causes a
    # DDS type mismatch on the shared topic.
    set_kill_switch = SetEnvironmentVariable(
        name='ROS2_SECURITY_DISABLED',
        value=LaunchConfiguration('security_disabled'),
    )

    # ── nodes ─────────────────────────────────────────────────────────────────

    publisher_node = Node(
        package='ros2_security_demo',
        executable='demo_publisher',
        name='demo_publisher',       # must match CN in certs + policy entry
        output='screen',
        emulate_tty=True,
        parameters=[{
            'certs_dir': LaunchConfiguration('certs_dir'),
        }],
    )

    subscriber_node = Node(
        package='ros2_security_demo',
        executable='demo_subscriber',
        name='demo_subscriber',      # must match CN in certs + policy entry
        output='screen',
        emulate_tty=True,
        parameters=[{
            'certs_dir': LaunchConfiguration('certs_dir'),
        }],
    )

    # ── launch description ────────────────────────────────────────────────────
    # Order matters: arguments and env must be declared before the nodes.

    return LaunchDescription([
        certs_dir_arg,
        security_disabled_arg,
        set_kill_switch,
        publisher_node,
        subscriber_node,
    ])
