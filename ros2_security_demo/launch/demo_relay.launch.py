"""Launch file for the legacy-relay bridge demo.

Topology
--------

  demo_legacy_publisher  ──native std_msgs/String──►  /legacy/chatter
                                                              │
                                                       demo_relay
                                                    (LegacyRelayNode,
                                                      NONE-level envelope,
                                                       no cert needed)
                                                              │
                                                       /chatter  (SecureEnvelope, level=none)
                                                       ┌────────────────────────────────────┐
                                               subscriber_open            subscriber_strict
                                             (min_level=none)            (min_level=sign)
                                              RECEIVES ✓                  DROPS ✗
                                        (relay traffic accepted)    (trust boundary enforced)
                                        └────────────────────────────────────────────────────┘

Key points demonstrated
-----------------------
* The legacy node has zero knowledge of ros2_security.  It is untouched.
* The relay wraps traffic in a NONE-level SecureEnvelope (no signing, no cert).
* A subscriber with min_level=none accepts the relay output — full delivery.
* A subscriber with min_level=sign DROPS the relay output — the trust boundary
  is enforced by the subscriber alone, with no changes to publisher or relay.
* To elevate trust, upgrade the relay to SecurityLevel.SIGN_ONLY with its own
  cert; it then vouches for the legacy node's traffic at its own identity.

Arguments
---------
certs_dir           Path to cert directory.  Only the demo_subscriber cert is
                    needed here (the relay runs at NONE level — no cert).
                    Default: ./certs

security_disabled   '1' to activate kill switch (ROS2_SECURITY_DISABLED=1).
                    Both nodes degrade to native ROS2.  Default: '0'.

Usage
-----
# Full relay demo (security on):
ros2 launch ros2_security_demo demo_relay.launch.py certs_dir:=./certs

# With kill switch (native passthrough everywhere):
ros2 launch ros2_security_demo demo_relay.launch.py security_disabled:=1
"""

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
            'Path to cert directory.  Only demo_subscriber.key/.crt are needed '
            '(the relay runs at NONE level and requires no cert).'
        ),
    )

    security_disabled_arg = DeclareLaunchArgument(
        'security_disabled',
        default_value='0',
        description=(
            "Set to '1' to activate the global kill switch "
            "(ROS2_SECURITY_DISABLED=1).  All nodes degrade to native ROS2."
        ),
    )

    # ── kill switch ───────────────────────────────────────────────────────────
    # Must be set uniformly for all nodes — applied via SetEnvironmentVariable
    # so every child process inherits it before Python import time.
    set_kill_switch = SetEnvironmentVariable(
        name='ROS2_SECURITY_DISABLED',
        value=LaunchConfiguration('security_disabled'),
    )

    # ── nodes ─────────────────────────────────────────────────────────────────

    # 1. Legacy publisher — plain Node, no mixin, no security awareness.
    #    Represents a third-party or unmigrated node publishing natively.
    legacy_publisher = Node(
        package='ros2_security_demo',
        executable='demo_legacy_publisher',
        name='demo_legacy_publisher',
        output='screen',
        emulate_tty=True,
    )

    # 2. Relay — bridges /legacy/chatter (native) → /chatter (NONE-level envelope).
    #    Runs at SecurityLevel.NONE so no certificate is required.
    relay_node = Node(
        package='ros2_security_demo',
        executable='demo_relay',
        name='legacy_relay',             # matches policy entry + cert CN
        output='screen',
        emulate_tty=True,
        parameters=[{
            'native_topic': '/legacy/chatter',
            'secure_topic': '/chatter',
            'certs_dir':    LaunchConfiguration('certs_dir'),
        }],
    )

    # 3a. Open subscriber — min_level=none, accepts the NONE-level relay output.
    #     Shows that the relayed traffic reaches the secured graph.
    subscriber_open = Node(
        package='ros2_security_demo',
        executable='demo_subscriber',
        name='demo_subscriber',          # cert CN: demo_subscriber
        output='screen',
        emulate_tty=True,
        parameters=[{
            'certs_dir': LaunchConfiguration('certs_dir'),
            'topic':     '/chatter',
            'min_level': 'none',         # override policy: accept relay output
        }],
    )

    # 3b. Strict subscriber — min_level=sign, drops the NONE-level relay output.
    #     Shows the trust boundary: relay traffic is rejected because it is unsigned.
    #     To accept it, the relay would need to be upgraded to SecurityLevel.SIGN_ONLY
    #     with its own cert, vouching for the legacy node's traffic.
    #
    #     NOTE: this node also uses the demo_subscriber cert (same ROS node name →
    #     same cert lookup).  Two nodes with the same name is valid in ROS2.
    subscriber_strict = Node(
        package='ros2_security_demo',
        executable='demo_subscriber',
        name='demo_subscriber',          # same cert as subscriber_open
        output='screen',
        emulate_tty=True,
        parameters=[{
            'certs_dir': LaunchConfiguration('certs_dir'),
            'topic':     '/chatter',
            'min_level': 'sign',         # override policy: reject unsigned relay
        }],
        prefix='[strict] ',              # distinguish in launch log output
    )

    # ── launch description ────────────────────────────────────────────────────

    return LaunchDescription([
        certs_dir_arg,
        security_disabled_arg,
        set_kill_switch,
        legacy_publisher,
        relay_node,
        subscriber_open,
        subscriber_strict,
    ])
