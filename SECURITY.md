# Using `ros2_security` in your project

This document explains how to add the `ros2_security` middleware to a ROS2
project — either a brand new one or an existing one that already publishes and
subscribes on plain ROS2 topics. It assumes ROS2 Humble is installed and
`source /opt/ros/humble/setup.bash` has been run.

The middleware provides three things on top of standard ROS2 topics:

- **Authentication** — every message carries the sender's identity (node CN) and
  an RSA-PSS signature verified against a shared Certificate Authority.
- **Authorization** — each subscription declares a `min_level` and drops any
  message ranked below it (mixed-trust topologies are explicit, not accidental).
- **Optional encryption** — AES-256-GCM confidentiality on top of the signature
  for topics that require it.

Security is opt-in per node via a mixin, with a global kill switch
(`ROS2_SECURITY_DISABLED=1`) that degrades the whole graph to native ROS2.

---

## 1. Add the packages to your workspace

Drop `ros2_security_msgs/`, `ros2_security/`, `scripts/`, `config/` and
`nodes/` into the `src/` directory of your colcon workspace (alongside your own
packages). A common layout:

```
your_ws/
  src/
    ros2_security_msgs/      # SecureEnvelope.msg (ament_cmake)
    ros2_security/           # mixin + policy loader + CLI tools (ament_python)
    scripts/                 # generate_certs.sh
    config/                  # security_policy.yaml (system posture)
    nodes/                   # legacy_relay.py (runnable template)
    your_package/            # your own ROS2 package(s)
```

Then declare a dependency on the two packages in your own `package.xml`:

```xml
<exec_depend>ros2_security</exec_depend>
<exec_depend>ros2_security_msgs</exec_depend>
```

## 2. Build

Build order matters — the message package first, because `ros2_security`
imports `SecureEnvelope` at runtime.

```bash
source /opt/ros/humble/setup.bash

colcon build --packages-select ros2_security_msgs
source install/setup.bash

colcon build --packages-select ros2_security
source install/setup.bash

# Then your own package
colcon build --packages-select your_package
source install/setup.bash
```

System dependencies (installed once per machine):

```bash
sudo apt install python3-cryptography python3-yaml openssl
```

## 3. Generate certificates

Each secured node needs its own RSA keypair and an X.509 certificate signed by
a shared Certificate Authority. The certificate `CN` **must equal** the ROS2
node name returned by `Node.get_name()`.

Run once per deployment. Pass every node name that will participate at a
non-`NONE` security level:

```bash
./scripts/generate_certs.sh camera_node lidar_node planner_node
```

Output (default `./certs/`, override with `CERTS_DIR=/path ./scripts/generate_certs.sh ...`):

```
certs/
  ca.crt   ca.key            # CA — keep ca.key OFFLINE in production
  camera_node.crt camera_node.key
  lidar_node.crt  lidar_node.key
  planner_node.crt planner_node.key
```

The CA is created on the first invocation and reused on subsequent runs — you
can add nodes incrementally without re-issuing existing certs.

> **Never commit private keys.** Add `certs/` (or whatever directory you pass
> via `CERTS_DIR`) to `.gitignore`. Distribute `ca.crt` and each node's
> `<node>.crt` / `<node>.key` to the machine that runs that node only.

## 4. Write the security policy

`config/security_policy.yaml` is the system-wide, auditable source of truth
for who publishes at what level and what each subscription minimally accepts.
It is read once at `security_init()` time.

Three valid level strings: `none`, `sign`, `sign+encrypt`.

```yaml
# config/security_policy.yaml
global_min_level: none    # floor for any node/subscription not listed below

nodes:
  camera_node:
    publish_level: sign+encrypt          # this node's wrap() level
    subscriptions:
      /control/commands:
        min_level: sign                  # accept sign OR sign+encrypt

  planner_node:
    publish_level: sign
    subscriptions:
      /camera/frame:
        min_level: sign
      /lidar/scan:
        min_level: sign
      /diagnostics:
        min_level: none                  # accept unsigned/legacy traffic
```

Policy file resolution at runtime (highest wins):

1. Explicit `policy_path=...` argument to `security_init`
2. `ROS2_SECURITY_POLICY` environment variable
3. `./config/security_policy.yaml` (relative to the working directory)

If the file is missing the loader logs a warning and behaves as
`global_min_level: none` — i.e. no policy is enforced. Make sure your launch
files set `ROS2_SECURITY_POLICY` (or run from a directory where the relative
path resolves correctly) in production.

## 5. Secure a new node

Three modifications turn a plain `rclpy` node into a secured one:

```python
import rclpy
from rclpy.node import Node
from std_msgs.msg import String

# (1) import the mixin and the level enum
from ros2_security import SecureNodeMixin, SecurityLevel


# (2) add SecureNodeMixin as the FIRST base class
class MyPublisher(SecureNodeMixin, Node):

    def __init__(self):
        super().__init__('my_publisher')          # name MUST match cert CN

        self.declare_parameter('certs_dir', './certs')
        certs_dir = self.get_parameter('certs_dir').value

        # (3a) initialise security (reads publish_level from policy file)
        self.security_init(certs_dir=certs_dir)

        # (3b) create a SECURE publisher (returns a Publisher[SecureEnvelope])
        self._pub = self.create_secure_publisher('/chatter', String)

        self.create_timer(1.0, self._tick)

    def _tick(self):
        msg = String(data='hello')
        # (3c) publish through the mixin (wrap → sign → optionally encrypt)
        self.secure_publish(self._pub, msg)


def main():
    rclpy.init()
    node = MyPublisher()
    rclpy.spin(node)
    node.destroy_node()
    rclpy.shutdown()
```

A subscriber follows the same pattern. The callback signature is unchanged —
the mixin verifies, decrypts, deserializes, and only then invokes the callback
with the typed inner message:

```python
class MySubscriber(SecureNodeMixin, Node):

    def __init__(self):
        super().__init__('my_subscriber')         # name MUST match cert CN
        self.security_init(certs_dir='./certs')

        # min_level=None means "read from the policy file"
        self.create_secure_subscription(
            '/chatter', String, self._on_message,
            min_level=None,
        )

    def _on_message(self, msg: String):           # plain typed message
        self.get_logger().info(f'got: {msg.data}')
```

## 6. Migrate an existing node

The diff between a plain node and a secured one is mechanical. For each node
you want to secure:

| Before (plain ROS2)                          | After (secured)                                                     |
| -------------------------------------------- | ------------------------------------------------------------------- |
| `class N(Node):`                             | `class N(SecureNodeMixin, Node):` &nbsp;&nbsp;(mixin **first**)     |
| *(nothing)*                                  | `self.security_init(certs_dir=...)` in `__init__`                   |
| `self.create_publisher(T, topic, qos)`       | `self.create_secure_publisher(topic, T, qos)`                       |
| `pub.publish(msg)`                           | `self.secure_publish(pub, msg)`                                     |
| `self.create_subscription(T, topic, cb, qos)`| `self.create_secure_subscription(topic, T, cb, min_level=None, qos)`|

Then for every migrated node:

1. Add an entry under `nodes:` in `config/security_policy.yaml` with the
   intended `publish_level` and per-topic `min_level`s.
2. Mint a certificate whose `CN` equals the node's `get_name()`:
   `./scripts/generate_certs.sh <node_name>`.
3. Make sure the launch file (or `ros2 run` invocation) sets `name=` to the
   same string, and points `certs_dir` / `ROS2_SECURITY_POLICY` at the right
   files.

Migration can be **incremental**: as long as the unmigrated nodes publish on
topics with `min_level: none`, or you bridge them via the legacy relay (see
section 9), they keep working while you convert the rest.

## 7. Security levels

| Level             | Wire format                            | Guarantees                                                   |
| ----------------- | -------------------------------------- | ------------------------------------------------------------ |
| `none`            | CDR payload inside `SecureEnvelope`    | None. Sender field is informational only — no verification.  |
| `sign`            | CDR payload + RSA-PSS over the payload | Authenticity + integrity. Payload is **visible** on the wire.|
| `sign+encrypt`    | AES-256-GCM ciphertext + RSA-PSS over the ciphertext | Confidentiality + authenticity. Verify-before-decrypt (no decrypt oracle). |

Each subscription's `min_level` is enforced by `level_rank`:
`none (0) < sign (1) < sign+encrypt (2)`. A subscriber with `min_level=sign`
accepts both `sign` and `sign+encrypt` traffic and drops `none`. The drop
happens silently apart from a `[SECURITY]` warning log.

`unwrap` returns `None` on **any** failure — bad signature, replay, unknown
sender, decrypt error, or level-gate drop — and the message is discarded. The
caller never sees an exception.

## 8. Kill switch

Set the environment variable **before** any of your nodes import `ros2_security`:

```bash
export ROS2_SECURITY_DISABLED=1
```

Effects:

- `SECURITY_ENABLED` (a module-level bool in `security_manager.py`, evaluated
  once at import) becomes `False`.
- `create_secure_publisher` returns a native `Publisher[T]`, not
  `Publisher[SecureEnvelope]`.
- `secure_publish` calls `publisher.publish(msg)` directly.
- `create_secure_subscription` returns a native `Subscription[T]` wired straight
  to your callback.
- No policy file is read; no certs are loaded.

Standard ROS2 tooling (`ros2 topic echo`, `rqt_graph`, bagging) works as
normal because the wire types are native.

> **Apply the kill switch uniformly to ALL nodes.** A mixed state — one node
> publishing `SecureEnvelope`, another expecting `std_msgs/String` on the same
> topic — produces a DDS type mismatch and the nodes will silently fail to
> connect. In a launch file, use `SetEnvironmentVariable` at the
> `LaunchDescription` level so every spawned child inherits it before its
> Python import runs (see section 10).

## 9. Bridging unmigrated / third-party nodes

If a node cannot be modified (binary-only, third-party, or simply not migrated
yet), use the **legacy relay**. It subscribes to a native topic and republishes
each message as a `NONE`-level `SecureEnvelope` on a secured topic — no cert
needed for the relay itself.

CLI form:

```bash
ros2 run ros2_security legacy_relay \
    --bridge std_msgs/msg/String /diagnostics_raw /diagnostics
```

You can pass `--bridge` multiple times to bridge several topics from one relay
process. A subscriber with `min_level=none` will accept the relayed traffic; a
subscriber with `min_level=sign` will drop it (the trust boundary is enforced
by the subscriber, with no changes needed upstream).

### Vouching for legacy traffic

To **vouch** for the legacy node's traffic at a higher level, raise the relay to
`sign` (or `sign+encrypt`) and give it its own cert (`legacy_relay.key`/`.crt`) —
it then re-signs the wrapped payload at its own identity, so a subscriber
requiring `min_level=sign` accepts the relayed traffic. No subclassing needed;
pass `--level` (and `--certs-dir`):

```bash
ros2 run ros2_security legacy_relay --level sign --certs-dir ./certs \
    --bridge std_msgs/msg/String /diagnostics_raw /diagnostics
```

The library form (`LegacyRelayNode` in `ros2_security/legacy_relay.py`) takes the
matching `level=`, `certs_dir=`, and `policy_path=` constructor arguments (all
defaulting to the `none`/no-cert behavior above). Pass `level=None` to let the
policy file drive it.

### Reverse direction: exiting the trusted graph (`secure → native`)

The symmetric case — feeding *trusted* traffic to an unmigrated or third-party
subscriber — is the same node with `--direction outbound`. It subscribes to the
secured topic, verifies/decrypts it, and republishes the typed inner message on
a plain native topic. Verifying signatures requires a non-`none` `--level` (so
the relay loads certs); `--min-level` gates which inbound traffic is allowed
through (defaulting to the policy file):

```bash
ros2 run ros2_security legacy_relay --direction outbound \
    --level sign --certs-dir ./certs --min-level sign \
    --bridge std_msgs/msg/String /diagnostics_native /diagnostics
```

In the bridge triple the `NATIVE_TOPIC SECURE_TOPIC` order is unchanged; only the
flow direction flips (secured `/diagnostics` → native `/diagnostics_native`).
The library form takes `direction='outbound'` and `min_level=` arguments.

## 10. Launch files

A typical launch file declares a `certs_dir` argument, propagates the kill
switch via `SetEnvironmentVariable`, and starts each node with the `name=` that
matches its cert CN and its policy entry.

```python
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, SetEnvironmentVariable
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    certs_dir_arg = DeclareLaunchArgument('certs_dir', default_value='./certs')
    security_disabled_arg = DeclareLaunchArgument('security_disabled', default_value='0')

    # Propagate ROS2_SECURITY_DISABLED to every child process BEFORE its
    # Python import runs. Do NOT use additional_env on individual Node actions —
    # that risks a mixed state.
    set_kill_switch = SetEnvironmentVariable(
        name='ROS2_SECURITY_DISABLED',
        value=LaunchConfiguration('security_disabled'),
    )

    camera = Node(
        package='your_package',
        executable='camera_node',
        name='camera_node',                    # MUST match cert CN + policy
        parameters=[{'certs_dir': LaunchConfiguration('certs_dir')}],
        output='screen',
    )

    return LaunchDescription([
        certs_dir_arg,
        security_disabled_arg,
        set_kill_switch,
        camera,
    ])
```

Run:

```bash
ros2 launch your_package your_launch.py certs_dir:=/abs/path/to/certs
ros2 launch your_package your_launch.py security_disabled:=1     # kill switch
```

## 11. Debugging — `secure_echo`

Plain `ros2 topic echo` on a secured topic shows only the raw `SecureEnvelope`
(level, sender, hex-encoded payload). To verify and decode the inner message:

```bash
ros2 run ros2_security secure_echo \
    --topic /camera/frame \
    --type sensor_msgs/msg/Image \
    --certs-dir ./certs
```

`secure_echo` loads the full trusted cert set and can decode any level
including `sign+encrypt`. Use `--min-level sign` to make it ignore unsigned
traffic on the topic.

## 12. Conventions and gotchas

Read these before writing or editing code that touches the mixin or crypto.

- **MRO matters.** `class N(SecureNodeMixin, Node)` is correct;
  `class N(Node, SecureNodeMixin)` shadows the mixin's methods. The mixin must
  come first.
- **Node name == cert CN == policy key.** All three strings must agree. If
  `get_name()` is `camera_node`, you need `certs/camera_node.{key,crt}` and a
  `nodes.camera_node:` entry in the policy.
- **`security_init` is idempotent.** A second call is a no-op (guarded by
  `hasattr(self, '_sec')`), so lifecycle reconfigure is safe.
- **Defaults are `None`, not a level.** `security_init(level=None)` and
  `create_secure_subscription(min_level=None)` mean "read from the policy
  file". Pass an explicit `SecurityLevel.XXX` only when you want to override
  the policy for a single node or subscription.
- **A `NONE`-level subscriber can still receive `NONE` traffic** (fast path,
  no signature check, no cert lookup) and can still *drop* higher-required
  traffic via the level gate. The gate runs before the cert lookup, so no
  certs are required for a pure-NONE subscriber.
- **A subscriber that must verify signatures has to load certs**, which only
  happens when its own `security_init(level=...)` is non-`NONE`. If you want a
  subscriber to enforce `min_level=sign` on inbound traffic, give it a non-NONE
  `publish_level` in the policy (or pass an explicit level to `security_init`)
  so the cert trust set actually loads.
- **`AES key is derived from the PUBLIC key DER on both sides.**
  `_aes_key_from_public_key` uses `SHA-256(public_key_DER)` for encrypt and
  decrypt — the public cert is the only material both parties share. Do not
  "fix" this to use the private key; it breaks the round-trip.
- **The kill switch is evaluated at import time, not per call.** Changing
  `ROS2_SECURITY_DISABLED` after the process has imported `ros2_security` has
  no effect on that process. Set it in the launch environment.
- **`SecureEnvelope` is imported lazily** inside the wrap/unwrap and the
  mixin's enabled paths — importing `ros2_security` under the kill switch
  never pulls in `ros2_security_msgs`.

## 13. Public API summary

```python
from ros2_security import (
    SecureNodeMixin,    # mixin: security_init, create_secure_publisher,
                        #        secure_publish, create_secure_subscription
    SecurityManager,    # per-node crypto (wrap/unwrap), normally used via mixin
    SecurityLevel,      # NONE | SIGN_ONLY | SIGN_ENCRYPT
    SECURITY_ENABLED,   # module-level bool, False when kill switch is set
)
```

CLI entry points (provided by the `ros2_security` package):

```bash
ros2 run ros2_security secure_echo    --topic ... --type ...
ros2 run ros2_security legacy_relay   --bridge TYPE NATIVE_TOPIC SECURE_TOPIC
```
