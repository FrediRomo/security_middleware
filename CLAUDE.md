# CLAUDE.md

Guidance for working in this repository. Keep this file current when commands,
layout, or the conventions below change.

## What this is

A thin **authentication / authorization / optional-encryption middleware** layer
on top of standard ROS2 topics — no DDS-Security, no SROS2. Opt-in per node via a
mixin, with a global kill switch, per-node security profiles, and mixed-trust
topologies. Messages travel as a custom `SecureEnvelope` carrying CDR-serialized
typed payloads (not JSON, not `std_msgs/String`).

Two colcon packages:
- `ros2_security_msgs` — `ament_cmake`, defines `SecureEnvelope.msg`.
- `ros2_security` — `ament_python`, the library + CLI tools.

## Build & test

ROS2 Humble must be sourced first. Build order matters — the msg package first.

```bash
source /opt/ros/humble/setup.bash
colcon build --packages-select ros2_security_msgs
source install/setup.bash
colcon build --packages-select ros2_security
source install/setup.bash
```

Run tests (run colcon build for `ros2_security_msgs` at least once first, and
source `install/setup.bash`, or the crypto/integration tests can't construct
`SecureEnvelope`):

```bash
# Unit tests — no running ROS graph needed (still needs msgs built + sourced)
pytest tests/test_policy_loader.py tests/test_security_manager.py tests/test_kill_switch.py -v

# Full suite incl. ROS2 integration + live DDS delivery
pytest tests/ -v
```

`git` note: the repo root is `/root/ros2_ws` (the working dir is a subfolder). If
git complains about dubious ownership: `git config --global --add safe.directory
/root/ros2_ws`. Current branch is `security`; main is `master`.

## Layout

```
ros2_security_msgs/        msg/SecureEnvelope.msg  (ament_cmake)
ros2_security/             ament_python package
  ros2_security/           THE MODULE (nested, not flat — see note below)
    security_manager.py    SECURITY_ENABLED, SecurityLevel, SecurityManager (crypto)
    policy_loader.py       SecurityPolicyLoader (reads security_policy.yaml)
    secure_node_mixin.py   SecureNodeMixin (drop-in for rclpy nodes)
    secure_echo.py         `ros2 run ros2_security secure_echo`  entry point
    legacy_relay.py        `ros2 run ros2_security legacy_relay` entry point + LegacyRelayNode
config/security_policy.yaml  system-wide posture (the auditable source of truth)
scripts/generate_certs.sh    CA + per-node cert minting (run once per deployment)
nodes/legacy_relay.py        runnable shim -> ros2_security.legacy_relay:main
tools/secure_echo.py         runnable shim -> ros2_security.secure_echo:main
tests/                       conftest + 5 test files
certs/                       GENERATED, gitignored — never commit private keys
```

> **Why the module is nested** (`ros2_security/ros2_security/`): the original
> spec drew a flat tree, but `colcon build` + `ros2 run` require a real
> `ament_python` package. Import paths are unchanged: `from ros2_security import
> SecureNodeMixin, SecurityManager, SecurityLevel`.

## Architecture / how it works

- **Kill switch:** `SECURITY_ENABLED = os.environ.get("ROS2_SECURITY_DISABLED",
  "0") != "1"` — a module-level bool evaluated **once at import time** in
  `security_manager.py`. When disabled, every mixin method publishes/subscribes
  the **native** message type directly: no envelope, no crypto, no policy load.
  It must be applied uniformly to all nodes (mixed state = DDS type mismatch).
- **Per-node identity:** each node has its own RSA keypair + X.509 cert signed by
  a shared CA (CN must equal `Node.get_name()`). No shared secret.
- **Three levels** (`SecurityLevel(str, Enum)`): `none` / `sign` (RSA-PSS over CDR
  bytes) / `sign+encrypt` (AES-256-GCM then RSA-PSS over the **ciphertext** —
  verify-before-decrypt, no decrypt oracle).
- **Mixed trust:** each subscription declares a `min_level`; `unwrap` drops
  anything ranked below it via `level_rank`. Publishers and subscribers are
  configured independently.
- **Policy resolution priority** (highest wins): kill switch → explicit code arg
  (`security_init(level=...)`, `create_secure_subscription(min_level=...)`) →
  `security_policy.yaml` → `global_min_level`. So pass `None` to let policy drive.
  Policy path: explicit arg > `ROS2_SECURITY_POLICY` env > `./config/security_policy.yaml`.

## Conventions & gotchas (read before editing crypto/mixin)

- **AES key derivation uses the PUBLIC key DER on both sides.** The spec text was
  self-contradictory (encrypt from private DER, decrypt from public DER — these
  never match). The public cert is the only shared material, so
  `_aes_key_from_public_key` derives `SHA-256(public_key_DER)` for both encrypt
  and decrypt. Do **not** "fix" this back to the private key — it breaks the
  SIGN_ENCRYPT round-trip. Tests `test_unwrap_valid_sign_encrypt` /
  `test_wrap_unwrap_round_trip[sign+encrypt]` guard it.
- **Defaults are `None`, not a level.** `security_init(level=None)` and
  `create_secure_subscription(min_level=None)` mean "read from policy." A
  non-None default would shadow the policy file entirely.
- **A subscriber that must verify signatures has to load certs**, which only
  happens when its own `security_init` level is non-`NONE` (`load()` is a no-op
  for `NONE` / kill switch). A `NONE`-level subscriber can still receive `NONE`
  traffic (fast path, no cert check) and can still *drop* higher-required traffic
  via the mixed-trust gate (gate runs before the cert lookup).
- **`security_init` is idempotent** — guarded by `hasattr(self, '_sec')` (needed
  for lifecycle reconfigure). MRO must be `(SecureNodeMixin, Node)` — mixin first.
- **`SecureEnvelope` is imported lazily** inside `wrap`/`unwrap` and the mixin's
  enabled paths, so importing the library under the kill switch never pulls in
  `ros2_security_msgs` (asserted by `test_no_secureenvelope_import`).
- **`unwrap` returns `None` on *any* failure** (bad sig, replay, unknown sender,
  decrypt error, level gate) — callers log and drop, never raise.
- **`content_type`** is derived as `<pkg>/msg/<ClassName>` from the message class;
  `unwrap` deserializes using the `msg_type` passed by the subscription, not this
  string (the string is for tooling/`secure_echo`).
- **cryptography 3.4.8** is installed (older than the spec's `>=41`) but supports
  everything used. **OpenSSL 3.0** uses random serials and won't emit `ca.srl`
  (harmless; certs verify fine) — don't chase that file.

## Tests — how they're structured

- `test_policy_loader.py`, `test_security_manager.py`, `test_kill_switch.py` —
  pure-ish unit tests, no running ROS graph (security_manager tests still need
  rclpy + built msgs for CDR + `SecureEnvelope`).
- `test_kill_switch.py` sets `ROS2_SECURITY_DISABLED=1` and **reloads** the
  security modules (because `SECURITY_ENABLED` is import-time), then reloads back
  in fixture teardown. Uses a `SimpleNamespace` fake node — no `rclpy.init()`.
- `test_secure_node_mixin.py`, `test_mixed_trust.py` — require the session-scoped
  `ros_context` fixture (real `rclpy.init`). `test_mixed_trust` spins a real
  `SingleThreadedExecutor` and ticks publishers in a loop until delivery or
  timeout (handles DDS discovery latency; "dropped" cases assert no delivery
  within a short timeout).
- `conftest.py`: `ros_context` (session), `test_certs_dir` (session, runs
  `generate_certs.sh`), `policy_file` (function).

## Common tasks

```bash
# Mint certs (CN must match each node's get_name())
./scripts/generate_certs.sh camera_node lidar_node planner_node legacy_relay

# Inspect a secured topic (verifies + decrypts + prints)
ros2 run ros2_security secure_echo --topic /camera/frame --type sensor_msgs/msg/Image

# Bridge a legacy native topic into the secured graph (NONE level, no cert)
ros2 run ros2_security legacy_relay --bridge std_msgs/msg/String /diag_raw /diagnostics

# Disable security globally (native ROS2 everywhere; all standard tooling works)
export ROS2_SECURITY_DISABLED=1
```
