# ROS2 Custom Security Layer

A thin authentication / authorization / optional-encryption middleware on top of
standard ROS2 topics. No DDS-Security, no SROS2. Opt-in per node, with a global
kill switch, per-node security profiles, and mixed-trust topologies.

## Layout

```
ros2_security_msgs/     custom SecureEnvelope message (ament_cmake)
ros2_security/          the middleware library + CLI tools (ament_python)
  ros2_security/        security_manager, policy_loader, secure_node_mixin,
                        secure_echo, legacy_relay
config/                 security_policy.yaml (system-wide posture)
scripts/                generate_certs.sh (CA + per-node certs)
nodes/                  legacy_relay.py (runnable relay template)
tools/                  secure_echo.py (runnable debug echo template)
tests/                  pytest suite (unit + integration)
```

> The Python source for `ros2_security` lives in the conventional nested
> `ros2_security/ros2_security/` module dir (required for `colcon build` and
> `ros2 run`). This is the only deviation from the flat tree in the spec's
> Section 2; all import paths (`from ros2_security import ...`) are unchanged.

## Build

```bash
colcon build --packages-select ros2_security_msgs
source install/setup.bash
colcon build --packages-select ros2_security
source install/setup.bash
```

## Generate certificates (once per deployment)

```bash
./scripts/generate_certs.sh camera_node lidar_node planner_node legacy_relay
```

## Kill switch

```bash
export ROS2_SECURITY_DISABLED=1   # entire system degrades to native ROS2
```

Apply it before the launch file, uniformly to all nodes — a mixed state
(some `SecureEnvelope`, some native) causes a DDS type mismatch.

## Security modes

| Mode | Guarantees |
|---|---|
| `NONE` | none — CDR payload passed through |
| `SIGN_ONLY` | RSA-PSS signature; integrity + sender identity, payload visible |
| `SIGN_ENCRYPT` | RSA-PSS signature + AES-256-GCM; confidentiality + integrity |

## Tests

```bash
# Unit tests (no running ROS graph; needs ros2_security_msgs built + sourced)
pytest tests/test_policy_loader.py tests/test_security_manager.py tests/test_kill_switch.py -v

# Full suite incl. integration
source /opt/ros/humble/setup.bash && source install/setup.bash
pytest tests/ -v
```

## Note on AES key derivation (spec reconciliation)

Section 7 of the spec describes the *self* AES key as `SHA-256(own private key
DER)` but the *decrypt* key as `SHA-256(sender public key DER)`. Those never
match, so SIGN_ENCRYPT could not round-trip. Since the public certificate is the
only key material both parties share, **both sides derive the symmetric key from
the public key DER** (the sender from its own public key, the receiver from the
sender's cert). See `security_manager._aes_key_from_public_key`.
