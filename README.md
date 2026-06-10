# ROS2 Custom Security Layer

A thin authentication / authorization / optional-encryption middleware on top of
standard ROS2 topics. No DDS-Security, no SROS2. Opt-in per node, with a global
kill switch, per-node security profiles, and mixed-trust topologies.

## Cryptographic Overview

This middleware provides optional encryption and authentication for ROS2 messages using industry-standard cryptographic primitives. Below is an explanation of the cryptographic architecture suitable for those new to cryptography.

### Public Key Infrastructure: Certificates and the CA

**The Role of a Certificate Authority (CA)**: A Certificate Authority is a trusted entity that verifies the identity of nodes and vouches for their authenticity by signing their certificates. In this system, a self-signed CA certificate is generated once during deployment (RSA-4096, valid for 3650 days). This CA certificate is then distributed to all nodes in the system.

**Certificate Structure**: An X.509 certificate is a digital document that cryptographically binds an identity (a node's name) to a public key. It contains:
- The **Common Name (CN)**: the node's identifier (e.g., `camera_node`)
- The **public key**: the node's public cryptographic key (RSA-2048 for node certs)
- The **issuer information**: the CA that signed this certificate
- The **validity period**: the date range during which the certificate is valid (typically 365 days per node)
- The **CA signature**: a cryptographic signature over the entire certificate, proving the CA endorses this node's identity

**Certificate Generation**: When a new node joins the system, it undergoes a three-step process:
1. Generate a unique RSA-2048 private key, kept secret on the node
2. Create a Certificate Signing Request (CSR) containing the node's public key and requested identity (CN)
3. Submit the CSR to the CA, which verifies the request and signs it, producing a certificate

The signed certificate proves that the CA trusts this node's identity and public key pair. During runtime, nodes load the CA's certificate and use it to verify that all peer certificates are legitimate—if verification fails, the peer is untrusted and messages from it are discarded.

### Asymmetric Signing: Authentication and Integrity

**RSA-PSS Signatures**: Each message is signed using RSA-PSS (Probabilistic Signature Scheme) with SHA-256. This asymmetric signature scheme provides two guarantees:
- **Authenticity**: only the holder of the private key could have produced the signature, proving the message came from a specific, identified sender
- **Integrity**: any bit-level tampering with the message invalidates the signature, guaranteeing the message was not altered in transit

The signature process: the message payload is hashed (using SHA-256), then the hash is signed using the sender's private key. The receiver verifies by hashing the same payload and using the sender's *public* key (obtained from the sender's certificate) to check that the signature is valid for that hash. This works because RSA's mathematical properties ensure only the private key holder can create valid signatures, while the public key can verify them.

### Symmetric Encryption: Confidentiality

**AES-256-GCM**: When using the `SIGN_ENCRYPT` security level, message payloads are encrypted with AES-256-GCM (Galois/Counter Mode). AES (Advanced Encryption Standard) is a symmetric cipher—the same key is used for both encryption and decryption—and GCM mode provides both confidentiality (secrecy) and authentication (tamper detection).

**Key Derivation**: Rather than requiring nodes to share a secret key, this system derives the symmetric AES key deterministically from public information: the node's public certificate. Specifically, the AES-256 key is computed as `SHA-256(public_key_DER)`. Both the sender (using its own public key) and any receiver (using the sender's public key from the certificate) derive the exact same key independently. This elegant approach avoids the problem of distributing secret keys while maintaining the confidentiality of encrypted messages.

**Encryption Process**: The sender generates a random 12-byte nonce (number used once) and encrypts the plaintext using AES-256-GCM with the derived key. The nonce ensures that encrypting the same plaintext twice produces different ciphertexts, preventing patterns. The receiver decrypts using the same symmetric key, deriving it from the sender's public certificate.

### Message Protection Flow

**Publish (Encryption Then Signature)**:
1. Serialize the ROS message into bytes
2. If `SIGN_ENCRYPT`: generate a random nonce, encrypt the payload using AES-256-GCM
3. Sign the (encrypted) payload using RSA-PSS with SHA-256, producing a signature
4. Wrap the signature, encrypted payload, nonce, sender identity, and timestamp into a `SecureEnvelope`

**Subscribe (Verify Then Decrypt)**:
1. Verify the signature first (before decryption) using the sender's public key from its certificate—this prevents decrypt-oracle attacks where an attacker could trigger decryption of chosen ciphertexts
2. Check the sender identity is in the trusted certificate list and verify the signature is valid
3. Enforce the mixing level policy: reject messages whose security level is below the subscriber's minimum requirement
4. Check the message timestamp against a replay window (default: 30 seconds) to reject old replayed messages
5. If `SIGN_ENCRYPT`: derive the AES key from the sender's public key and decrypt the payload
6. Deserialize the decrypted bytes back into a typed ROS message

This design—sign-then-encrypt at publish, verify-before-decrypt at subscribe—prevents a class of attacks where an attacker tries to manipulate encrypted data without the secret key.

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
