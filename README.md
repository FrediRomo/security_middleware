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

## Implementation Examples

### Unsecured Node (Standard ROS2)

A standard ROS2 node with no security:

```python
import rclpy
from rclpy.node import Node
from std_msgs.msg import String

class UnsecuredPublisher(Node):
    def __init__(self):
        super().__init__('publisher_node')
        # Standard ROS2 publisher — no security
        self.publisher = self.create_publisher(String, '/topic', 10)
        self.timer = self.create_timer(1.0, self.timer_callback)

    def timer_callback(self):
        msg = String()
        msg.data = 'Hello, World'
        # Direct native message published to the DDS network
        self.publisher.publish(msg)

if __name__ == '__main__':
    rclpy.init()
    node = UnsecuredPublisher()
    rclpy.spin(node)
```

The message is published as raw CDR (Common Data Representation) bytes over DDS with no encryption, signature, or identity verification. Any node can publish or subscribe to any topic.

### Secured Node Using SecureNodeMixin

A node that uses the `SecureNodeMixin` to add authentication and optional encryption:

```python
import rclpy
from rclpy.node import Node
from std_msgs.msg import String

from ros2_security.secure_node_mixin import SecureNodeMixin
from ros2_security.security_manager import SecurityLevel

class SecuredPublisher(SecureNodeMixin, Node):
    """Node that publishes signed/encrypted messages."""

    def __init__(self):
        super().__init__('camera_node')
        
        # Initialize security: load certificates and set up crypto
        # level=None reads from policy file; explicit level overrides
        self.security_init(
            level=SecurityLevel.SIGN_ENCRYPT,
            certs_dir="./certs",
            policy_path="./config/security_policy.yaml"
        )
        
        # Create a secure publisher (publishes SecureEnvelope, not String)
        self.publisher = self.create_secure_publisher(
            '/camera/frame', String, qos=10
        )
        self.timer = self.create_timer(1.0, self.timer_callback)

    def timer_callback(self):
        msg = String()
        msg.data = 'Encrypted frame data'
        # secure_publish handles serialization, encryption, and signing
        self.secure_publish(self.publisher, msg)

class SecuredSubscriber(SecureNodeMixin, Node):
    """Node that verifies signatures and decrypts messages."""

    def __init__(self):
        super().__init__('planner_node')
        
        # Initialize security
        self.security_init(level=SecurityLevel.SIGN_ENCRYPT)
        
        # Create a secure subscription
        # min_level=None reads from policy; explicit level enforces a minimum
        self.create_secure_subscription(
            '/camera/frame',
            String,
            self.on_message,
            min_level=SecurityLevel.SIGN_ENCRYPT
        )

    def on_message(self, msg):
        # msg is already verified and decrypted; callback receives typed message
        self.get_logger().info(f'Received: {msg.data}')

if __name__ == '__main__':
    rclpy.init()
    node = SecuredPublisher()
    # OR: node = SecuredSubscriber()
    rclpy.spin(node)
```

**How the security layer transforms the message:**

1. **Publisher side** (`secure_publish`):
   - Serializes the `String` message to CDR bytes
   - Generates a random nonce (12 bytes)
   - Encrypts the bytes using AES-256-GCM with the key derived from the node's own public certificate
   - Signs the ciphertext using RSA-PSS (SHA-256) with the node's private key
   - Wraps the result in a `SecureEnvelope` (sender ID, timestamp, signature, encrypted payload, nonce)

2. **Subscriber side** (`create_secure_subscription`):
   - Receives the `SecureEnvelope`
   - Verifies the signature using the sender's public key (loaded from the sender's certificate)
   - Checks that the sender is in the trusted certificate list
   - Enforces `min_level`: rejects messages below the required security level
   - Checks the timestamp against the replay window (default: 30s)
   - Decrypts the payload using AES-256-GCM with the key derived from the sender's public certificate
   - Deserializes the plaintext back to a typed `String` message
   - Calls the application callback with the authenticated, decrypted message

### Legacy Relay: Bridging Secure and Native Topologies

The `LegacyRelayNode` bridges messages between secured and unsecured portions of the system:

```python
from ros2_security.legacy_relay import LegacyRelayNode
from ros2_security.security_manager import SecurityLevel
from std_msgs.msg import String

# Inbound relay: native -> secured, with the relay vouching for legacy traffic
inbound = LegacyRelayNode(
    bridges=[
        (String, '/diagnostics_raw', '/diagnostics'),  # native_topic -> secure_topic
    ],
    node_name='legacy_relay_in',
    direction='inbound',
    level=SecurityLevel.SIGN,  # The relay has a cert and re-signs
    certs_dir='./certs'
)

# Outbound relay: secured -> native, verifying signatures first
outbound = LegacyRelayNode(
    bridges=[
        (String, '/secure_data', '/public_data'),  # secure_topic -> native_topic
    ],
    node_name='legacy_relay_out',
    direction='outbound',
    level=SecurityLevel.SIGN,  # Required to verify signatures
    min_level=SecurityLevel.SIGN,  # Only forward messages signed at SIGN or above
    certs_dir='./certs'
)
```

**Inbound relay workflow** (native → secure):
- Subscribes to a native (unsecured) topic using standard ROS2 subscription
- When a message arrives, it's wrapped and signed at the relay's own identity using `secure_publish`
- Downstream secured subscribers see it as coming from `legacy_relay_in`, not the original untrusted source
- This allows legacy nodes (third-party, binary-only, or unmigrated) to contribute to the secured graph

**Outbound relay workflow** (secure → native):
- Subscribes to a secured topic using `create_secure_subscription` with a `min_level`
- The relay verifies signatures and decrypts before handling the message
- The typed message (already verified) is re-published natively on an unsecured topic
- Allows downstream legacy subscribers to consume trusted traffic without understanding envelopes

### Debug Tool: Secure Echo

For debugging and monitoring encrypted topics without building a full node:

```python
from ros2_security.secure_echo import SecureEchoNode
from ros2_security.security_manager import SecurityLevel
from sensor_msgs.msg import Image

# Create a debug subscriber that loads all certificates and can verify/decrypt
node = SecureEchoNode(
    topic='/camera/frame',
    msg_type=Image,
    certs_dir='./certs',
    node_name='secure_echo',
    min_level=SecurityLevel.SIGN_ENCRYPT  # Only accept encrypted messages
)

# Usage from command line:
# ros2 run ros2_security secure_echo \
#     --topic /camera/frame \
#     --type sensor_msgs/msg/Image \
#     --min-level sign+encrypt \
#     --certs-dir ./certs
```

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
