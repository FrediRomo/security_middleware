"""Per-node cryptographic operations for the ROS2 security layer.

This module is import-safe without a running ROS2 graph: it only needs ``rclpy``
(for CDR (de)serialization) and ``cryptography``.  The custom ``SecureEnvelope``
message type is imported lazily inside :meth:`SecurityManager.wrap` /
:meth:`SecurityManager.unwrap` so that merely importing this module (e.g. when
the global kill switch is active) never pulls in ``ros2_security_msgs``.
"""

import glob
import hashlib
import os
import time
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

# ---------------------------------------------------------------------------
# Global kill switch -- evaluated ONCE at import time, never per-message.
# When ROS2_SECURITY_DISABLED=1, the whole layer degrades to native ROS2.
# ---------------------------------------------------------------------------
SECURITY_ENABLED = os.environ.get("ROS2_SECURITY_DISABLED", "0") != "1"


class SecurityLevel(str, Enum):
    """Security profile for a publish or a subscription.

    Subclasses ``str`` so the value survives a round-trip through the
    ``SecureEnvelope.level`` string field without explicit conversion.
    """

    NONE = "none"
    SIGN_ONLY = "sign"
    SIGN_ENCRYPT = "sign+encrypt"


# Ordering used by the mixed-trust gate: a subscriber accepts any level whose
# rank is >= its own ``min_level`` rank.
level_rank = {
    SecurityLevel.NONE: 0,
    SecurityLevel.SIGN_ONLY: 1,
    SecurityLevel.SIGN_ENCRYPT: 2,
}

# RSA-PSS parameters used everywhere for signing/verification.
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _ros_type_string(msg) -> str:
    """Return the fully-qualified ROS2 type string, e.g. ``sensor_msgs/msg/Image``."""
    cls = type(msg)
    # Standard rclpy message classes live in ``<pkg>.msg._<lower>``.
    pkg = cls.__module__.split(".")[0]
    return "{}/msg/{}".format(pkg, cls.__name__)


def _aes_key_from_public_key(public_key) -> bytes:
    """Derive a deterministic AES-256 key from a public key's DER encoding.

    NOTE on a spec inconsistency: Section 7 says the *self* AES key is
    ``SHA-256(own private key DER)`` while the *decrypt* key is
    ``SHA-256(sender public key DER)``.  Those two never match, so an encrypted
    message could never be decrypted by the receiver.  Because the public
    certificate is the only key material both parties share, BOTH sides derive
    the symmetric key from the *public* key DER -- the sender from its own
    public key, the receiver from the sender's certificate.  This is the only
    choice that makes the SIGN_ENCRYPT round-trip work.
    """
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).digest()


class SecurityManager:
    """One instance per node (not a singleton).

    Constructed by :meth:`SecureNodeMixin.security_init`.
    """

    def __init__(self):
        self.node_id: str = ""
        self.level: SecurityLevel = SecurityLevel.NONE
        self.replay_window = 30.0  # seconds; None disables the replay check
        self._private_key = None  # own RSA private key
        self._aes_key: bytes = b""  # AES-256 key derived from own public key
        self._trusted_certs = {}  # CN -> x509.Certificate

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def load(self, node_id, level, certs_dir="./certs", replay_window=30.0):
        """Load own key + the set of CA-signed trusted certificates.

        No-op (no file I/O) when the kill switch is active or ``level`` is
        ``NONE`` -- a ``NONE`` node needs no certificate.
        """
        self.node_id = node_id
        self.level = SecurityLevel(level)
        self.replay_window = replay_window

        if not SECURITY_ENABLED or self.level == SecurityLevel.NONE:
            return

        # 1. Load own private key (PEM, no password).
        key_path = os.path.join(certs_dir, "{}.key".format(node_id))
        with open(key_path, "rb") as fh:
            self._private_key = serialization.load_pem_private_key(fh.read(), password=None)

        # 2. Derive own symmetric AES key from own public key DER (see note above).
        self._aes_key = _aes_key_from_public_key(self._private_key.public_key())

        # 3. Load the CA certificate.
        ca_path = os.path.join(certs_dir, "ca.crt")
        with open(ca_path, "rb") as fh:
            ca_cert = x509.load_pem_x509_certificate(fh.read())
        ca_pub = ca_cert.public_key()

        # 4. Verify every node cert against the CA and trust the ones that pass.
        for cert_path in glob.glob(os.path.join(certs_dir, "*.crt")):
            if os.path.basename(cert_path) == "ca.crt":
                continue
            try:
                with open(cert_path, "rb") as fh:
                    cert = x509.load_pem_x509_certificate(fh.read())
                ca_pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception:
                # Untrusted / unparseable cert -- skip silently.
                continue
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            self._trusted_certs[cn] = cert

    # ------------------------------------------------------------------
    # Wrapping (publish side)
    # ------------------------------------------------------------------
    def wrap(self, ros_msg):
        """Serialize, sign and optionally encrypt ``ros_msg`` into a SecureEnvelope."""
        from rclpy.serialization import serialize_message
        from ros2_security_msgs.msg import SecureEnvelope

        payload_bytes = serialize_message(ros_msg)
        content_type = _ros_type_string(ros_msg)
        ts = time.time()

        if not SECURITY_ENABLED or self.level == SecurityLevel.NONE:
            return SecureEnvelope(
                level=SecurityLevel.NONE.value,
                sender=self.node_id,
                content_type=content_type,
                ts=ts,
                payload=list(payload_bytes),
                nonce="",
                sig="",
            )

        if self.level == SecurityLevel.SIGN_ONLY:
            signature = self._private_key.sign(payload_bytes, _PSS, hashes.SHA256())
            return SecureEnvelope(
                level=SecurityLevel.SIGN_ONLY.value,
                sender=self.node_id,
                content_type=content_type,
                ts=ts,
                payload=list(payload_bytes),
                nonce="",
                sig=signature.hex(),
            )

        # SIGN_ENCRYPT: encrypt first, then sign the ciphertext (no decrypt oracle).
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._aes_key).encrypt(nonce, payload_bytes, None)
        signature = self._private_key.sign(ciphertext, _PSS, hashes.SHA256())
        return SecureEnvelope(
            level=SecurityLevel.SIGN_ENCRYPT.value,
            sender=self.node_id,
            content_type=content_type,
            ts=ts,
            payload=list(ciphertext),
            nonce=nonce.hex(),
            sig=signature.hex(),
        )

    # ------------------------------------------------------------------
    # Unwrapping (subscribe side)
    # ------------------------------------------------------------------
    def unwrap(self, envelope, min_level, msg_type):
        """Verify/decode an envelope. Return a typed message, or ``None`` on any failure."""
        from rclpy.serialization import deserialize_message

        try:
            level = SecurityLevel(envelope.level)
        except ValueError:
            return None

        # 1. Mixed-trust gate.
        if level_rank[level] < level_rank[SecurityLevel(min_level)]:
            return None

        payload = bytes(envelope.payload)

        # 2. NONE fast-path: no signature, no sender check, no replay guard.
        if level == SecurityLevel.NONE:
            try:
                return deserialize_message(payload, msg_type)
            except Exception:
                return None

        # 3. Replay guard.
        if self.replay_window is not None and (time.time() - envelope.ts) > self.replay_window:
            return None

        # 4. Sender must be a trusted, CA-signed identity.
        sender_cert = self._trusted_certs.get(envelope.sender)
        if sender_cert is None:
            return None
        sender_pub = sender_cert.public_key()

        # 5. Signature verification (over payload == plaintext for SIGN_ONLY,
        #    ciphertext for SIGN_ENCRYPT). Verify happens before any decryption.
        try:
            sender_pub.verify(bytes.fromhex(envelope.sig), payload, _PSS, hashes.SHA256())
        except (InvalidSignature, ValueError):
            return None

        if level == SecurityLevel.SIGN_ONLY:
            try:
                return deserialize_message(payload, msg_type)
            except Exception:
                return None

        # 6. SIGN_ENCRYPT: derive sender's AES key from its public cert, decrypt.
        try:
            sender_aes_key = _aes_key_from_public_key(sender_pub)
            plaintext = AESGCM(sender_aes_key).decrypt(
                bytes.fromhex(envelope.nonce), payload, None
            )
            return deserialize_message(plaintext, msg_type)
        except Exception:
            return None
