# Security level: "none" | "sign" | "sign+encrypt"
string level

# Sender node CN -- must match a cert in the receiver's trusted_certs
string sender

# Original ROS2 message type, e.g. "sensor_msgs/msg/Image"
# Used for CDR deserialization on the subscriber side
string content_type

# Unix timestamp (float64) for replay guard
float64 ts

# CDR-serialized original message bytes (plaintext for NONE/SIGN_ONLY,
# AES-GCM ciphertext for SIGN_ENCRYPT)
uint8[] payload

# 12-byte AES-GCM nonce, hex-encoded. Empty string if not encrypted.
string nonce

# RSA-PSS signature over payload bytes, hex-encoded.
# Empty string if level is "none".
string sig
