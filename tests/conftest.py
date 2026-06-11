"""Shared pytest fixtures.

The ``ros_context`` fixture is session-scoped so ``rclpy`` is initialised once
for the whole run (required by integration tests only).  ``test_certs_dir``
mints a temporary CA + node certs by invoking ``scripts/generate_certs.sh``.
"""

import os
import subprocess

import pytest

# Repository root = two levels up from this file (tests/ -> repo root).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATE_CERTS = os.path.join(REPO_ROOT, "scripts", "generate_certs.sh")

# Node names that the certificate-based tests rely on.
CERT_NODE_NAMES = [
    "node_a",
    "node_b",
    "camera_node",
    "lidar_node",
    "planner_node",
    "legacy_relay",
]


@pytest.fixture(scope="session")
def ros_context():
    """Initialise rclpy once for the session. Required by integration tests only."""
    import rclpy
    rclpy.init()
    yield
    rclpy.shutdown()


@pytest.fixture(scope="session")
def test_certs_dir(tmp_path_factory):
    """Generate a temporary CA + node certs and return the certs directory path."""
    certs = tmp_path_factory.mktemp("certs")
    env = dict(os.environ, CERTS_DIR=str(certs))
    subprocess.run(
        ["bash", GENERATE_CERTS, *CERT_NODE_NAMES],
        check=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return str(certs)


@pytest.fixture()
def policy_file(tmp_path):
    """Write a minimal security_policy.yaml to a temp dir and return its path."""
    content = """
global_min_level: none
nodes:
  node_a:
    publish_level: sign
    subscriptions:
      /topic_a:
        min_level: sign
  node_b:
    publish_level: sign+encrypt
    subscriptions: {}
"""
    p = tmp_path / "security_policy.yaml"
    p.write_text(content)
    return str(p)
