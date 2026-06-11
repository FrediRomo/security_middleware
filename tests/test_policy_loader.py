"""Unit tests for SecurityPolicyLoader -- no ROS2 required."""

import pytest

from ros2_security.policy_loader import SecurityPolicyLoader
from ros2_security.security_manager import SecurityLevel


def _write(tmp_path, text, name="security_policy.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_publish_level_explicit(policy_file):
    loader = SecurityPolicyLoader(policy_file)
    assert loader.publish_level("node_a") == SecurityLevel.SIGN_ONLY
    assert loader.publish_level("node_b") == SecurityLevel.SIGN_ENCRYPT


def test_publish_level_fallback(policy_file):
    # node_x is unlisted -> falls back to global_min_level (none).
    loader = SecurityPolicyLoader(policy_file)
    assert loader.publish_level("node_x") == SecurityLevel.NONE


def test_min_level_explicit(policy_file):
    loader = SecurityPolicyLoader(policy_file)
    assert loader.min_level("node_a", "/topic_a") == SecurityLevel.SIGN_ONLY


def test_min_level_node_fallback(policy_file):
    # node_a is listed but /other is not -> global_min_level (none).
    loader = SecurityPolicyLoader(policy_file)
    assert loader.min_level("node_a", "/other") == SecurityLevel.NONE


def test_min_level_node_not_listed(policy_file):
    loader = SecurityPolicyLoader(policy_file)
    assert loader.min_level("ghost", "/whatever") == SecurityLevel.NONE


def test_global_min_level_honoured(tmp_path):
    path = _write(tmp_path, "global_min_level: sign\nnodes: {}\n")
    loader = SecurityPolicyLoader(path)
    assert loader.publish_level("anything") == SecurityLevel.SIGN_ONLY
    assert loader.min_level("anything", "/t") == SecurityLevel.SIGN_ONLY


def test_file_not_found(tmp_path, caplog):
    missing = str(tmp_path / "does_not_exist.yaml")
    loader = SecurityPolicyLoader(missing)  # must not raise
    assert loader.publish_level("node_a") == SecurityLevel.NONE
    assert loader.min_level("node_a", "/topic_a") == SecurityLevel.NONE


def test_malformed_yaml(tmp_path):
    path = _write(tmp_path, "global_min_level: none\nnodes: [this is: bad: yaml\n")
    with pytest.raises(ValueError, match="[Mm]alformed"):
        SecurityPolicyLoader(path)


def test_invalid_level_string(tmp_path):
    path = _write(
        tmp_path,
        "global_min_level: none\nnodes:\n  node_a:\n    publish_level: high\n",
    )
    with pytest.raises(ValueError, match="Invalid security level"):
        SecurityPolicyLoader(path)


def test_invalid_global_level_string(tmp_path):
    path = _write(tmp_path, "global_min_level: ultra\nnodes: {}\n")
    with pytest.raises(ValueError, match="Invalid security level"):
        SecurityPolicyLoader(path)


def test_env_var_path(tmp_path, monkeypatch):
    path = _write(tmp_path, "global_min_level: sign\nnodes: {}\n")
    monkeypatch.setenv("ROS2_SECURITY_POLICY", path)
    from ros2_security.policy_loader import resolve_policy_path
    resolved = resolve_policy_path(None)
    assert resolved == path
    loader = SecurityPolicyLoader(resolved)
    assert loader.publish_level("x") == SecurityLevel.SIGN_ONLY


def test_explicit_path_wins_over_env(tmp_path, monkeypatch):
    env_path = _write(tmp_path, "global_min_level: sign\nnodes: {}\n", "env.yaml")
    explicit_path = _write(
        tmp_path, "global_min_level: sign+encrypt\nnodes: {}\n", "explicit.yaml"
    )
    monkeypatch.setenv("ROS2_SECURITY_POLICY", env_path)
    from ros2_security.policy_loader import resolve_policy_path
    assert resolve_policy_path(explicit_path) == explicit_path
