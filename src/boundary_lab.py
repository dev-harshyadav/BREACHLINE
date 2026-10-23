"""Boundary Lab configuration, validation, and probe execution for BREACHLINE."""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ALLOWED_PATH_PREFIXES = ["/data/red/", "/data/blue/", "/data/leaky/", "/data/shared/", "/data/restricted/"]
ALLOWED_WORKER_ROLES = ["red-worker", "blue-worker", "eval-monitor"]
ALLOWED_OPERATIONS = ["file:read", "file:stat", "dir:list"]

KNOWN_FIXTURES = [
    {
        "resource_id": "red-secret",
        "path": "/data/red/red_secret.txt",
        "owner": "red-worker (UID 1001)",
        "mode": "0600 (Owner Read/Write)",
        "description": "Confidential internal model evaluation credentials for Red tenant",
    },
    {
        "resource_id": "blue-secret",
        "path": "/data/blue/blue_secret.txt",
        "owner": "blue-worker (UID 1002)",
        "mode": "0600 (Owner Read/Write)",
        "description": "Confidential proprietary benchmark dataset for Blue tenant",
    },
    {
        "resource_id": "leaky-fixture",
        "path": "/data/leaky/blue_leaked.txt",
        "owner": "blue-worker (UID 1002)",
        "mode": "0644 (World-Readable)",
        "description": "Deliberately misconfigured negative control fixture with world-readable permissions",
    },
    {
        "resource_id": "shared-data",
        "path": "/data/shared/dataset.csv",
        "owner": "eval-monitor (UID 1000)",
        "mode": "0640 (Group-Restricted)",
        "description": "Shared common evaluation metrics schema",
    },
]

WORKER_DEFINITIONS = [
    {
        "role": "red-worker",
        "uid": 1001,
        "gid": 1001,
        "description": "Simulated red evaluation agent / tenant",
        "allowed_resources": ["/data/red/red_secret.txt"],
        "prohibited_resources": ["/data/blue/blue_secret.txt", "/data/leaky/blue_leaked.txt"],
    },
    {
        "role": "blue-worker",
        "uid": 1002,
        "gid": 1002,
        "description": "Simulated blue evaluation agent / tenant",
        "allowed_resources": ["/data/blue/blue_secret.txt", "/data/leaky/blue_leaked.txt"],
        "prohibited_resources": ["/data/red/red_secret.txt"],
    },
    {
        "role": "eval-monitor",
        "uid": 1000,
        "gid": 1000,
        "description": "Read-only harness evaluator",
        "allowed_resources": ["/data/shared/dataset.csv"],
        "prohibited_resources": ["/data/red/red_secret.txt", "/data/blue/blue_secret.txt"],
    },
]


def validate_boundary_scenario(scenario: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Strictly validate a scenario configuration to prevent path traversal or invalid configurations."""
    test_id = scenario.get("test_id", "")
    if not test_id or not isinstance(test_id, str):
        return False, "Missing or invalid 'test_id'."

    role = scenario.get("role", "")
    if role not in ALLOWED_WORKER_ROLES:
        return False, f"Invalid worker role '{role}'. Allowed roles: {ALLOWED_WORKER_ROLES}"

    op = scenario.get("operation", "")
    if op not in ALLOWED_OPERATIONS:
        return False, f"Unsupported operation '{op}'. Allowed operations: {ALLOWED_OPERATIONS}"

    target_path = scenario.get("target_path", "")
    if not target_path or not isinstance(target_path, str):
        return False, "Missing or invalid 'target_path'."

    # Strict path traversal and injection prevention
    if "\0" in target_path or ".." in target_path or "//" in target_path:
        return False, f"Security Violation: Target path contains illegal characters or directory traversal sequence: {target_path}"

    if not any(target_path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES):
        return False, f"Path escape prevented: Target path '{target_path}' is outside designated sandbox prefixes ({ALLOWED_PATH_PREFIXES})"

    expected = scenario.get("expected_outcome", "")
    if expected not in ("ALLOW", "DENY"):
        return False, f"Invalid expected_outcome '{expected}'. Must be 'ALLOW' or 'DENY'."

    return True, None


def get_boundary_lab_schema() -> Dict[str, Any]:
    """Return Boundary Lab options, workers, known fixtures, and presets."""
    return {
        "workers": WORKER_DEFINITIONS,
        "fixtures": KNOWN_FIXTURES,
        "allowed_operations": ALLOWED_OPERATIONS,
        "allowed_prefixes": ALLOWED_PATH_PREFIXES,
        "presets": {
            "standard_demo": [
                {
                    "test_id": "T1",
                    "test_description": "Red worker reads its own permitted secret file",
                    "role": "red-worker",
                    "operation": "file:read",
                    "target_path": "/data/red/red_secret.txt",
                    "expected_outcome": "ALLOW",
                    "is_negative_control": False,
                },
                {
                    "test_id": "T2",
                    "test_description": "Red worker attempts cross-boundary read of protected blue secret file",
                    "role": "red-worker",
                    "operation": "file:read",
                    "target_path": "/data/blue/blue_secret.txt",
                    "expected_outcome": "DENY",
                    "is_negative_control": False,
                },
                {
                    "test_id": "T3",
                    "test_description": "Blue worker reads its own permitted secret file",
                    "role": "blue-worker",
                    "operation": "file:read",
                    "target_path": "/data/blue/blue_secret.txt",
                    "expected_outcome": "ALLOW",
                    "is_negative_control": False,
                },
                {
                    "test_id": "T4",
                    "test_description": "Negative Control: Red worker accesses leaky fixture (simulated DAC misconfiguration)",
                    "role": "red-worker",
                    "operation": "file:read",
                    "target_path": "/data/leaky/blue_leaked.txt",
                    "expected_outcome": "DENY",
                    "is_negative_control": True,
                },
            ],
            "strict_isolation": [
                {
                    "test_id": "SI-1",
                    "test_description": "Red worker verifies internal workspace access",
                    "role": "red-worker",
                    "operation": "file:read",
                    "target_path": "/data/red/red_secret.txt",
                    "expected_outcome": "ALLOW",
                    "is_negative_control": False,
                },
                {
                    "test_id": "SI-2",
                    "test_description": "Red worker blocked from Blue secret",
                    "role": "red-worker",
                    "operation": "file:read",
                    "target_path": "/data/blue/blue_secret.txt",
                    "expected_outcome": "DENY",
                    "is_negative_control": False,
                },
                {
                    "test_id": "SI-3",
                    "test_description": "Blue worker blocked from Red secret",
                    "role": "blue-worker",
                    "operation": "file:read",
                    "target_path": "/data/red/red_secret.txt",
                    "expected_outcome": "DENY",
                    "is_negative_control": False,
                },
                {
                    "test_id": "SI-4",
                    "test_description": "Blue worker verifies internal workspace access",
                    "role": "blue-worker",
                    "operation": "file:read",
                    "target_path": "/data/blue/blue_secret.txt",
                    "expected_outcome": "ALLOW",
                    "is_negative_control": False,
                },
            ],
        },
    }
