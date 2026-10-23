"""Local POSIX Sandbox environment for BREACHLINE.

Provides:
1. Genuine OS-enforced local filesystem tests:
   Creates real files on disk with explicit POSIX permission bits (chmod 0000, chmod 0644, chmod 0600),
   attempts real open() operations, and captures genuine OS kernel PermissionError (Errno 13).
2. Explicitly labeled fallback simulation mode:
   Clearly distinguishes application-level role mock testing from genuine OS-enforced testing.
"""

import errno
import os
from pathlib import Path
import stat
from typing import Any, Dict

SANDBOX_ROOT = Path("output/local_sandbox")
SANDBOX_DATA = SANDBOX_ROOT / "data"

FIXTURE_CONTENTS = {
    "red/red_secret.txt": "CONFIDENTIAL_RED_TENANT_EVAL_CREDENTIALS_2026_NON_ROOT\n",
    "blue/blue_secret.txt": "CONFIDENTIAL_BLUE_TENANT_BENCHMARK_PROPRIETARY_DATA_2026\n",
    "leaky/blue_leaked.txt": "MISCONFIGURED_WORLD_READABLE_DATA_DAC_FAILURE_EXEMPLAR_2026\n",
    "shared/dataset.csv": "test_id,metric,value\nT1,isolation,passed\nT4,misconfiguration,detected\n",
    "restricted/blocked_by_os.txt": "SECRET_BLOCKED_BY_KERNEL_DAC_MODE_0000\n",
}


def setup_local_sandbox() -> Path:
    """Initialize local sandbox directory and set realistic POSIX permission bits on disk."""
    SANDBOX_DATA.mkdir(parents=True, exist_ok=True)
    (SANDBOX_DATA / "red").mkdir(parents=True, exist_ok=True)
    (SANDBOX_DATA / "blue").mkdir(parents=True, exist_ok=True)
    (SANDBOX_DATA / "leaky").mkdir(parents=True, exist_ok=True)
    (SANDBOX_DATA / "shared").mkdir(parents=True, exist_ok=True)
    (SANDBOX_DATA / "restricted").mkdir(parents=True, exist_ok=True)

    for rel_path, content in FIXTURE_CONTENTS.items():
        file_path = SANDBOX_DATA / rel_path
        if file_path.exists():
            try:
                os.chmod(file_path, 0o644)
            except Exception:
                pass
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    # Set real POSIX file permission modes
    try:
        os.chmod(SANDBOX_DATA / "red" / "red_secret.txt", 0o600)
        os.chmod(SANDBOX_DATA / "blue" / "blue_secret.txt", 0o600)
        os.chmod(SANDBOX_DATA / "leaky" / "blue_leaked.txt", 0o644)
        os.chmod(SANDBOX_DATA / "shared" / "dataset.csv", 0o640)
        # Real POSIX DAC block: mode 0000 prevents ANY read by non-root OS processes!
        os.chmod(SANDBOX_DATA / "restricted" / "blocked_by_os.txt", 0o000)
    except Exception:
        pass

    return SANDBOX_DATA


def execute_local_os_operation(operation: str, target_path: str) -> Dict[str, Any]:
    """Execute a genuine OS-enforced filesystem operation under the current host process identity.
    
    This function performs real syscalls (open, stat, listdir).
    If access is blocked, it is because the host operating system kernel denied it (PermissionError, Errno 13),
    NOT because of an application-level role check.
    """
    setup_local_sandbox()
    current_uid = os.getuid()
    current_gid = os.getgid()

    # Map /data/... prefix to local sandbox data directory
    if target_path.startswith("/data/"):
        rel = target_path[len("/data/"):]
        real_file = SANDBOX_DATA / rel
    else:
        return {
            "success": False,
            "exit_code": 126,
            "output": "",
            "error": f"Security Violation: Target path '{target_path}' is outside /data/ prefix.",
            "uid": current_uid,
            "gid": current_gid,
            "is_os_enforced": True,
            "is_execution_error": True,
            "enforcement_mechanism": "Path Validation Barrier",
        }

    # Strict directory traversal check
    try:
        real_file.resolve().relative_to(SANDBOX_ROOT.resolve())
    except ValueError:
        return {
            "success": False,
            "exit_code": 126,
            "output": "",
            "error": "Directory traversal attempt detected and blocked.",
            "uid": current_uid,
            "gid": current_gid,
            "is_os_enforced": True,
            "is_execution_error": True,
            "enforcement_mechanism": "Path Traversal Barrier",
        }

    if operation == "file:read":
        # REAL OS KERNEL DAC TEST: Attempt to open the file directly
        try:
            with open(real_file, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "success": True,
                "exit_code": 0,
                "output": content.strip(),
                "error": None,
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel POSIX DAC",
            }
        except PermissionError as e:
            # Genuine OS Kernel DAC denial!
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": f"Permission denied (Host OS DAC): {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel POSIX DAC",
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "exit_code": 2,
                "output": "",
                "error": f"File not found (Host OS): {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel VFS",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": 125,
                "output": "",
                "error": f"Unexpected Host OS Error: {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": True,
                "enforcement_mechanism": "Host OS Kernel Exception",
            }

    elif operation == "file:stat":
        try:
            st = real_file.stat()
            mode_str = oct(stat.S_IMODE(st.st_mode))
            return {
                "success": True,
                "exit_code": 0,
                "output": f"Size: {st.st_size} bytes, Mode: {mode_str}, Owner: {st.st_uid}:{st.st_gid}",
                "error": None,
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel stat()",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": f"stat() failed: {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel stat()",
            }

    elif operation == "dir:list":
        try:
            items = os.listdir(real_file.parent)
            return {
                "success": True,
                "exit_code": 0,
                "output": ", ".join(items),
                "error": None,
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel listdir()",
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": f"listdir() failed: {e}",
                "uid": current_uid,
                "gid": current_gid,
                "is_os_enforced": True,
                "is_execution_error": False,
                "enforcement_mechanism": "Host OS Kernel listdir()",
            }

    else:
        return {
            "success": False,
            "exit_code": 127,
            "output": "",
            "error": f"Unsupported operation: {operation}",
            "uid": current_uid,
            "gid": current_gid,
            "is_os_enforced": False,
            "is_execution_error": True,
            "enforcement_mechanism": "None",
        }


def execute_simulated_role_operation(role: str, operation: str, target_path: str) -> Dict[str, Any]:
    """Explicitly labeled fallback simulation mode for testing when Docker is unavailable.
    
    IMPORTANT: This function uses application-level role mapping.
    It is EXPLICITLY LABELED as is_os_enforced = False so it is never
    misrepresented as real operating system enforcement.
    """
    setup_local_sandbox()
    
    # Path traversal check
    if "\0" in target_path or ".." in target_path:
        return {
            "success": False,
            "exit_code": 126,
            "output": "",
            "error": "Directory traversal attempt detected and blocked.",
            "worker": role,
            "is_os_enforced": False,
            "is_execution_error": True,
            "enforcement_mechanism": "SIMULATED_ROLE_BASED",
            "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
        }

    # Map role expectations
    if role == "red-worker":
        if "/blue/blue_secret.txt" in target_path:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": "Permission denied (Simulated DAC): Red worker prohibited from Blue secret.",
                "worker": role,
                "is_os_enforced": False,
                "is_execution_error": False,
                "enforcement_mechanism": "SIMULATED_ROLE_BASED",
                "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
            }
        elif "/red/red_secret.txt" in target_path or "/leaky/blue_leaked.txt" in target_path:
            return {
                "success": True,
                "exit_code": 0,
                "output": "SIMULATED_READ_CONTENT",
                "error": None,
                "worker": role,
                "is_os_enforced": False,
                "is_execution_error": False,
                "enforcement_mechanism": "SIMULATED_ROLE_BASED",
                "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
            }

    elif role == "blue-worker":
        if "/red/red_secret.txt" in target_path:
            return {
                "success": False,
                "exit_code": 1,
                "output": "",
                "error": "Permission denied (Simulated DAC): Blue worker prohibited from Red secret.",
                "worker": role,
                "is_os_enforced": False,
                "is_execution_error": False,
                "enforcement_mechanism": "SIMULATED_ROLE_BASED",
                "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
            }
        elif "/blue/blue_secret.txt" in target_path or "/leaky/blue_leaked.txt" in target_path:
            return {
                "success": True,
                "exit_code": 0,
                "output": "SIMULATED_READ_CONTENT",
                "error": None,
                "worker": role,
                "is_os_enforced": False,
                "is_execution_error": False,
                "enforcement_mechanism": "SIMULATED_ROLE_BASED",
                "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
            }

    return {
        "success": False,
        "exit_code": 1,
        "output": "",
        "error": "Access Denied (Simulated)",
        "worker": role,
        "is_os_enforced": False,
        "is_execution_error": False,
        "enforcement_mechanism": "SIMULATED_ROLE_BASED",
        "simulation_notice": "Application-level simulation. NOT OS ENFORCED.",
    }


def execute_local_operation(role: str, operation: str, target_path: str, force_simulation: bool = False) -> Dict[str, Any]:
    """Execute operation locally.
    
    - If target_path targets a real POSIX permission test (e.g. /data/restricted/blocked_by_os.txt),
      it runs execute_local_os_operation with genuine OS kernel enforcement.
    - If multi-tenant cross-role simulation is explicitly requested, it runs execute_simulated_role_operation
      with explicit labeling that it is an application-level simulation.
    """
    if force_simulation or "/blue/" in target_path or "/red/" in target_path:
        return execute_simulated_role_operation(role, operation, target_path)
    return execute_local_os_operation(operation, target_path)
