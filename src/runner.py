"""Test Runner for BREACHLINE.

Executes boundary test cases against genuine non-root worker containers (Docker Linux DAC)
or host POSIX kernel permissions, captures actual operating system enforcement outcomes,
evaluates PASS/FAIL, and streams structured evidence into a hash-chained evidence log.

Crucial Security Guarantees:
1. Genuine OS Enforcement: Tests are executed by real non-root worker processes/containers
   under their intended OS identities (UID 1001 for Red, UID 1002 for Blue).
2. No Silent Simulation: If OS enforcement is requested but the required isolation environment
   is unavailable, the runner raises a clear error rather than substituting simulated outcomes.
3. Execution Error Separation: Execution errors (timeouts, network errors, path security violations)
   are recorded as 'ERROR' and evaluated as policy 'FAIL'. They are NEVER classified as successful policy denials.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from src.boundary_lab import validate_boundary_scenario
from src.classification import classify_execution_outcome
from src.evidence import EvidenceRecorder
from src.local_sandbox import execute_local_os_operation, execute_simulated_role_operation
from src.models import TestCase
from src.storage import persist_run

DEFAULT_CONFIG_PATH = "config/test_cases.json"
DEFAULT_EVIDENCE_PATH = "output/evidence.jsonl"


def get_worker_url(role: str) -> str:
    """Resolve worker endpoint depending on Docker network vs Host mode."""
    if role == "red-worker":
        if "RED_WORKER_URL" in os.environ:
            return os.environ["RED_WORKER_URL"]
        in_docker = os.path.exists("/.dockerenv") or os.environ.get("RUNNER_IN_DOCKER") == "1"
        return "http://red-worker:8080" if in_docker else "http://localhost:8081"

    elif role == "blue-worker":
        if "BLUE_WORKER_URL" in os.environ:
            return os.environ["BLUE_WORKER_URL"]
        in_docker = os.path.exists("/.dockerenv") or os.environ.get("RUNNER_IN_DOCKER") == "1"
        return "http://blue-worker:8080" if in_docker else "http://localhost:8082"

    raise ValueError(f"Unknown role: {role}")


def check_worker_health(base_url: str, timeout: float = 1.5) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Check health endpoint of a worker container."""
    try:
        url = f"{base_url}/health"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return True, data
    except Exception:
        pass
    return False, None


def check_docker_environment() -> Dict[str, Any]:
    """Inspect Docker worker container availability."""
    red_url = get_worker_url("red-worker")
    blue_url = get_worker_url("blue-worker")

    red_ok, red_info = check_worker_health(red_url)
    blue_ok, blue_info = check_worker_health(blue_url)

    available = red_ok and blue_ok
    return {
        "available": available,
        "red_worker": {"url": red_url, "healthy": red_ok, "info": red_info},
        "blue_worker": {"url": blue_url, "healthy": blue_ok, "info": blue_info},
        "message": (
            "Docker worker containers are running and reachable (Genuine Linux Kernel DAC active)."
            if available
            else "Docker containers are unreachable. Run 'docker compose up -d' for real OS DAC enforcement."
        ),
    }


def execute_remote_worker(
    worker_url: str,
    operation: str,
    target_path: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Dispatch an operation to a real non-root worker container over HTTP."""
    url = f"{worker_url}/execute"
    payload = json.dumps({"operation": operation, "target_path": target_path}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def wait_for_workers(timeout: int = 6) -> bool:
    """Wait for red and blue workers to become healthy."""
    red_url = get_worker_url("red-worker")
    blue_url = get_worker_url("blue-worker")

    start_time = time.time()
    for worker_name, base_url in [("red-worker", red_url), ("blue-worker", blue_url)]:
        health_url = f"{base_url}/health"
        healthy = False
        while time.time() - start_time < timeout:
            try:
                with urllib.request.urlopen(health_url, timeout=1.5) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(0.4)

        if not healthy:
            return False

    return True


def get_default_evidence_path() -> Path:
    from src.storage import OUTPUT_DIR
    return OUTPUT_DIR / "evidence.jsonl"


class TestRunner:
    __test__ = False

    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        evidence_path: Optional[str] = None,
        run_id: Optional[str] = None,
        executor_override: Optional[Callable[..., Dict[str, Any]]] = None,
        mode: str = "auto",  # 'auto', 'docker', 'local_os', 'simulated', 'demo'
    ):
        self.config_path = Path(config_path)
        if evidence_path is None:
            self.evidence_path = get_default_evidence_path()
        else:
            self.evidence_path = Path(evidence_path)
        self.recorder = EvidenceRecorder(str(self.evidence_path), run_id=run_id)
        self.executor_override = executor_override
        self.mode = mode
        self.effective_mode = mode
        self.is_os_enforced = False

    def load_test_cases(self) -> List[TestCase]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [TestCase(**item) for item in data]

    def _determine_execution_mode(self, verify_workers: bool) -> str:
        if self.executor_override:
            self.is_os_enforced = False
            return "override"

        if self.mode in ("docker", "os_enforced"):
            if not wait_for_workers(timeout=4):
                raise RuntimeError(
                    "Real OS-enforced multi-tenant testing was requested, but Docker worker containers are offline.\n"
                    "BREACHLINE refuses to silently substitute simulated outcomes for real OS tests.\n"
                    "To start the genuine OS-enforced environment, run:\n"
                    "  docker compose up -d fixture-init red-worker blue-worker\n"
                    "Or if you explicitly wish to run offline role simulation, use:\n"
                    "  ./breachline run --mode simulated"
                )
            self.is_os_enforced = True
            return "docker"

        elif self.mode == "local_os":
            self.is_os_enforced = True
            return "local_os"

        elif self.mode in ("simulated", "demo", "local_sandbox"):
            self.is_os_enforced = False
            return self.mode

        else:  # 'auto'
            docker_status = check_docker_environment()
            if docker_status["available"]:
                self.is_os_enforced = True
                return "docker"
            else:
                # Docker is not running
                raise RuntimeError(
                    "Docker worker containers are not reachable.\n"
                    "Genuine multi-tenant OS DAC testing requires the Docker worker architecture (red-worker UID 1001, blue-worker UID 1002).\n"
                    "To start the genuine OS-enforced environment, run:\n"
                    "  docker compose up -d fixture-init red-worker blue-worker\n\n"
                    "If you explicitly want to run in offline simulation mode without OS enforcement, specify:\n"
                    "  ./breachline run --mode simulated"
                )

    def run_all(self, verify_workers: bool = True) -> Dict[str, Any]:
        """Execute all configured boundary tests and record evidence."""
        test_cases = self.load_test_cases()
        self.effective_mode = self._determine_execution_mode(verify_workers)

        print(f"\n========================================================")
        print(f"  BREACHLINE EVALUATION HARNESS — RUN ID: {self.recorder.run_id}")
        print(f"  MODE: {self.effective_mode.upper()} (OS Enforced: {self.is_os_enforced})")
        print(f"========================================================")
        print(f"Loaded {len(test_cases)} boundary test cases from {self.config_path}")

        if self.effective_mode == "docker":
            print("[INFO] Connected to Docker worker containers (red-worker UID 1001 & blue-worker UID 1002).")
            print("[INFO] Access boundaries are actively enforced by Linux Kernel POSIX DAC.")
        elif self.effective_mode == "local_os":
            print("[INFO] Executing under host POSIX kernel enforcement.")
        elif self.effective_mode in ("simulated", "demo", "local_sandbox"):
            print(f"[NOTICE] Running in EXPLICIT SIMULATION mode ({self.effective_mode}). Results are application-level role mocks, NOT OS-enforced.")

        summary: Dict[str, Any] = {
            "run_id": self.recorder.run_id,
            "execution_mode": self.effective_mode,
            "is_os_enforced": self.is_os_enforced,
            "total": len(test_cases),
            "passed": 0,
            "failed": 0,
            "unexpected_access_count": 0,
            "execution_errors_count": 0,
            "records": [],
            "findings": [],
            "execution_errors": [],
            "environment_info": {
                "os": platform.system(),
                "release": platform.release(),
                "python": sys.version.split()[0],
                "effective_mode": self.effective_mode,
                "is_os_enforced": self.is_os_enforced,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            },
        }

        print("\n" + "-" * 75)
        print(f"{'TEST':<5} | {'ROLE':<12} | {'OPERATION':<12} | {'EXPECTED':<8} | {'ACTUAL':<8} | {'RESULT'}")
        print("-" * 75)

        for tc in test_cases:
            # 1. Validate scenario to prevent path traversal or invalid configurations
            val_ok, val_err = validate_boundary_scenario({
                "test_id": tc.test_id,
                "role": tc.role,
                "operation": tc.operation,
                "target_path": tc.target_path,
                "expected_outcome": tc.expected_outcome,
            })

            execution_error_info = None

            if not val_ok:
                res = {"exit_code": 126, "error": val_err, "is_execution_error": True}
            else:
                # 2. Execute operation according to effective mode
                if self.executor_override:
                    res = self.executor_override(tc.role, tc.operation, tc.target_path)
                elif self.effective_mode == "docker":
                    try:
                        worker_url = get_worker_url(tc.role)
                        res = execute_remote_worker(worker_url, tc.operation, tc.target_path, timeout=5.0)
                    except urllib.error.URLError as e:
                        res = {
                            "exit_code": 125,
                            "error": f"Worker connection failed: {e}",
                            "is_unavailable": True,
                            "is_execution_error": True,
                        }
                    except TimeoutError as e:
                        res = {
                            "exit_code": 124,
                            "error": f"Worker execution timed out: {e}",
                            "is_timeout": True,
                            "is_execution_error": True,
                        }
                    except Exception as e:
                        res = {
                            "exit_code": 125,
                            "error": f"Worker connection error: {e}",
                            "is_execution_error": True,
                        }
                elif self.effective_mode == "local_os":
                    res = execute_local_os_operation(tc.operation, tc.target_path)
                else:
                    # Simulated mode
                    res = execute_simulated_role_operation(tc.role, tc.operation, tc.target_path)

            exit_code = res.get("exit_code", 1) if isinstance(res, dict) else 125

            # 3. Policy Evaluation (CRITICAL: Do NOT classify execution errors as successful denials!)
            actual_outcome, policy_result, execution_error_info = classify_execution_outcome(res, tc.expected_outcome)

            if actual_outcome in ("ERROR", "TIMEOUT", "UNAVAILABLE"):
                summary["execution_errors_count"] += 1
                summary["execution_errors"].append({
                    "test_id": tc.test_id,
                    "role": tc.role,
                    "operation": tc.operation,
                    "target_path": tc.target_path,
                    "exit_code": exit_code,
                    "outcome": actual_outcome,
                    "error": execution_error_info,
                })

            if policy_result == "PASS":
                summary["passed"] += 1
            else:
                summary["failed"] += 1
                if tc.expected_outcome == "DENY" and actual_outcome == "ALLOW":
                    summary["unexpected_access_count"] += 1
                    summary["findings"].append({
                        "finding_id": f"FINDING-{tc.test_id}-{self.recorder.run_id[:8]}",
                        "test_id": tc.test_id,
                        "run_id": self.recorder.run_id,
                        "worker": tc.role,
                        "resource": tc.target_path,
                        "operation": tc.operation,
                        "expected_outcome": tc.expected_outcome,
                        "observed_outcome": actual_outcome,
                        "policy_result": "FAIL",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "is_negative_control": getattr(tc, "is_negative_control", False),
                        "explanation": (
                            f"The operation '{tc.operation}' succeeded with exit code 0 even though "
                            f"the policy specified expected outcome '{tc.expected_outcome}'."
                        ),
                        "interpretation": (
                            "NEGATIVE CONTROL CONFIRMED: Harness detected deliberately misconfigured permissive fixture (mode 0644)."
                            if getattr(tc, "is_negative_control", False)
                            else "Configured boundary failed to isolate resource from unauthorized worker."
                        ),
                        "recommended_step": (
                            "Verify test harness detection capability. Fixture is behaving as intended for negative control."
                            if getattr(tc, "is_negative_control", False)
                            else "Inspect POSIX DAC permission bits (chmod/chown) and worker UID configuration."
                        ),
                    })

            # 4. Append to cryptographic evidence chain
            full_op = f"{tc.operation} {tc.target_path}"
            rec = self.recorder.record_test(
                test_id=tc.test_id,
                test_description=tc.test_description,
                role=tc.role,
                operation=full_op,
                expected_outcome=tc.expected_outcome,
                actual_outcome=actual_outcome,
                result=policy_result,
                exit_code=exit_code,
            )
            summary["records"].append(rec.to_dict())

            # Print readable status row
            badge = "[\033[92mPASS\033[0m]" if policy_result == "PASS" else "[\033[91mFAIL\033[0m]"
            print(
                f"{tc.test_id:<5} | {tc.role:<12} | {tc.operation:<12} | "
                f"{tc.expected_outcome:<8} | {actual_outcome:<8} | {badge}"
            )

        print("-" * 75)
        print(f"Summary: Total: {summary['total']} | Passed: {summary['passed']} | Failed: {summary['failed']} | Errors: {summary['execution_errors_count']}")
        print(f"Evidence logged to: {self.evidence_path}")
        print("========================================================\n")

        # 5. Persist run to storage history
        try:
            test_cases_dicts = [
                {
                    "test_id": t.test_id,
                    "test_description": t.test_description,
                    "role": t.role,
                    "operation": t.operation,
                    "target_path": t.target_path,
                    "expected_outcome": t.expected_outcome,
                    "is_negative_control": getattr(t, "is_negative_control", False),
                }
                for t in test_cases
            ]
            persist_run(
                run_id=self.recorder.run_id,
                test_cases=test_cases_dicts,
                records=summary["records"],
                summary=summary,
                execution_mode=self.effective_mode,
                environment_info=summary["environment_info"],
            )
        except Exception as e:
            print(f"[RUNNER STORAGE WARNING] Could not persist run to history: {e}", file=sys.stderr)

        return summary


def main():
    config_file = DEFAULT_CONFIG_PATH
    mode = "auto"
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg.endswith(".json") and os.path.exists(arg):
                config_file = arg
            elif arg in ("--docker", "docker"):
                mode = "docker"
            elif arg in ("--local_os", "local_os"):
                mode = "local_os"
            elif arg in ("--simulated", "simulated"):
                mode = "simulated"
            elif arg in ("--local_sandbox", "local_sandbox"):
                mode = "local_sandbox"
            elif arg in ("--demo", "demo"):
                mode = "demo"

    runner = TestRunner(config_path=config_file, mode=mode)
    try:
        runner.run_all()
    except Exception as e:
        print(f"[RUNNER FATAL] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
