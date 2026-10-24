"""Security Outcome Classification Engine for BREACHLINE.

Guarantees technically defensible classification across all execution modes:
- ALLOW: The operation succeeded with confirmed access permitted (exit_code == 0).
- DENY: Reliable evidence establishes access was denied by the relevant enforcement mechanism (EACCES / PermissionError / Errno 13 / exit_code == 1).
- ERROR: The operation could not be evaluated reliably (ENOENT / FileNotFoundError, missing fixture directory, malformed response, syntax error).
- TIMEOUT: Execution exceeded configured timeout limit.
- UNAVAILABLE: Required worker or enforcement mechanism was unreachable or offline.

CRITICAL RULES:
1. A nonzero exit code alone must NEVER be sufficient to conclude that an operation was denied.
2. Missing files (ENOENT) are classified as ERROR, not DENY.
3. Missing fixture directories produce an execution ERROR.
4. Worker connectivity failures produce UNAVAILABLE or ERROR.
5. Timeouts are classified as TIMEOUT, never DENY.
6. Execution errors must NEVER be classified as successful policy denials (cannot produce PASS).
7. Negative controls: When expected is DENY and observed is ALLOW, policy_result is FAIL and flagged as unexpected access.
"""

class OutcomeClassification:
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


def classify_execution_outcome(res: Dict[str, Any], expected_outcome: str) -> Tuple[str, str, Optional[str]]:
    """Classify execution outcome into (actual_outcome, policy_result, error_info).
    
    Returns:
        actual_outcome: 'ALLOW' | 'DENY' | 'ERROR' | 'TIMEOUT' | 'UNAVAILABLE'
        policy_result: 'PASS' | 'FAIL'
        error_info: Optional explanation string if an error or unexpected access occurred
    """
    if not isinstance(res, dict):
        return "ERROR", "FAIL", f"Malformed worker response: expected dict, received {type(res).__name__}"

    exit_code = res.get("exit_code", 1)
    err_str = str(res.get("error") or "")
    is_exec_err = res.get("is_execution_error", False)
    is_timeout = res.get("is_timeout", False) or exit_code == 124 or "timed out" in err_str.lower()
    is_unavailable = res.get("is_unavailable", False) or (
        exit_code == 125 and ("worker connection failed" in err_str.lower() or "unreachable" in err_str.lower() or "failed to establish a new connection" in err_str.lower())
    )

    # 1. Timeout detection
    if is_timeout:
        return "TIMEOUT", "FAIL", err_str or "Execution timed out"

    # 2. Worker / infrastructure unavailable
    if is_unavailable:
        return "UNAVAILABLE", "FAIL", err_str or "Worker service unavailable or offline"

    # 3. File not found / missing fixture (ENOENT / exit_code 2)
    if exit_code == 2 or "file not found" in err_str.lower() or "does not exist" in err_str.lower() or "not found:" in err_str.lower():
        return "ERROR", "FAIL", err_str or "Target file or fixture does not exist (not a permission denial)"

    # 4. Explicit execution error or high exit code (>= 125, invalid scenario, syntax error)
    if is_exec_err or exit_code >= 125:
        return "ERROR", "FAIL", err_str or f"Execution error occurred (exit code {exit_code})"

    # 5. Success (exit_code == 0)
    if exit_code == 0:
        actual_outcome = "ALLOW"
        policy_result = "PASS" if expected_outcome == "ALLOW" else "FAIL"
        err = None
        if policy_result == "FAIL":
            err = f"Unexpected access permitted: Policy expected '{expected_outcome}', but operation succeeded with exit code 0."
        return actual_outcome, policy_result, err

    # 6. Confirmed permission denial (exit_code == 1 with permission denial proof)
    denial_signals = [
        "permission denied",
        "access denied",
        "errno 13",
        "os dac",
        "simulated dac",
    ]
    has_denial_proof = res.get("is_denied", False) or any(sig in err_str.lower() for sig in denial_signals)
    if exit_code == 1 and has_denial_proof:
        actual_outcome = "DENY"
        policy_result = "PASS" if expected_outcome == "DENY" else "FAIL"
        err = None
        if policy_result == "FAIL":
            err = f"Unexpected access denial: Policy expected '{expected_outcome}', but operation was denied."
        return actual_outcome, policy_result, err

    # 7. Nonzero exit code WITHOUT verified permission denial evidence -> Unreliable / ERROR
    return "ERROR", "FAIL", err_str or f"Unverified failure with exit code {exit_code} (lacks confirmed DAC denial evidence)"
