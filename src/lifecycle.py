"""Run Lifecycle & Real-Time Progress Tracker for BREACHLINE.

Implements an explicit six-stage execution lifecycle:
CONFIGURE -> EXECUTE -> OBSERVE -> COMPARE -> RECORD -> VERIFY

Supports thread-safe run state transitions, real-time stage progress,
SSE streaming, and persistent run retrieval across browser refreshes and restarts.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import queue
import threading
import time
from typing import Any, Dict, List, Optional

from src.storage import get_run


class RunStage:
    CONFIGURE = "CONFIGURE"
    EXECUTE = "EXECUTE"
    OBSERVE = "OBSERVE"
    COMPARE = "COMPARE"
    RECORD = "RECORD"
    VERIFY = "VERIFY"
    FINISHED = "FINISHED"

    ALL_STAGES = [CONFIGURE, EXECUTE, OBSERVE, COMPARE, RECORD, VERIFY]


STAGE_DESCRIPTIONS = {
    RunStage.CONFIGURE: "Loading boundary test scenarios, validating containment paths, and resolving worker endpoints.",
    RunStage.EXECUTE: "Dispatching boundary probes to assigned worker container identities under OS enforcement.",
    RunStage.OBSERVE: "Capturing actual process exit codes, error streams, and POSIX DAC enforcement signals.",
    RunStage.COMPARE: "Evaluating observed access against expected security policy and identifying violations.",
    RunStage.RECORD: "Canonicalizing JSON payloads, computing SHA-256 hashes, and sealing hash chain.",
    RunStage.VERIFY: "Executing independent mathematical verification and committing trust anchor.",
    RunStage.FINISHED: "Boundary evaluation and evidence verification completed.",
}


class RunStatus:
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_FAILURES = "COMPLETED_WITH_FAILURES"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class RunState:
    run_id: str
    status: str = RunStatus.QUEUED
    current_stage: str = RunStage.CONFIGURE
    stage_explanation: str = STAGE_DESCRIPTIONS[RunStage.CONFIGURE]
    stages_completed: List[str] = field(default_factory=list)
    stage_states: Dict[str, str] = field(default_factory=lambda: {s: "pending" for s in RunStage.ALL_STAGES})
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at_utc: Optional[str] = None
    completed_at_utc: Optional[str] = None
    elapsed_seconds: float = 0.0
    total_tests: int = 0
    completed_tests: int = 0
    current_test_id: Optional[str] = None
    passed_tests: int = 0
    failed_tests: int = 0
    execution_errors: int = 0
    unexpected_access_count: int = 0
    effective_mode: str = "auto"
    recording_status: str = "PENDING"      # PENDING, RECORDING, RECORDED, FAILED
    verification_status: str = "PENDING"  # PENDING, VERIFYING, VALID, INVALID, FAILED
    trust_anchor_status: str = "PENDING"  # PENDING, COMMITTED, FAILED, UNANCHORED
    summary: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RunLifecycleManager:
    """Thread-safe lifecycle coordinator managing active run progress and SSE broadcasts."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active_runs: Dict[str, RunState] = {}
        self._subscribers: Dict[str, List[queue.Queue]] = {}
        self._start_times: Dict[str, float] = {}

    def init_run(self, run_id: str, mode: str = "auto", total_tests: int = 4) -> RunState:
        with self._lock:
            state = RunState(
                run_id=run_id,
                status=RunStatus.RUNNING,
                current_stage=RunStage.CONFIGURE,
                stage_explanation=STAGE_DESCRIPTIONS[RunStage.CONFIGURE],
                effective_mode=mode,
                total_tests=total_tests,
                started_at_utc=datetime.now(timezone.utc).isoformat(),
                stage_states={
                    RunStage.CONFIGURE: "running",
                    RunStage.EXECUTE: "pending",
                    RunStage.OBSERVE: "pending",
                    RunStage.COMPARE: "pending",
                    RunStage.RECORD: "pending",
                    RunStage.VERIFY: "pending",
                }
            )
            self._active_runs[run_id] = state
            self._start_times[run_id] = time.time()
            self._broadcast(state)
            return state

    def set_stage(self, run_id: str, stage: str, explanation: Optional[str] = None, stage_state: str = "running") -> None:
        with self._lock:
            state = self._active_runs.get(run_id)
            if not state:
                return
            state.current_stage = stage
            state.stage_explanation = explanation or STAGE_DESCRIPTIONS.get(stage, "")
            state.stage_states[stage] = stage_state
            if run_id in self._start_times:
                state.elapsed_seconds = round(time.time() - self._start_times[run_id], 2)
            self._broadcast(state)

    def complete_stage(self, run_id: str, stage: str, stage_state: str = "passed") -> None:
        with self._lock:
            state = self._active_runs.get(run_id)
            if not state:
                return
            state.stage_states[stage] = stage_state
            if stage not in state.stages_completed:
                state.stages_completed.append(stage)
            if run_id in self._start_times:
                state.elapsed_seconds = round(time.time() - self._start_times[run_id], 2)
            self._broadcast(state)

    def update_test_progress(
        self,
        run_id: str,
        test_id: str,
        completed_count: int,
        is_pass: bool,
        is_unexpected: bool = False,
        is_error: bool = False,
    ) -> None:
        with self._lock:
            state = self._active_runs.get(run_id)
            if not state:
                return
            state.current_test_id = test_id
            state.completed_tests = completed_count
            if is_error:
                state.execution_errors += 1
                state.failed_tests += 1
            elif is_pass:
                state.passed_tests += 1
            else:
                state.failed_tests += 1

            if is_unexpected:
                state.unexpected_access_count += 1

            if run_id in self._start_times:
                state.elapsed_seconds = round(time.time() - self._start_times[run_id], 2)
            self._broadcast(state)

    def finish_run(
        self,
        run_id: str,
        final_status: str,
        summary: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
    ) -> RunState:
        with self._lock:
            state = self._active_runs.get(run_id)
            if not state:
                state = RunState(run_id=run_id)
                self._active_runs[run_id] = state

            state.status = final_status
            state.current_stage = RunStage.FINISHED
            state.stage_explanation = STAGE_DESCRIPTIONS[RunStage.FINISHED]
            state.completed_at_utc = datetime.now(timezone.utc).isoformat()
            if run_id in self._start_times:
                state.elapsed_seconds = round(time.time() - self._start_times[run_id], 2)
            state.summary = summary
            state.error_message = error_message

            if summary:
                state.passed_tests = summary.get("passed", state.passed_tests)
                state.failed_tests = summary.get("failed", state.failed_tests)
                state.execution_errors = summary.get("errors", state.execution_errors)
                state.completed_tests = summary.get("total", state.completed_tests)
                state.total_tests = summary.get("total", state.total_tests)
                state.recording_status = "RECORDED"
                state.verification_status = "VALID" if summary.get("evidence_valid") else "INVALID"

            self._broadcast(state)
            return state

    def get_run_state(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if run_id in self._active_runs:
                state = self._active_runs[run_id]
                if run_id in self._start_times and state.status == RunStatus.RUNNING:
                    state.elapsed_seconds = round(time.time() - self._start_times[run_id], 2)
                return state.to_dict()

        # If not active in memory, reconstruct from disk (history persistence)
        persisted = get_run(run_id)
        if not persisted:
            return None

        meta = persisted.get("meta", {})
        records = persisted.get("records", [])
        total = meta.get("total_tests", len(records))
        mismatches = meta.get("policy_mismatches", 0)
        unexpected = meta.get("unexpected_access_count", 0)
        verif_data = meta.get("evidence_integrity", {})
        is_valid = verif_data.get("is_valid", False)

        final_status = RunStatus.COMPLETED if mismatches == 0 else RunStatus.COMPLETED_WITH_FAILURES
        if not is_valid:
            final_status = RunStatus.FAILED

        stage_states = {
            RunStage.CONFIGURE: "passed",
            RunStage.EXECUTE: "passed",
            RunStage.OBSERVE: "passed",
            RunStage.COMPARE: "warn" if mismatches > 0 else "passed",
            RunStage.RECORD: "passed",
            RunStage.VERIFY: "passed" if is_valid else "failed",
        }

        reconstructed = RunState(
            run_id=run_id,
            status=final_status,
            current_stage=RunStage.FINISHED,
            stage_explanation="Historical evaluation results loaded from persistent storage.",
            stages_completed=list(RunStage.ALL_STAGES),
            stage_states=stage_states,
            created_at_utc=meta.get("timestamp_utc", ""),
            started_at_utc=meta.get("timestamp_utc"),
            completed_at_utc=meta.get("finish_time_utc"),
            total_tests=total,
            completed_tests=total,
            passed_tests=meta.get("policy_matches", total - mismatches),
            failed_tests=mismatches,
            unexpected_access_count=unexpected,
            effective_mode=meta.get("execution_mode", "auto"),
            recording_status="RECORDED",
            verification_status="VALID" if is_valid else "INVALID",
            trust_anchor_status=meta.get("trust_anchor_status", "COMMITTED"),
            summary=meta,
        )
        return reconstructed.to_dict()

    def get_active_run(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            for rid, state in self._active_runs.items():
                if state.status == RunStatus.RUNNING:
                    if rid in self._start_times:
                        state.elapsed_seconds = round(time.time() - self._start_times[rid], 2)
                    return state.to_dict()
        return None

    def subscribe(self, run_id: str) -> queue.Queue:
        with self._lock:
            q = queue.Queue(maxsize=100)
            if run_id not in self._subscribers:
                self._subscribers[run_id] = []
            self._subscribers[run_id].append(q)
            return q

    def unsubscribe(self, run_id: str, q: queue.Queue) -> None:
        with self._lock:
            if run_id in self._subscribers and q in self._subscribers[run_id]:
                self._subscribers[run_id].remove(q)
                if not self._subscribers[run_id]:
                    del self._subscribers[run_id]

    def _broadcast(self, state: RunState) -> None:
        rid = state.run_id
        if rid in self._subscribers:
            data = json.dumps(state.to_dict())
            for q in list(self._subscribers[rid]):
                try:
                    q.put_nowait(data)
                except queue.Full:
                    pass


RUN_LIFECYCLE = RunLifecycleManager()
