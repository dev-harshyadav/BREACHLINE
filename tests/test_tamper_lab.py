"""Unit tests for the Evidence Tampering Laboratory."""

import os
from pathlib import Path
import pytest

from src.tamper import EvidenceTamperLab


def test_tamper_lab_all_attacks():
    """Verify that tamper lab runs all 5 attacks safely on disposable copies."""
    lab = EvidenceTamperLab()
    results = lab.run_all_attacks()

    assert len(results) == 5

    # Attacks 1-4 must be mathematically detected by the independent verifier
    for r in results[:4]:
        assert r.detected_as_tampered is True
        assert r.verifier_result["is_valid"] is False

    # Attack 5 (Full-Chain Rewrite) must confirm the documented limitation:
    # Internal verifier alone passes because all downstream hashes were recomputed.
    attack5 = results[4]
    assert attack5.attack_id == "ATTACK_5"
    assert attack5.detected_as_tampered is False
    assert attack5.verifier_result["is_valid"] is True
    assert "anchor" in attack5.architectural_note.lower()
