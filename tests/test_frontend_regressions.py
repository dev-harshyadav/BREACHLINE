"""Regression tests for frontend page rendering, table containment, and navigation safety."""

from pathlib import Path
import re
import pytest
from fastapi.testclient import TestClient
from src.server import app
from src.cli import is_port_in_use, find_next_free_port


client = TestClient(app)


def test_index_html_has_all_ten_view_sections():
    """Verify that all 10 dashboard views exist with correct IDs and matching nav links."""
    index_path = Path("src/static/index.html")
    assert index_path.exists(), "src/static/index.html must exist"
    content = index_path.read_text(encoding="utf-8")

    expected_views = [
        "overview",
        "boundary-lab",
        "scenarios",
        "history",
        "inspector",
        "vault",
        "verification",
        "tamper-lab",
        "reports",
        "settings",
    ]

    for view in expected_views:
        # Check that section exists
        section_pattern = rf'<section[^>]+id=["\']view-{view}["\']'
        assert re.search(section_pattern, content), f"View section id='view-{view}' must exist in index.html"

        # Check that nav-link exists
        nav_pattern = rf'data-view=["\']{view}["\']'
        assert re.search(nav_pattern, content), f"Nav link data-view='{view}' must exist in index.html"


def test_all_data_tables_have_table_container_wrapper():
    """Verify that every data-table in index.html is wrapped in a table-container for laptop responsiveness."""
    index_path = Path("src/static/index.html")
    content = index_path.read_text(encoding="utf-8")

    # Find occurrences of <table class="data-table"
    table_matches = list(re.finditer(r'<table[^>]+class=["\'][^"\']*data-table[^"\']*["\']', content))
    assert len(table_matches) >= 5, "Expected at least 5 data tables across views"

    for match in table_matches:
        start_idx = match.start()
        # Look backwards 150 chars to verify it is enclosed by <div class="table-container">
        snippet_before = content[max(0, start_idx - 160):start_idx]
        assert 'class="table-container"' in snippet_before or "table-container" in snippet_before, (
            f"Table at character {start_idx} is not enclosed in a table-container div."
        )


def test_app_js_handles_all_views_in_navigateto():
    """Verify that app.js explicitly handles all view switches without missing branches."""
    app_js_path = Path("src/static/app.js")
    assert app_js_path.exists(), "src/static/app.js must exist"
    content = app_js_path.read_text(encoding="utf-8")

    expected_views = [
        "overview",
        "boundary-lab",
        "scenarios",
        "history",
        "inspector",
        "vault",
        "verification",
        "tamper-lab",
        "reports",
        "settings",
    ]

    for view in expected_views:
        assert f"viewName === '{view}'" in content or f"'{view}':" in content, (
            f"View '{view}' must be explicitly handled in app.js navigation."
        )

    # Check for defensive null-handling patterns
    assert "escapeHtml" in content
    assert "toLowerCase()" not in content or "String(" in content, "Direct toLowerCase without string coercion is unsafe"


def test_view_api_endpoints_return_valid_structures():
    """Verify that all APIs supporting dashboard views return expected non-empty payloads."""
    # 1. Overview & Settings: /api/status
    res_status = client.get("/api/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "system_info" in status_data
    assert "docker_environment" in status_data
    assert "metrics" in status_data

    # 2. Boundary Lab: /api/boundary-lab/schema
    res_schema = client.get("/api/boundary-lab/schema")
    assert res_schema.status_code == 200
    schema_data = res_schema.json()
    assert "fixtures" in schema_data
    assert "workers" in schema_data
    assert len(schema_data["fixtures"]) >= 3

    # 3. History: /api/runs
    res_runs = client.get("/api/runs")
    assert res_runs.status_code == 200
    runs_data = res_runs.json()
    assert "runs" in runs_data
    assert isinstance(runs_data["runs"], list)

    # 4. Inspector: /api/findings
    res_findings = client.get("/api/findings")
    assert res_findings.status_code == 200
    findings_data = res_findings.json()
    assert "findings" in findings_data
    assert isinstance(findings_data["findings"], list)


def test_port_diagnostics_and_free_port_finder():
    """Verify that find_next_free_port identifies an available port and avoids worker ports 8081/8082."""
    free_port = find_next_free_port("127.0.0.1", start_port=8080)
    assert free_port != 8081, "Free port finder must avoid Red worker port 8081"
    assert free_port != 8082, "Free port finder must avoid Blue worker port 8082"
    assert not is_port_in_use("127.0.0.1", free_port)
