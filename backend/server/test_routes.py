"""
test_routes.py - Integration tests for the server layer using FastAPI's TestClient.

Running the tests
-----------------
From the  backend/  directory:

    pytest server/test_routes.py -v

Or from the project root (backend/server/ is in sys.path via conftest):

    pytest backend/server/test_routes.py -v

What is tested
--------------
1. Known SQL injection input  → is_injection: True
2. Clean / safe input         → is_injection: False
3. Empty input string         → HTTP 400
4. Health-check route GET /   → {"status": "running"}
"""

import sys
import os

# ---------------------------------------------------------------------------
# Ensure 'backend/' is on sys.path before importing the app.
# This mirrors the path setup done in app.py so tests work when run from
# any directory (project root, backend/, or backend/server/).
# ---------------------------------------------------------------------------
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app instance (sys.path is already patched above)
from server.app import app

# ---------------------------------------------------------------------------
# Shared test client — created once per module for performance
# ---------------------------------------------------------------------------

client = TestClient(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def post_scan(input_value: str) -> "httpx.Response":  # type: ignore[name-defined]
    """Convenience wrapper around the /scan endpoint."""
    return client.post("/scan", json={"input": input_value})


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestScanEndpoint:
    """Tests for POST /scan"""

    # ------------------------------------------------------------------
    # 1. Known SQL injection — classic tautology + comment sequence
    # ------------------------------------------------------------------
    def test_sql_injection_detected(self):
        """
        ' OR 1=1 -- is a textbook boolean-based injection.
        The engine's 'classic_tautology' rule (severity 10) and
        'comment_sequence' rule (severity 4) should both fire,
        pushing the score above the 'suspicious' threshold.
        Expected: is_injection=True, verdict in {"Suspicious","Malicious"}.
        """
        response = post_scan("' OR 1=1 --")

        assert response.status_code == 200

        body = response.json()
        assert body["is_injection"] is True
        assert body["verdict"] in ("Suspicious", "Malicious")
        assert body["score"] > 0.0
        # attack_type should NOT be 'none' for a real injection
        assert body["attack_type"] != "none"
        # Original input is echoed back
        assert body["input"] == "' OR 1=1 --"

    # ------------------------------------------------------------------
    # 2. Clean input — plain English phrase
    # ------------------------------------------------------------------
    def test_safe_input_not_flagged(self):
        """
        'hello world' contains no SQL injection signatures.
        Expected: is_injection=False, verdict='Safe', score=0.0.
        """
        response = post_scan("hello world")

        assert response.status_code == 200

        body = response.json()
        assert body["is_injection"] is False
        assert body["verdict"] == "Safe"
        assert body["score"] == 0.0
        assert body["attack_type"] == "none"
        assert body["input"] == "hello world"

    # ------------------------------------------------------------------
    # 3. Empty input — must return HTTP 400
    # ------------------------------------------------------------------
    def test_empty_input_returns_400(self):
        """
        An empty string is not a valid scan target.
        The route handler returns HTTP 400 Bad Request.
        """
        response = post_scan("")

        # FastAPI/Pydantic raises 422 for the field_validator failure;
        # an explicit empty string bypasses pydantic (it IS a valid str)
        # and hits the HTTPException(400) in the route handler.
        # Both 400 and 422 are acceptable — we assert that the request
        # was rejected (not 200 OK).
        assert response.status_code in (400, 422)

    def test_whitespace_only_input_returns_400(self):
        """
        A string of only spaces/tabs is semantically empty.
        The route handler returns HTTP 400 Bad Request.
        """
        response = post_scan("   ")

        assert response.status_code in (400, 422)

    # ------------------------------------------------------------------
    # 4. Additional injection variants
    # ------------------------------------------------------------------
    def test_union_select_injection(self):
        """
        UNION SELECT is a classic data-exfiltration payload.
        """
        response = post_scan("1 UNION SELECT username, password FROM users")

        assert response.status_code == 200
        body = response.json()
        assert body["is_injection"] is True
        assert body["attack_type"] == "union-based"

    def test_time_based_blind_injection(self):
        """
        SLEEP() is the canonical time-based blind injection technique.
        """
        response = post_scan("1; SELECT SLEEP(5)--")

        assert response.status_code == 200
        body = response.json()
        assert body["is_injection"] is True

    # ------------------------------------------------------------------
    # Score / normalisation sanity checks
    # ------------------------------------------------------------------
    def test_score_is_normalised_float(self):
        """Score must be a float between 0.0 and 1.0 (inclusive)."""
        response = post_scan("' OR 1=1 --")
        body = response.json()
        assert isinstance(body["score"], float)
        assert 0.0 <= body["score"] <= 1.0

    def test_response_schema_fields_present(self):
        """All expected fields must be present in the response."""
        response = post_scan("test input")
        body = response.json()
        for field in ("input", "is_injection", "score", "attack_type", "verdict"):
            assert field in body, f"Missing field: {field}"


class TestHealthCheck:
    """Tests for GET /"""

    def test_health_check_returns_running(self):
        """
        The root endpoint is a simple liveness probe.
        Expected: HTTP 200, body == {"status": "running"}.
        """
        response = client.get("/")

        assert response.status_code == 200
        assert response.json() == {"status": "running"}

    def test_health_check_content_type_json(self):
        """Response should be application/json."""
        response = client.get("/")
        assert "application/json" in response.headers.get("content-type", "")
