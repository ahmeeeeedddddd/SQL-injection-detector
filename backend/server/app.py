"""
app.py - FastAPI application factory and entry point.

Layout
------
backend/
├── engine/          ← detection engine (do NOT modify)
│   ├── detector.py
│   ├── rules.py
│   └── classifier.py
└── server/          ← this layer
    ├── app.py       ← YOU ARE HERE
    ├── routes.py
    └── models.py

Running the server
------------------
From the  backend/  directory:

    uvicorn server.app:app --reload --port 8000

Or simply:

    python server/app.py        (uses the __main__ block below)

CORS note
---------
The frontend is served from a separate origin (e.g. file:// or localhost:3000),
so we allow all origins with CORSMiddleware.  Restrict this in production.
"""

import sys
import os

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
# Insert the *backend/* directory into sys.path so that both
#   • `from engine.detector import detect`   (engine package)
#   • `from server.models  import ...`        (server package)
# resolve correctly regardless of the working directory the user starts from.

_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# FastAPI & middleware imports (must come AFTER sys.path is patched)
# ---------------------------------------------------------------------------
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.routes import router   # the /scan endpoint

# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SQL Injection Detector API",
    description=(
        "A lightweight REST API that analyses strings for SQL injection "
        "signatures using regex-based rules and OWASP payload signatures."
    ),
    version="1.0.0",
    docs_url="/docs",       # Swagger UI
    redoc_url="/redoc",     # ReDoc UI
)

# ---------------------------------------------------------------------------
# CORS — allow all origins so the browser-based frontend can reach the API
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # ← restrict to specific origin in production
    allow_credentials=True,
    allow_methods=["*"],          # GET, POST, OPTIONS, …
    allow_headers=["*"],          # Content-Type, Authorization, …
)

# ---------------------------------------------------------------------------
# Register routers
# ---------------------------------------------------------------------------
app.include_router(router)        # registers POST /scan

# ---------------------------------------------------------------------------
# Health-check endpoint
# ---------------------------------------------------------------------------

@app.get(
    "/",
    summary="Health check",
    tags=["Health"],
    response_description="Server status",
)
def health_check() -> dict:
    """
    Simple liveness probe.  Returns {"status": "running"} when the server
    is up and reachable.
    """
    return {"status": "running"}


# ---------------------------------------------------------------------------
# Direct execution entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server.app:app",   # module path (works when CWD is backend/)
        host="0.0.0.0",
        port=8000,
        reload=True,        # hot-reload on file changes (dev mode)
    )
