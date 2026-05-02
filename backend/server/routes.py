"""
routes.py - POST /scan endpoint definition.

Responsibilities
----------------
1. Accept and validate a JSON body via the ScanRequest model.
2. Guard against blank / whitespace-only input (returns HTTP 400).
3. Delegate detection to engine.detector.detect().
4. Map the raw engine output to the ScanResponse schema and return it.

Import note
-----------
The engine package lives at  backend/engine/  which is a sibling of
backend/server/.  When the application is launched from the *backend/*
directory (or when PYTHONPATH includes it), the import  `from engine.detector
import detect`  resolves correctly.  app.py sets sys.path accordingly.
"""

from fastapi import APIRouter, HTTPException

# Engine entry-point — detect() lives one package up (backend/engine/)
from engine.detector import detect

# Local Pydantic schemas
from server.models import ScanRequest, ScanResponse

# ---------------------------------------------------------------------------
# Router setup
# ---------------------------------------------------------------------------

router = APIRouter()


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------

@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Scan a string for SQL injection",
    tags=["Detection"],
)
def scan(payload: ScanRequest) -> ScanResponse:
    """
    Analyse the supplied input string for SQL injection signatures.

    Request body (JSON)
    -------------------
    {
        "input": "<string to analyse>"
    }

    Returns (JSON)
    --------------
    {
        "input"        : "<original string>",
        "is_injection" : true | false,
        "score"        : 0.0 – 1.0,
        "attack_type"  : "<category>",
        "verdict"      : "Safe" | "Suspicious" | "Malicious"
    }

    Error responses
    ---------------
    400 Bad Request  – input is empty / whitespace-only.
    422 Unprocessable Entity – malformed JSON or missing 'input' field
                               (handled automatically by FastAPI/Pydantic).
    """

    # ------------------------------------------------------------------ #
    # Extra guard: pydantic validator already rejects blank strings with  #
    # a 422, but we also handle the edge-case where a caller might strip  #
    # the string themselves and send e.g. {"input": "   "}.               #
    # ------------------------------------------------------------------ #
    if not payload.input.strip():
        raise HTTPException(
            status_code=400,
            detail="'input' must not be empty or whitespace-only.",
        )

    # ------------------------------------------------------------------ #
    # Run detection engine                                                #
    # ------------------------------------------------------------------ #
    result = detect(payload.input)

    # Engine returns:
    #   verdict      : "safe" | "suspicious" | "malicious"
    #   score        : int 0–10
    #   attack_type  : str  (category label)
    #   matched_rules: list[str]
    #   explanation  : str

    raw_verdict: str = result["verdict"]          # lowercase from engine
    raw_score: int   = result["score"]            # integer 0–10

    # ------------------------------------------------------------------ #
    # Normalise score to [0.0, 1.0]                                       #
    # ------------------------------------------------------------------ #
    normalised_score: float = round(raw_score / 10.0, 2)

    # ------------------------------------------------------------------ #
    # Derive is_injection flag                                            #
    # Any verdict other than "safe" is considered an injection attempt.  #
    # ------------------------------------------------------------------ #
    is_injection: bool = raw_verdict != "safe"

    # ------------------------------------------------------------------ #
    # Capitalise verdict for a human-readable response                    #
    # ------------------------------------------------------------------ #
    human_verdict: str = raw_verdict.capitalize()   # "Safe" / "Suspicious" / "Malicious"

    # ------------------------------------------------------------------ #
    # Attack type: use "none" when the engine returns "generic" and no   #
    # rules were matched (clean input).                                   #
    # ------------------------------------------------------------------ #
    attack_type: str = result["attack_type"]
    if not result["matched_rules"]:
        attack_type = "none"

    return ScanResponse(
        input=payload.input,
        is_injection=is_injection,
        score=normalised_score,
        attack_type=attack_type,
        verdict=human_verdict,
    )
