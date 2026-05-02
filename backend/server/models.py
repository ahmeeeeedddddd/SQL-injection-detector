"""
models.py - Pydantic schemas for request and response validation.

Using Pydantic v2 (bundled with FastAPI). If you are on Pydantic v1,
replace `model_validator` / `field_validator` with `@validator`.
"""

from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    """
    Incoming payload for POST /scan.

    Fields
    ------
    input : str
        The raw string to be analysed for SQL injection.
    """

    input: str

    # ------------------------------------------------------------------ #
    # Validators                                                           #
    # ------------------------------------------------------------------ #

    @field_validator("input")
    @classmethod
    def input_must_not_be_blank(cls, value: str) -> str:
        """
        Reject payloads whose 'input' field is empty or contains only
        whitespace.  Raising a ValueError here causes FastAPI to return a
        422 Unprocessable Entity automatically; the route handler promotes
        blank-string cases to an explicit 400 Bad Request for clarity.
        """
        if not value.strip():
            raise ValueError("'input' must not be blank or whitespace-only.")
        return value  # return the original (un-stripped) value so detection
                      # can catch leading/trailing injection tokens too.


class ScanResponse(BaseModel):
    """
    JSON body returned by POST /scan.

    Fields
    ------
    input       : str   – the original string that was scanned.
    is_injection: bool  – True when the engine verdict is suspicious or malicious.
    score       : float – normalised confidence score in [0.0, 1.0].
    attack_type : str   – category label produced by the classifier
                          (e.g. 'union-based', 'time-based blind', 'none').
    verdict     : str   – human-readable verdict ('Safe', 'Suspicious', 'Malicious').
    """

    input: str
    is_injection: bool
    score: float
    attack_type: str
    verdict: str
