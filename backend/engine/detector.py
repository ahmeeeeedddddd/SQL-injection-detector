"""
detector.py - Main detect() function and scoring logic.
"""
import re
from engine.rules import SQLI_RULES
from engine.classifier import classify_attack

def detect(input_str: str) -> dict:
    """
    Analyzes the input string for SQL injection signatures.
    
    Args:
        input_str: The string to analyze.
        
    Returns:
        dict: {
          "verdict": "safe | suspicious | malicious",
          "score": int,
          "matched_rules": list[str],
          "attack_type": str,
          "explanation": str
        }
    """
    matched_rules = []
    total_score = 0
    
    # Run against all patterns (case-insensitive)
    for rule in SQLI_RULES:
        if re.search(rule["pattern"], input_str, re.IGNORECASE):
            matched_rules.append(rule["name"])
            total_score += rule["severity"]
            
    # Cap score at 10
    final_score = min(total_score, 10)
    
    # Determine verdict
    if final_score <= 2:
        verdict = "safe"
    elif final_score <= 5:
        verdict = "suspicious"
    else:
        verdict = "malicious"
        
    # Get classification
    attack_type = classify_attack(matched_rules)
    
    # Explanation
    if not matched_rules:
        explanation = "No SQL injection signatures detected."
    else:
        explanation = f"Detected SQLi signatures: {', '.join(matched_rules)}."
        
    return {
        "verdict": verdict,
        "score": final_score,
        "matched_rules": matched_rules,
        "attack_type": attack_type,
        "explanation": explanation
    }
