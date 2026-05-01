"""
classifier.py - Given matched rule names, return the attack category.
"""
from engine.rules import SQLI_RULES

def classify_attack(matched_rule_names: list) -> str:
    """
    Given a list of matched rule names, return the attack category.
    If multiple match, return the category of the highest-severity rules.
    
    Args:
        matched_rule_names: List of strings (rule names)
        
    Returns:
        String representing the attack category.
    """
    if not matched_rule_names:
        return "generic"
        
    # Filter rules that were matched
    matched_rules = [r for r in SQLI_RULES if r["name"] in matched_rule_names]
    
    if not matched_rules:
        return "generic"
        
    # Sort by severity descending
    matched_rules.sort(key=lambda x: x["severity"], reverse=True)
    
    # Return the category of the highest severity match
    return matched_rules[0]["category"]
