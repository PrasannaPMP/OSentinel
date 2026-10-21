import json
import os
from backend.config import RULES_DIR

def load_rules():
    rules_file = RULES_DIR / "security_rules.json"
    if not os.path.exists(rules_file):
        return []
    try:
        with open(rules_file, "r") as f:
            return json.load(f)
    except Exception:
        return []

def evaluate_rules(feature_dict: dict):
    rules = load_rules()
    triggered_rules = []
    total_weight = 0
    
    for rule in rules:
        condition = rule.get("condition", "False")
        try:
            # Safe evaluation using feature_dict as local scope
            is_matched = eval(condition, {"__builtins__": {}}, feature_dict)
            if is_matched:
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "weight": rule["weight"],
                    "description": rule["description"]
                })
                total_weight += rule["weight"]
        except Exception:
            continue
            
    # Normalize rule score between 0 and 100
    rule_score = min(100.0, float(total_weight))
    
    return {
        "rule_score": round(rule_score, 1),
        "triggered_rules": triggered_rules,
        "triggered_count": len(triggered_rules)
    }
