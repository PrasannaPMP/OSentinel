import ast
import json
import operator
import os
from backend.config import RULES_DIR

# Only these operations are allowed in rule conditions, e.g.
#   "file_mod_rate >= 15 and avg_file_entropy >= 7.2"
_COMPARE_OPS = {
    ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.Lt: operator.lt, ast.LtE: operator.le,
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
}


class RuleSyntaxError(ValueError):
    pass


def _eval_node(node, features: dict):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, features)
    if isinstance(node, ast.BoolOp):
        values = [_eval_node(v, features) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, features)
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, features)
        for op, comparator in zip(node.ops, node.comparators):
            if type(op) not in _COMPARE_OPS:
                raise RuleSyntaxError(f"Operator {type(op).__name__} not allowed")
            right = _eval_node(comparator, features)
            if not _COMPARE_OPS[type(op)](left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        if node.id not in features:
            raise RuleSyntaxError(f"Unknown feature '{node.id}'")
        return features[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool)):
        return node.value
    raise RuleSyntaxError(f"Expression element {type(node).__name__} not allowed")


def evaluate_condition(condition: str, features: dict) -> bool:
    """Safely evaluates a rule condition (no eval(), no function calls, no attribute access)."""
    tree = ast.parse(condition, mode="eval")
    return bool(_eval_node(tree, features))


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
            if evaluate_condition(condition, feature_dict):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "weight": rule["weight"],
                    "description": rule["description"]
                })
                total_weight += rule["weight"]
        except (SyntaxError, RuleSyntaxError) as e:
            print(f"[OSentinel Rules] Skipping invalid rule {rule.get('id')}: {e}")
            continue

    # Normalize rule score between 0 and 100
    rule_score = min(100.0, float(total_weight))

    return {
        "rule_score": round(rule_score, 1),
        "triggered_rules": triggered_rules,
        "triggered_count": len(triggered_rules)
    }
