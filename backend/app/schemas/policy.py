from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class PolicyRuleAssertion(BaseModel):
    source: str  # e.g., "execution_trace.tool_calls.get_invoice.arguments.customer_id"
    operator: Literal["EQUALS", "NOT_CONTAINS", "MAX_SIMILARITY", "EXACT_TOKEN_MATCH"]
    expected: Optional[str] = None
    forbidden_tokens: Optional[List[str]] = None
    max_similarity_threshold: Optional[float] = None


class PolicyRule(BaseModel):
    id: str                        # e.g., "POL-BOLA-001"
    name: str
    owasp_category: str            # e.g., "LLM06" — category ID only
    owasp_name: str = ""           # e.g., "Excessive Agency"
    taxonomy_version: str = "2025" # versioned — "2025" or "2026"
    application_security_class: Optional[str] = None  # e.g., "BOLA/IDOR"
    resource: str                  # e.g., "invoice"
    rule_type: Literal["identity_match", "canary_absence", "entropy_and_token_match"]
    assertion: PolicyRuleAssertion
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    remediation: str
    required_capabilities: List[str] = []


class PolicyContract(BaseModel):
    target_name: str
    version: str = "1.0"
    taxonomy: str = "OWASP"
    taxonomy_version: str = "2025"
    policies: List[PolicyRule]
