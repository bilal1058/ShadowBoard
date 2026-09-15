"""Policy-as-Code Compiler.

Parses, validates, and compiles declarative YAML / JSON security policies
into executable rule objects.
"""

from typing import Dict, Any, List, Optional
import yaml
from pydantic import BaseModel, Field, ValidationError


class PolicyCondition(BaseModel):
    type: str
    assertion: Optional[str] = None
    session_identity_field: Optional[str] = "session_user_id"
    tool_argument_field: Optional[str] = "customer_id"
    forbidden_tokens: Optional[List[str]] = None
    restricted_tools: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    blocked_tags: Optional[List[str]] = None
    requires_approval: Optional[bool] = None
    quarantine_untrusted_context: Optional[bool] = None
    max_similarity_threshold: Optional[float] = None
    custom_params: Dict[str, Any] = Field(default_factory=dict)


class CompiledRule(BaseModel):
    id: str
    name: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    owasp_category: str = "LLM01"
    owasp_name: str = ""
    description: str = ""
    target_scope: Dict[str, Any] = Field(default_factory=dict)
    condition: PolicyCondition
    remediation: str = ""


class CompiledPolicy(BaseModel):
    version: str = "1.0"
    name: str
    description: str = ""
    taxonomy: str = "OWASP"
    taxonomy_version: str = "2025"
    rules: List[CompiledRule]
    raw_yaml: str = ""


class PolicyCompilerError(Exception):
    pass


class PolicyCompiler:
    """Compiles YAML or JSON into verified, executable security contracts."""

    @staticmethod
    def compile_yaml(yaml_str: str) -> CompiledPolicy:
        """Parses and validates a YAML policy document."""
        try:
            parsed = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            raise PolicyCompilerError(f"YAML Syntax Error: {e}")

        if not isinstance(parsed, dict):
            raise PolicyCompilerError("Invalid policy format: Expected root dictionary")

        return PolicyCompiler.compile_dict(parsed, raw_yaml=yaml_str)

    @staticmethod
    def compile_dict(data: Dict[str, Any], raw_yaml: str = "") -> CompiledPolicy:
        """Validates and compiles a dictionary into CompiledPolicy."""
        try:
            name = data.get("name", "Untitled Policy")
            version = str(data.get("version", "1.0"))
            description = data.get("description", "")
            taxonomy = data.get("taxonomy", "OWASP")
            taxonomy_version = str(data.get("taxonomy_version", "2025"))

            raw_rules = data.get("rules", [])
            if not isinstance(raw_rules, list):
                raise PolicyCompilerError("'rules' must be a list of rule definitions")

            compiled_rules: List[CompiledRule] = []
            for idx, r in enumerate(raw_rules):
                if not isinstance(r, dict):
                    raise PolicyCompilerError(f"Rule at index {idx} must be a dictionary")

                rule_id = r.get("id")
                if not rule_id:
                    raise PolicyCompilerError(f"Rule at index {idx} is missing required 'id' field")

                rule_name = r.get("name", rule_id)
                severity = r.get("severity", "MEDIUM").upper()
                if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = "MEDIUM"

                owasp_cat = r.get("owasp_category", "LLM01")
                owasp_name = r.get("owasp_name", "")
                desc = r.get("description", "")
                remediation = r.get("remediation", "Review and enforce security boundaries.")
                target_scope = r.get("target_scope", {})

                cond_data = r.get("condition", {})
                if not isinstance(cond_data, dict) or not cond_data.get("type"):
                    raise PolicyCompilerError(f"Rule '{rule_id}' is missing valid condition with 'type'")

                condition = PolicyCondition(
                    type=cond_data.get("type"),
                    assertion=cond_data.get("assertion"),
                    session_identity_field=cond_data.get("session_identity_field", "session_user_id"),
                    tool_argument_field=cond_data.get("tool_argument_field", "customer_id"),
                    forbidden_tokens=cond_data.get("forbidden_tokens"),
                    restricted_tools=cond_data.get("restricted_tools"),
                    allowed_tools=cond_data.get("allowed_tools"),
                    blocked_tags=cond_data.get("blocked_tags"),
                    requires_approval=cond_data.get("requires_approval"),
                    quarantine_untrusted_context=cond_data.get("quarantine_untrusted_context"),
                    max_similarity_threshold=cond_data.get("max_similarity_threshold"),
                )

                compiled_rules.append(
                    CompiledRule(
                        id=rule_id,
                        name=rule_name,
                        severity=severity,
                        owasp_category=owasp_cat,
                        owasp_name=owasp_name,
                        description=desc,
                        target_scope=target_scope,
                        condition=condition,
                        remediation=remediation,
                    )
                )

            return CompiledPolicy(
                version=version,
                name=name,
                description=description,
                taxonomy=taxonomy,
                taxonomy_version=taxonomy_version,
                rules=compiled_rules,
                raw_yaml=raw_yaml or yaml.dump(data),
            )

        except ValidationError as e:
            raise PolicyCompilerError(f"Validation Error in policy schema: {e}")
