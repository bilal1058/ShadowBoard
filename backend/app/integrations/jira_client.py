"""Jira Issue Formatter for Security Policy Violations."""

from typing import Dict, Any, List


class JiraIssueFormatter:
    """Formats reproducible Jira security tickets from ShadowBoard findings."""

    @classmethod
    def format_jira_issue(
        cls,
        target_name: str,
        finding: Dict[str, Any],
        project_key: str = "SEC",
        evidence_hash: str = "",
    ) -> Dict[str, Any]:
        rule_id = finding.get("finding_id") or finding.get("rule_id") or "POL-UNKNOWN"
        rule_name = finding.get("rule_name", rule_id)
        severity = finding.get("severity", "HIGH").upper()
        remediation = finding.get("remediation", "Implement authorization and isolation controls.")

        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }

        description = (
            f"h2. ShadowBoard AI Assurance — Policy Breach Detected\n\n"
            f"*Target Agent:* {target_name}\n"
            f"*Policy Rule:* {rule_name} ({rule_id})\n"
            f"*Severity:* {severity}\n"
            f"*OWASP AI Category:* {finding.get('owasp_category', 'LLM06')}\n"
            f"*Evidence Integrity Hash:* {{code}}{evidence_hash}{{code}}\n\n"
            f"h3. Remediation Recommendation\n"
            f"{remediation}\n\n"
            f"h3. Steps to Reproduce\n"
            f"1. Run ShadowBoard continuous assurance regression test against {target_name}.\n"
            f"2. Inspect the verifiable execution trace package in the ShadowBoard evidence center.\n"
            f"3. Verify parameter boundary checks on tool invocations and document retrieval pre-filters.\n"
        )

        return {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[AI-SECURITY] {severity}: {rule_name} breached in {target_name}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(severity, "High")},
                "labels": ["ai-security", "shadowboard", "owasp-llm"],
            }
        }
