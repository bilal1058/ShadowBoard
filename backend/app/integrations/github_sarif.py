"""GitHub SARIF and JUnit XML Generator for CI/CD Pipeline Integrations.

Converts ShadowBoard security findings into standard SARIF 2.1.0 format
(for GitHub Security code scanning alerts) and JUnit XML (for GitLab/Jenkins).
"""

from typing import Dict, Any, List
import json
import xml.etree.ElementTree as ET


class SARIFGenerator:
    """Generates OASIS SARIF 2.1.0 documents from ShadowBoard findings."""

    @classmethod
    def generate_sarif(cls, target_name: str, scan_id: int, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        rules = []
        results = []

        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }

        for f in findings:
            rule_id = f.get("finding_id") or f.get("rule_id") or "SB-VULN"
            rule_name = f.get("rule_name") or rule_id
            severity = f.get("severity", "HIGH").upper()
            status = f.get("status", "CONFIRMED")
            remediation = f.get("remediation", "Enforce security boundaries.")

            rules.append({
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "fullDescription": {"text": f"Policy breach: {remediation}"},
                "defaultConfiguration": {"level": level_map.get(severity, "error")},
                "properties": {
                    "tags": ["security", "ai-assurance", f"owasp-{f.get('owasp_category', 'LLM01')}"],
                    "precision": "very-high"
                }
            })

            if status in ("CONFIRMED", "LIKELY"):
                results.append({
                    "ruleId": rule_id,
                    "level": level_map.get(severity, "error"),
                    "message": {
                        "text": f"AI Policy Breach detected in {target_name}: {rule_name}. Remediation: {remediation}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"agents/{target_name.replace(' ', '_').lower()}.py"},
                            "region": {"startLine": 1}
                        }
                    }]
                })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ShadowBoard Enterprise AI Assurance",
                        "informationUri": "https://github.com/bilal1058/ShadowBoard",
                        "semanticVersion": "2.0.0",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }


class JUnitGenerator:
    """Generates JUnit XML test report for CI/CD test dashboards."""

    @classmethod
    def generate_junit_xml(cls, target_name: str, scan_id: int, findings: List[Dict[str, Any]]) -> str:
        testsuite = ET.Element("testsuite", {
            "name": f"ShadowBoard_{target_name.replace(' ', '_')}",
            "tests": str(len(findings)),
            "failures": str(sum(1 for f in findings if f.get("status") in ("CONFIRMED", "LIKELY"))),
            "errors": "0",
            "skipped": str(sum(1 for f in findings if f.get("status") in ("NOT_APPLICABLE",))),
        })

        for f in findings:
            rule_id = f.get("finding_id") or f.get("rule_id") or "SB-VULN"
            rule_name = f.get("rule_name") or rule_id
            status = f.get("status", "PASS")
            remediation = f.get("remediation", "")

            testcase = ET.SubElement(testsuite, "testcase", {
                "classname": f"ShadowBoard.{target_name.replace(' ', '_')}",
                "name": f"{rule_id}_{rule_name.replace(' ', '_')}",
                "time": "0.12",
            })

            if status in ("CONFIRMED", "LIKELY"):
                failure = ET.SubElement(testcase, "failure", {
                    "message": f"Security Policy Violation: {rule_name}",
                    "type": f.get("severity", "HIGH"),
                })
                failure.text = f"Remediation: {remediation}\nEvidence Hash: {f.get('evidence_hash', '')}"

        return ET.tostring(testsuite, encoding="unicode")
