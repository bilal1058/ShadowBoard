"""Slack Block Kit Formatter & Dispatcher for Security Alerts."""

from typing import Dict, Any, List


class SlackAlertFormatter:
    """Formats rich Slack messages for security breaches."""

    @classmethod
    def format_scan_alert(
        cls,
        target_name: str,
        scan_id: int,
        risk_score: int,
        risk_grade: str,
        findings: List[Dict[str, Any]],
        dashboard_url: str = "http://localhost:8000",
    ) -> Dict[str, Any]:
        confirmed_findings = [f for f in findings if f.get("status") in ("CONFIRMED", "LIKELY")]
        has_critical = any(f.get("severity") == "CRITICAL" for f in confirmed_findings)

        status_emoji = ":rotating_light:" if has_critical else (":warning:" if confirmed_findings else ":white_check_mark:")
        header_text = f"{status_emoji} ShadowBoard Alert: {target_name} Scanned"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:* {target_name}"},
                    {"type": "mrkdwn", "text": f"*Scan Run ID:* #{scan_id}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:* `{risk_score}/100` (Grade: *{risk_grade}*)"},
                    {"type": "mrkdwn", "text": f"*Violations Confirmed:* `{len(confirmed_findings)}`"},
                ]
            }
        ]

        if confirmed_findings:
            finding_bullets = []
            for f in confirmed_findings[:5]:
                sev = f.get("severity", "HIGH")
                rule = f.get("rule_name") or f.get("finding_id")
                finding_bullets.append(f"• *[{sev}]* {rule}")

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Confirmed Policy Violations:*\n" + "\n".join(finding_bullets)
                }
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Inspect Evidence in ShadowBoard", "emoji": True},
                    "url": f"{dashboard_url}/#scans",
                    "style": "danger" if confirmed_findings else "primary"
                }
            ]
        })

        return {"text": f"ShadowBoard Scan #{scan_id} Completed for {target_name}", "blocks": blocks}
