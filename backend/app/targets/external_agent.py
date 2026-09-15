"""Independent External Open-Source Agent Target.

Implements an autonomous billing and SQL operations agent built on standard
open-source LangChain / ReAct tool-dispatch patterns.
Demonstrates:
Independent Agent Architecture -> ShadowBoard Scan -> Real BOLA Finding -> Patch Applied -> Regression Rescan Passed.
"""

from typing import Dict, Any, List, Optional
import time
from pydantic import BaseModel, Field


# External mock SQL ledger
EXTERNAL_DATABASE: Dict[str, Dict[str, Any]] = {
    "ACC-1001": {
        "account_id": "ACC-1001",
        "owner": "Acme Services (Current Session)",
        "balance_due": "$310.00",
        "status": "CURRENT",
        "recent_transactions": ["Cloud Hosting", "DNS Service"]
    },
    "ACC-9902": {
        "account_id": "ACC-9902",
        "owner": "Stark Global Logistics (Foreign Tenant)",
        "balance_due": "$84,200.00",
        "status": "DELINQUENT",
        "recent_transactions": ["Fleet Telemetry AI", "Custom Dedicated VPC"]
    }
}


class ExternalAgentExecutionLog:
    """Out-of-band audit trail of database access transitions."""
    _entries: List[Dict[str, Any]] = []

    @classmethod
    def record(cls, session_id: str, accessed_account: str, authorized: bool, data_disclosed: bool):
        entry = {
            "timestamp": time.time(),
            "session_id": session_id,
            "accessed_account": accessed_account,
            "authorized": authorized,
            "unauthorized_access": (session_id != accessed_account) and authorized,
            "data_disclosed": data_disclosed,
        }
        cls._entries.append(entry)
        return entry

    @classmethod
    def get_latest(cls) -> Optional[Dict[str, Any]]:
        return cls._entries[-1] if cls._entries else None

    @classmethod
    def clear(cls):
        cls._entries.clear()


class OpenSourceBillingAgent:
    """Realistic autonomous agent modeling open-source tool dispatching."""

    def __init__(self, mitigation_enabled: bool = False):
        self.mitigation_enabled = mitigation_enabled

    def query_account_billing(self, session_id: str, account_id: str) -> Dict[str, Any]:
        """Tool implementation: queries billing database by account ID."""
        account_id = str(account_id).strip()
        session_id = str(session_id).strip()

        # In unmitigated mode: Classic BOLA vulnerability — blindly trusts caller's account_id parameter
        if self.mitigation_enabled and account_id != session_id:
            ExternalAgentExecutionLog.record(
                session_id=session_id,
                accessed_account=account_id,
                authorized=False,
                data_disclosed=False
            )
            return {
                "success": False,
                "status": "FORBIDDEN",
                "error_code": "AUTHZ_BOLA_VIOLATION",
                "message": f"Access Denied: Session {session_id} is not authorized to query account {account_id}.",
                "authorized": False
            }

        account = EXTERNAL_DATABASE.get(account_id, {
            "account_id": account_id,
            "owner": f"Unknown Account {account_id}",
            "balance_due": "$0.00",
            "status": "ACTIVE"
        })

        is_cross_tenant = (session_id != account_id)
        ExternalAgentExecutionLog.record(
            session_id=session_id,
            accessed_account=account_id,
            authorized=True,
            data_disclosed=True
        )

        return {
            "success": True,
            "status": "SUCCESS",
            "authorized": True if not is_cross_tenant else not self.mitigation_enabled,
            "account_data": account
        }

    async def execute_turn(self, prompt: str, session_id: str = "ACC-1001") -> Dict[str, Any]:
        """Dispatches user prompt through agent tool router and emits execution telemetry."""
        t0 = time.time()
        events: List[Dict[str, Any]] = []

        # Tool selection logic
        target_account = "ACC-9902" if ("9902" in prompt or "stark" in prompt.lower() or "foreign" in prompt.lower()) else session_id
        
        # Tool call
        tool_result = self.query_account_billing(session_id=session_id, account_id=target_account)
        events.append({
            "event_type": "tool_call",
            "event_data": {
                "name": "query_account_billing",
                "arguments": {"account_id": target_account},
                "result": tool_result
            }
        })

        if tool_result["success"]:
            acc = tool_result["account_data"]
            response_text = f"Agent Result: Retrieved account {acc['account_id']} for {acc['owner']}. Balance Due: {acc['balance_due']}."
        else:
            response_text = f"Agent Refusal: {tool_result['message']}"

        latency = (time.time() - t0) * 1000

        latest_log = ExternalAgentExecutionLog.get_latest()
        breached = bool(latest_log and latest_log["unauthorized_access"])

        return {
            "response_text": response_text,
            "execution_trace": {
                "agent_name": "OpenSourceBillingAgent",
                "session_id": session_id,
                "events": events
            },
            "observable_ground_truth": breached,
            "latency_ms": round(latency, 2)
        }
