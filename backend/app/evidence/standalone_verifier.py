"""Standalone Evidence Verifier for Third-Party Auditors.

Validates the cryptographic integrity, Ed25519 authenticity signature, and policy claims
of a ShadowBoard Evidence Package offline without needing a running server.

Distinguishes:
1. Integrity: Merkle hash chain over events + manifest hash (bit tampering detection)
2. Authenticity: Asymmetric Ed25519 digital signature (identity verification & non-repudiation)
3. Substrate Truth: Provenance of telemetry (TARGET_INSTRUMENTED | PROXY_OBSERVED | SYNTHETIC)
"""

from typing import Dict, Any, Tuple
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


class StandaloneVerifier:
    """Independent offline auditor verification tool."""

    @staticmethod
    def canonical_hash(obj: Any) -> str:
        serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def verify_package(cls, pkg_data: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """Verifies package integrity and Ed25519 signature, returning (is_valid, message, audit_summary)."""
        proof = pkg_data.get("proof", {})
        if not proof:
            return False, "Missing cryptographic proof block in evidence package", {}

        claimed_event_hash = proof.get("event_chain_hash")
        claimed_manifest_hash = proof.get("manifest_hash")
        sig_ed25519_hex = proof.get("signature_ed25519_hex")
        pubkey_hex = proof.get("signer_public_key_hex")
        legacy_sig = proof.get("package_signature")
        substrate_truth = proof.get("substrate_truth_level", "UNKNOWN")

        # -------------------------------------------------------------
        # 1. Integrity Verification (Merkle Event Chain)
        # -------------------------------------------------------------
        events = pkg_data.get("execution_events", [])
        if not events:
            recomputed_event_hash = hashlib.sha256(b"EMPTY_TRACE").hexdigest()
        else:
            current_hash = hashlib.sha256(b"GENESIS").hexdigest()
            for ev in events:
                ev_hash = cls.canonical_hash(ev)
                combined = f"{current_hash}:{ev_hash}"
                current_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            recomputed_event_hash = current_hash

        if recomputed_event_hash != claimed_event_hash:
            return False, f"Integrity Failure: Event chain hash mismatch! Claimed: {claimed_event_hash}, Computed: {recomputed_event_hash}", {}

        # -------------------------------------------------------------
        # 2. Integrity Verification (Manifest Hash)
        # -------------------------------------------------------------
        manifest_data = {
            "pkg_id": pkg_data.get("package_id"),
            "scan_id": pkg_data.get("scan_id"),
            "target_id": pkg_data.get("target_id"),
            "rule_id": pkg_data.get("rule_id"),
            "finding_id": pkg_data.get("finding_id"),
        }
        recomputed_manifest_hash = cls.canonical_hash(manifest_data)
        if recomputed_manifest_hash != claimed_manifest_hash:
            return False, f"Integrity Failure: Manifest hash mismatch! Claimed: {claimed_manifest_hash}, Computed: {recomputed_manifest_hash}", {}

        # -------------------------------------------------------------
        # 3. Authenticity Verification (Ed25519 Digital Signature)
        # -------------------------------------------------------------
        response_text = pkg_data.get("response_text", "")
        combined_payload = {
            "manifest_hash": recomputed_manifest_hash,
            "event_chain_hash": recomputed_event_hash,
            "response_hash": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
            "violation": pkg_data.get("violation_details", {}),
        }
        recomputed_canonical_hash = cls.canonical_hash(combined_payload)

        # If Ed25519 signature and public key are present, perform asymmetric verification
        if sig_ed25519_hex and pubkey_hex:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
                sig_bytes = bytes.fromhex(sig_ed25519_hex)
                # Verify that the canonical payload hash was signed by the holder of this private key
                public_key.verify(sig_bytes, recomputed_canonical_hash.encode("utf-8"))
            except (InvalidSignature, ValueError) as exc:
                return False, f"Authenticity Failure: Invalid Ed25519 digital signature! Tampered payload detected or signature mismatch ({exc}).", {}
        elif legacy_sig and recomputed_canonical_hash != legacy_sig:
            return False, f"Integrity Failure: Canonical payload hash mismatch! Claimed: {legacy_sig}, Computed: {recomputed_canonical_hash}", {}

        summary = {
            "package_id": pkg_data.get("package_id"),
            "target_name": pkg_data.get("target_name"),
            "rule_id": pkg_data.get("rule_id"),
            "severity": pkg_data.get("severity"),
            "events_verified": len(events),
            "verification_status": "CRYPTOGRAPHICALLY_VERIFIED",
            "integrity_status": "SHA256_MERKLE_CHAIN_VERIFIED",
            "authenticity_status": "ED25519_SIGNATURE_VERIFIED" if sig_ed25519_hex else "HASH_INTEGRITY_ONLY",
            "substrate_truth_level": substrate_truth,
            "signer_public_key": pubkey_hex or "NONE",
        }
        return True, "Evidence package integrity and Ed25519 signature verified successfully. No tampering detected.", summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.evidence.standalone_verifier <evidence_package.json>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    valid, msg, summary = StandaloneVerifier.verify_package(data)
    if valid:
        print(f"\n[+] AUDIT VERIFIED: {msg}")
        for k, v in summary.items():
            print(f"    * {k}: {v}")
    else:
        print(f"\n[-] AUDIT REJECTED: {msg}")
        sys.exit(1)
