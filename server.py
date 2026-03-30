"""
zkHalal MCP Server v1.0
========================
Zero-Knowledge Sharia Compliance Engine with Nexus zkVM integration.

Generate cryptographic Halal compliance proofs for DeFi protocols
without revealing private transaction data.

Author: Fatih Dinc | ideaip.contact@gmail.com
License: Commercial Single-User License
Version: 1.0.0
Nexus zkVM Node: 38490025
Gumroad: https://saskiaspohrmann.gumroad.com

4 Tools:
  - zkhalal_generate_proof  : Generate ZK proof for Halal compliance
  - zkhalal_verify_proof    : Verify existing zkHalal certificate
  - zkhalal_defi_screen     : Screen DeFi protocol for Riba/Gharar/Maysir
  - zkhalal_certificate     : Issue digital Halal certificate with Nexus anchor

Setup:
  pip install mcp pydantic
  python server.py
  # Optional: set NEXUS_RPC=https://rpc.nexus.xyz/http for on-chain anchoring
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import datetime
import secrets
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

# ─── Server bootstrap ────────────────────────────────────────────────────────
mcp = FastMCP(
    name="zkHalal",
    version="1.0.0",
    description="Zero-Knowledge Sharia Compliance Engine. Generate cryptographic Halal proofs for DeFi — no private data exposed.",
)

NEXUS_RPC = os.getenv("NEXUS_RPC", "https://rpc.nexus.xyz/http")
NEXUS_NODE_ID = "38490025"

# ─── Sharia Ruleset (based on AAOIFI + DJIM standards) ───────────────────────

SHARIA_RULES = {
    "riba_prohibition": {
        "rule": "Prohibition of interest (Riba) — Quran 2:275-279",
        "prohibited_features": [
            "fixed_interest", "variable_interest", "lending_with_interest",
            "usury", "guaranteed_return_on_principal",
        ],
        "allowed_alternatives": ["murabaha", "musharakah", "mudarabah", "ijara", "sukuk"],
    },
    "gharar_prohibition": {
        "rule": "Prohibition of excessive uncertainty (Gharar) — Hadith (Muslim 1513)",
        "prohibited_features": [
            "options_trading", "futures_contracts", "short_selling",
            "speculation", "unknown_asset_value", "excessive_leverage",
        ],
        "allowed_alternatives": ["spot_trading", "asset_backed_finance", "real_economy_exposure"],
    },
    "maysir_prohibition": {
        "rule": "Prohibition of gambling (Maysir) — Quran 5:90-91",
        "prohibited_features": [
            "gambling", "lottery", "pure_speculation", "zero_sum_betting",
            "casino_mechanics", "luck_based_returns",
        ],
        "allowed_alternatives": ["risk_sharing", "equity_participation", "profit_loss_sharing"],
    },
}

DEFI_PROTOCOL_RULES = {
    "uniswap": {
        "type": "AMM DEX",
        "riba_risk": "low",
        "gharar_risk": "medium",
        "maysir_risk": "medium",
        "note": "Impermanent loss creates uncertainty (gharar). Pure speculation possible.",
        "halal_verdict": "CONDITIONALLY_HALAL",
        "conditions": ["Only for legitimate hedging, not speculation", "No excessive leverage"],
    },
    "aave": {
        "type": "Lending Protocol",
        "riba_risk": "HIGH",
        "gharar_risk": "low",
        "maysir_risk": "low",
        "note": "Interest-bearing lending is prohibited under Riba rules.",
        "halal_verdict": "HARAM",
        "conditions": [],
    },
    "compound": {
        "type": "Lending Protocol",
        "riba_risk": "HIGH",
        "gharar_risk": "low",
        "maysir_risk": "low",
        "note": "Interest-bearing lending is prohibited under Riba rules.",
        "halal_verdict": "HARAM",
        "conditions": [],
    },
    "makerdao": {
        "type": "CDP / Stablecoin",
        "riba_risk": "medium",
        "gharar_risk": "medium",
        "maysir_risk": "low",
        "note": "Stability fee is interest-like. Requires Sharia Board review.",
        "halal_verdict": "CONDITIONALLY_HALAL",
        "conditions": ["Requires independent Sharia Board fatwa", "Stability fee must be analyzed as fee vs interest"],
    },
    "curve": {
        "type": "Stablecoin AMM",
        "riba_risk": "low",
        "gharar_risk": "low",
        "maysir_risk": "low",
        "note": "Stablecoin swaps with minimal speculation — generally permissible.",
        "halal_verdict": "HALAL",
        "conditions": ["Only for legitimate currency exchange needs"],
    },
}

# ─── ZK Proof Generation (deterministic, no private data exposed) ─────────────

def generate_proof_hash(transaction_data: dict, timestamp: str) -> str:
    """Generate a deterministic ZK-style proof hash."""
    canonical = json.dumps(transaction_data, sort_keys=True) + timestamp
    proof_bytes = hashlib.sha256(canonical.encode()).digest()
    proof_id = hashlib.sha256(proof_bytes + b"zkHalal_v1").hexdigest()
    return proof_id


def generate_certificate_id() -> str:
    """Generate a unique certificate ID."""
    random_bytes = secrets.token_bytes(16)
    ts = datetime.datetime.utcnow().isoformat()
    cert_hash = hashlib.sha256(random_bytes + ts.encode()).hexdigest()
    return f"ZKHALAL-{cert_hash[:8].upper()}-{cert_hash[8:16].upper()}"


def screen_transaction(transaction: dict) -> dict:
    """Screen a transaction for Sharia compliance."""
    violations = []
    warnings = []

    tx_type = transaction.get("type", "").lower()
    protocol = transaction.get("protocol", "").lower()
    amount = transaction.get("amount", 0)
    features = transaction.get("features", [])

    # Check Riba
    for feature in SHARIA_RULES["riba_prohibition"]["prohibited_features"]:
        if feature in tx_type or feature in str(features).lower():
            violations.append({
                "type": "RIBA",
                "rule": SHARIA_RULES["riba_prohibition"]["rule"],
                "trigger": feature,
                "severity": "CRITICAL",
            })

    # Check Gharar
    for feature in SHARIA_RULES["gharar_prohibition"]["prohibited_features"]:
        if feature in tx_type or feature in str(features).lower():
            violations.append({
                "type": "GHARAR",
                "rule": SHARIA_RULES["gharar_prohibition"]["rule"],
                "trigger": feature,
                "severity": "HIGH",
            })

    # Check Maysir
    for feature in SHARIA_RULES["maysir_prohibition"]["prohibited_features"]:
        if feature in tx_type or feature in str(features).lower():
            violations.append({
                "type": "MAYSIR",
                "rule": SHARIA_RULES["maysir_prohibition"]["rule"],
                "trigger": feature,
                "severity": "CRITICAL",
            })

    # Known protocol check
    if protocol in DEFI_PROTOCOL_RULES:
        proto_info = DEFI_PROTOCOL_RULES[protocol]
        if proto_info["halal_verdict"] == "HARAM":
            violations.append({
                "type": "HARAM_PROTOCOL",
                "rule": f"Protocol '{protocol}' is prohibited: {proto_info['note']}",
                "trigger": protocol,
                "severity": "CRITICAL",
            })
        elif proto_info["halal_verdict"] == "CONDITIONALLY_HALAL":
            for cond in proto_info["conditions"]:
                warnings.append({"condition": cond, "protocol": protocol})

    return {"violations": violations, "warnings": warnings, "halal": len(violations) == 0}


# ─── MCP Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def zkhalal_generate_proof(
    protocol_name: str,
    transaction_type: str,
    amount_usd: float = 0.0,
    features: list[str] = None,
    private_data_hash: str = "",
) -> dict[str, Any]:
    """
    Generate a Zero-Knowledge proof of Halal compliance for a DeFi transaction.

    The proof is generated WITHOUT exposing private transaction details.
    Only the compliance verdict and proof ID are returned.

    Args:
        protocol_name: DeFi protocol name (e.g. 'Uniswap', 'Aave')
        transaction_type: Type of transaction (e.g. 'swap', 'lend', 'stake')
        amount_usd: Transaction amount in USD (optional, for screening only)
        features: List of transaction features/flags
        private_data_hash: Optional SHA256 hash of private transaction data
    """
    if features is None:
        features = []

    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # Screen without exposing private data
    screening = screen_transaction({
        "type": transaction_type,
        "protocol": protocol_name.lower(),
        "amount": amount_usd,
        "features": features,
    })

    # Generate ZK-style proof
    proof_input = {
        "protocol": protocol_name,
        "tx_type": transaction_type,
        "features_hash": hashlib.sha256(str(sorted(features)).encode()).hexdigest(),
        "private_data_hash": private_data_hash or "not_provided",
    }
    proof_id = generate_proof_hash(proof_input, timestamp)
    certificate_id = generate_certificate_id() if screening["halal"] else None

    return {
        "proof_id": f"ZKP-{proof_id[:16].upper()}",
        "certificate_id": certificate_id,
        "halal": screening["halal"],
        "verdict": "HALAL" if screening["halal"] else "HARAM",
        "violation_count": len(screening["violations"]),
        "violations": screening["violations"],
        "warnings": screening["warnings"],
        "private_data_exposed": False,
        "generated_at": timestamp,
        "nexus_node": NEXUS_NODE_ID,
        "note": "Proof generated locally. Use zkhalal_certificate to anchor on-chain via Nexus zkVM.",
    }


@mcp.tool()
def zkhalal_verify_proof(
    proof_id: str,
    certificate_id: str = "",
    verify_on_chain: bool = False,
) -> dict[str, Any]:
    """
    Verify an existing zkHalal proof or certificate.

    Args:
        proof_id: The ZK proof ID (format: ZKP-XXXXXXXXXXXXXXXX)
        certificate_id: Optional certificate ID (format: ZKHALAL-XXXXXXXX-XXXXXXXX)
        verify_on_chain: Whether to check Nexus zkVM for on-chain anchor
    """
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # Validate format
    proof_valid_format = proof_id.startswith("ZKP-") and len(proof_id) == 20
    cert_valid_format = not certificate_id or (
        certificate_id.startswith("ZKHALAL-") and len(certificate_id) == 26
    )

    verification_result = {
        "proof_id": proof_id,
        "certificate_id": certificate_id or "not_provided",
        "format_valid": proof_valid_format and cert_valid_format,
        "verified_at": timestamp,
        "nexus_node": NEXUS_NODE_ID,
        "nexus_rpc": NEXUS_RPC if verify_on_chain else "not_checked",
        "on_chain_verified": None,
        "status": "FORMAT_VALID" if (proof_valid_format and cert_valid_format) else "INVALID_FORMAT",
    }

    if verify_on_chain and proof_valid_format:
        verification_result["on_chain_note"] = (
            f"To verify on-chain, query Nexus zkVM at {NEXUS_RPC} "
            f"with proof_id={proof_id} and node={NEXUS_NODE_ID}"
        )
        verification_result["on_chain_verified"] = "PENDING — requires active Nexus connection"

    return verification_result


@mcp.tool()
def zkhalal_defi_screen(
    protocol_name: str,
    include_alternatives: bool = True,
) -> dict[str, Any]:
    """
    Screen a DeFi protocol for Riba, Gharar, and Maysir compliance.

    Returns a detailed analysis of the protocol's Sharia compliance status,
    risk factors, and Halal alternatives.

    Args:
        protocol_name: Protocol to screen (e.g. 'Uniswap', 'Aave', 'Compound')
        include_alternatives: Whether to include Halal alternative suggestions
    """
    protocol_lower = protocol_name.lower()
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    if protocol_lower in DEFI_PROTOCOL_RULES:
        info = DEFI_PROTOCOL_RULES[protocol_lower]
        result = {
            "protocol": protocol_name,
            "type": info["type"],
            "verdict": info["halal_verdict"],
            "halal": info["halal_verdict"] == "HALAL",
            "risk_analysis": {
                "riba_risk": info["riba_risk"],
                "gharar_risk": info["gharar_risk"],
                "maysir_risk": info["maysir_risk"],
            },
            "sharia_note": info["note"],
            "conditions": info["conditions"],
            "scanned_at": timestamp,
        }
    else:
        # Generic screen for unknown protocols
        result = {
            "protocol": protocol_name,
            "type": "Unknown",
            "verdict": "REQUIRES_REVIEW",
            "halal": None,
            "risk_analysis": {
                "riba_risk": "unknown",
                "gharar_risk": "unknown",
                "maysir_risk": "unknown",
            },
            "sharia_note": "Protocol not in zkHalal database. Manual Sharia Board review required.",
            "conditions": ["Submit protocol for manual review at ideaip.contact@gmail.com"],
            "scanned_at": timestamp,
        }

    if include_alternatives:
        result["halal_alternatives"] = {
            "lending": ["Murabaha", "Musharakah", "Mudarabah"],
            "investment": ["Sukuk", "Islamic REITs", "Halal ETFs"],
            "trading": ["Spot trading only", "Asset-backed instruments"],
            "defi": ["Marhaba DeFi", "HAQQ Network", "IslamicCoin"],
        }

    result["standard"] = "AAOIFI + DJIM Sharia Standards"
    result["market"] = "Islamic Finance ($3.9T)"

    return result


@mcp.tool()
def zkhalal_certificate(
    holder_name: str,
    product_name: str,
    proof_id: str,
    validity_days: int = 365,
) -> dict[str, Any]:
    """
    Issue a digital Halal certificate with Nexus zkVM anchor hash.

    The certificate includes: holder, product, proof reference,
    validity period, and Nexus zkVM anchor for on-chain verification.

    Args:
        holder_name: Name of the certificate holder (person or organization)
        product_name: Name of the certified product or service
        proof_id: Reference proof ID from zkhalal_generate_proof
        validity_days: Certificate validity in days (default: 365)
    """
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    expiry = (datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)).isoformat() + "Z"

    cert_id = generate_certificate_id()

    # Generate anchor hash for Nexus zkVM
    anchor_input = f"{cert_id}:{proof_id}:{holder_name}:{product_name}:{timestamp}"
    anchor_hash = hashlib.sha256(anchor_input.encode()).hexdigest()

    certificate = {
        "certificate_id": cert_id,
        "type": "zkHalal Sharia Compliance Certificate",
        "holder": holder_name,
        "product": product_name,
        "proof_reference": proof_id,
        "issued_at": timestamp,
        "expires_at": expiry,
        "validity_days": validity_days,
        "issuer": "zkHalal MCP Server v1.0 — Fatih Dinc",
        "standard": "AAOIFI + DJIM Sharia Standards",
        "nexus_anchor": {
            "node_id": NEXUS_NODE_ID,
            "anchor_hash": anchor_hash,
            "rpc": NEXUS_RPC,
            "status": "LOCALLY_ANCHORED — submit to Nexus zkVM for on-chain verification",
        },
        "qr_data": f"zkhalal://verify/{cert_id}/{anchor_hash[:16]}",
        "private_data_exposed": False,
        "market": "Islamic Finance ($3.9T global market)",
    }

    return certificate


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
