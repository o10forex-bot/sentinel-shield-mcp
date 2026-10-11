"""x402 Protocol (HTTP 402 Payment Required) handler for autonomous M2M micropayments."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field

from sentinel_shield.config import config


class PaymentChallenge(BaseModel):
    """x402 Payment Challenge returned when an autonomous agent requests a paid tool."""

    status: int = Field(default=402, description="HTTP status code")
    protocol: str = Field(default="x402/1.0", description="Protocol version identifier")
    price_usdc: float = Field(..., description="Cost of invocation in USDC")
    recipient_wallet: str = Field(..., description="EVM wallet address to receive settlement")
    network: str = Field(..., description="Settlement blockchain (polygon or base)")
    currency: str = Field(default="USDC", description="Token symbol")
    resource: str = Field(..., description="Tool or resource being purchased")


class PaymentVerification(BaseModel):
    """Payment verification outcome."""

    authorized: bool = Field(..., description="Whether tool execution is authorized")
    payment_receipt: Optional[str] = Field(default=None, description="Transaction hash or payment receipt")
    challenge: Optional[PaymentChallenge] = Field(default=None, description="Challenge if unauthorized")


def evaluate_x402_payment(
    resource_name: str,
    payment_proof: Optional[str] = None,
) -> PaymentVerification:
    """Evaluate whether caller satisfies x402 payment requirements.

    In development / permissive mode (enforce_x402=False), all calls are authorized
    while returning the payment requirement metadata for client discovery.
    """
    if not config.enforce_x402:
        return PaymentVerification(
            authorized=True,
            payment_receipt="free_tier_local_evaluation",
        )

    if payment_proof and len(payment_proof.strip()) >= 32:
        # Proof provided (e.g. valid tx hash or signed settlement voucher)
        return PaymentVerification(
            authorized=True,
            payment_receipt=payment_proof.strip(),
        )

    # Issue x402 challenge
    challenge = PaymentChallenge(
        price_usdc=config.price_per_audit_usdc,
        recipient_wallet=config.payout_wallet,
        network=config.payout_network,
        resource=resource_name,
    )
    return PaymentVerification(
        authorized=False,
        challenge=challenge,
    )
