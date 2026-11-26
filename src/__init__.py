"""
Package initialization for Onion Auditor engine.
"""

from .auditor import audit_iam, audit_terraform, calculate_score_and_risk
from .handler import lambda_handler

__all__ = ["audit_iam", "audit_terraform", "calculate_score_and_risk", "lambda_handler"]
