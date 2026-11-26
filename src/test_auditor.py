"""
Unit tests for Onion Auditor Core Engine (src/auditor.py).
Uses only standard library (unittest).
"""

import json
import unittest

from src.auditor import (
    audit_iam,
    audit_terraform,
    calculate_score_and_risk,
)


class TestAuditorEngine(unittest.TestCase):
    def test_score_calculation_deductions(self):
        """Validates score deduction and risk mapping rules."""
        # 1 CRITICAL (-30) -> Score 70, but has CRITICAL -> CRITICAL
        findings = [{"severity": "CRITICAL"}]
        score, risk = calculate_score_and_risk(findings)
        self.assertEqual(score, 70)
        self.assertEqual(risk, "CRITICAL")

        # 1 HIGH (-15) -> Score 85 -> MEDIUM
        findings = [{"severity": "HIGH"}]
        score, risk = calculate_score_and_risk(findings)
        self.assertEqual(score, 85)
        self.assertEqual(risk, "MEDIUM")

        # 2 HIGH (-30) + 1 MEDIUM (-10) -> Score 60 -> HIGH
        findings = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "MEDIUM"}]
        score, risk = calculate_score_and_risk(findings)
        self.assertEqual(score, 60)
        self.assertEqual(risk, "HIGH")

        # 1 LOW (-5) -> Score 95 -> LOW
        findings = [{"severity": "LOW"}]
        score, risk = calculate_score_and_risk(findings)
        self.assertEqual(score, 95)
        self.assertEqual(risk, "LOW")

        # Empty findings -> Score 100 -> LOW
        score, risk = calculate_score_and_risk([])
        self.assertEqual(score, 100)
        self.assertEqual(risk, "LOW")

        # Excessive findings clamped to 0
        findings = [{"severity": "CRITICAL"}] * 5
        score, risk = calculate_score_and_risk(findings)
        self.assertEqual(score, 0)
        self.assertEqual(risk, "CRITICAL")

    def test_iam_action_service_wildcard(self):
        """Validates detection of service wildcards (e.g. s3:*) as IAM-001."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-001", rule_ids)

    def test_iam_destructive_action_wildcard(self):
        """Validates detection of destructive wildcards (*:Delete*) as IAM-004."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:Delete*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-004", rule_ids)

    def test_iam_missing_version(self):
        """Validates detection of missing Version as IAM-006."""
        policy = json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ]
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-006", rule_ids)

    def test_tf_port_range_exposure(self):
        """Validates detection of sensitive ports within a port range."""
        hcl = """
resource "aws_security_group" "wide_range" {
  name = "wide-sg"
  ingress {
    from_port   = 20
    to_port     = 30
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        res = audit_terraform(hcl)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("TF-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
