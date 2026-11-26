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

    def test_iam_casing_normalization_lowercase(self):
        """Validates that lowercase keys are normalized and properly audited (QA-001)."""
        policy = json.dumps({
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "LowercaseStmt",
                    "effect": "allow",
                    "action": "*",
                    "resource": "*",
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-001", rule_ids)
        self.assertIn("IAM-002", rule_ids)
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertEqual(res["score"], 15)

    def test_iam_casing_normalization_mixed_case(self):
        """Validates that mixed-case keys ('ACTION', 'resource') are normalized (QA-001)."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "ACTION": "*",
                    "resource": "*",
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-001", rule_ids)
        self.assertIn("IAM-002", rule_ids)

    def test_iam_notresource_allow_detected(self):
        """Validates detection of NotResource with Effect: Allow as IAM-002 (QA-002)."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "NotResourceExemption",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "NotResource": "arn:aws:s3:::exempt-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-002", rule_ids)
        self.assertEqual(res["risk_level"], "CRITICAL")

    def test_iam_deny_rules_ignored_no_false_positive(self):
        """Validates that defensive Deny statements do not trigger false positive IAM-008 (QA-003)."""
        # TLS Enforcement Deny
        tls_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnforceTLSOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        })
        res_tls = audit_iam(tls_policy)
        self.assertEqual(res_tls["score"], 100)
        self.assertEqual(res_tls["risk_level"], "LOW")
        self.assertEqual(len(res_tls["findings"]), 0)

        # IP Whitelist Deny
        ip_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyOutsideCorpIP",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"NotIpAddress": {"aws:SourceIp": ["198.51.100.0/24"]}},
                }
            ],
        })
        res_ip = audit_iam(ip_policy)
        self.assertEqual(res_ip["score"], 100)
        self.assertEqual(res_ip["risk_level"], "LOW")
        self.assertEqual(len(res_ip["findings"]), 0)

    def test_iam_principal_dict_wildcard(self):
        """Validates detection of Principal: {'AWS': '*'} as IAM-008."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-008", rule_ids)

    def test_iam_passrole_condition_validations(self):
        """Validates iam:PassRole condition enforcement (QA-005)."""
        # 1. Missing condition -> IAM-009
        policy_no_cond = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                }
            ],
        })
        res1 = audit_iam(policy_no_cond)
        self.assertIn("IAM-009", [f["id"] for f in res1["findings"]])

        # 2. Empty condition {} -> IAM-009
        policy_empty_cond = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {},
                }
            ],
        })
        res2 = audit_iam(policy_empty_cond)
        self.assertIn("IAM-009", [f["id"] for f in res2["findings"]])

        # 3. Irrelevant condition (aws:username) -> IAM-009
        policy_irrelevant_cond = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:username": "developer-alice"}},
                }
            ],
        })
        res3 = audit_iam(policy_irrelevant_cond)
        self.assertIn("IAM-009", [f["id"] for f in res3["findings"]])

        # 4. Valid condition (iam:PassedToService) -> No IAM-009
        policy_valid_cond = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/ec2-role",
                    "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
                }
            ],
        })
        res4 = audit_iam(policy_valid_cond)
        self.assertNotIn("IAM-009", [f["id"] for f in res4["findings"]])

    def test_iam_partial_and_mixed_action_wildcards(self):
        """Validates detection of wildcards mixed in lists and in action radicals (QA-007)."""
        # Mixed list with '*'
        policy_mixed = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "*"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res_mixed = audit_iam(policy_mixed)
        self.assertIn("IAM-001", [f["id"] for f in res_mixed["findings"]])

        # Verb radical wildcard s3:Get*
        policy_radical = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:Get*", "s3:Put*"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        res_radical = audit_iam(policy_radical)
        self.assertIn("IAM-001", [f["id"] for f in res_radical["findings"]])

    def test_tf_s3_authenticated_read_and_public_acls(self):
        """Validates detection of authenticated-read and public ACLs on S3 (QA-006)."""
        # Inline authenticated-read
        hcl_auth = """
resource "aws_s3_bucket" "b1" {
  bucket = "auth-read-bucket"
  acl    = "authenticated-read"
}
"""
        res_auth = audit_terraform(hcl_auth)
        self.assertIn("TF-002", [f["id"] for f in res_auth["findings"]])

        # External aws_s3_bucket_acl
        hcl_ext = """
resource "aws_s3_bucket" "b2" {
  bucket = "public-bucket"
}
resource "aws_s3_bucket_acl" "b2_acl" {
  bucket = aws_s3_bucket.b2.id
  acl    = "public-read"
}
"""
        res_ext = audit_terraform(hcl_ext)
        self.assertIn("TF-002", [f["id"] for f in res_ext["findings"]])

        # Private S3 ACL safe
        hcl_private = """
resource "aws_s3_bucket" "b3" {
  bucket = "private-bucket"
  acl    = "private"
  tags   = { Environment = "prod", Project = "onion" }
}
resource "aws_s3_bucket_public_access_block" "b3_pab" {
  bucket                  = aws_s3_bucket.b3.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "b3_sse" {
  bucket = aws_s3_bucket.b3.id
}
"""
        res_private = audit_terraform(hcl_private)
        self.assertNotIn("TF-002", [f["id"] for f in res_private["findings"]])
        self.assertEqual(res_private["score"], 100)

    def test_tf_comments_stripping_no_false_positive(self):
        """Validates that comments (#, //, /* */) are cleanly stripped without false positives."""
        hcl = """
resource "aws_security_group" "safe_sg" {
  name = "safe-sg"
  # ingress { from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"] }
  // ingress { from_port = 3389, to_port = 3389, cidr_blocks = ["0.0.0.0/0"] }
  /*
  ingress {
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  */
  tags = { Environment = "prod", Project = "onion" }
}
"""
        res = audit_terraform(hcl)
        self.assertNotIn("TF-001", [f["id"] for f in res["findings"]])

    def test_tf_ebs_rds_encryption_omitted_and_false(self):
        """Validates encryption detection for EBS and RDS (omitted vs false vs true)."""
        # EBS omitted
        hcl_ebs_omitted = """
resource "aws_ebs_volume" "vol1" {
  availability_zone = "us-east-1a"
  size              = 20
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        res_ebs1 = audit_terraform(hcl_ebs_omitted)
        self.assertIn("TF-006", [f["id"] for f in res_ebs1["findings"]])

        # EBS explicit false
        hcl_ebs_false = """
resource "aws_ebs_volume" "vol2" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        res_ebs2 = audit_terraform(hcl_ebs_false)
        self.assertIn("TF-006", [f["id"] for f in res_ebs2["findings"]])

        # RDS omitted
        hcl_rds_omitted = """
resource "aws_db_instance" "db1" {
  instance_class = "db.t3.micro"
  engine         = "postgres"
  tags           = { Environment = "prod", Project = "onion" }
}
"""
        res_rds1 = audit_terraform(hcl_rds_omitted)
        self.assertIn("TF-007", [f["id"] for f in res_rds1["findings"]])

        # RDS explicit false
        hcl_rds_false = """
resource "aws_db_instance" "db2" {
  instance_class    = "db.t3.micro"
  engine            = "postgres"
  storage_encrypted = false
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        res_rds2 = audit_terraform(hcl_rds_false)
        self.assertIn("TF-007", [f["id"] for f in res_rds2["findings"]])

    def test_iam_principal_list_whitespace_wildcard(self):
        """Validates detection of wildcard with whitespace inside Principal list."""
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:role/legit", " * "]},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ],
        })
        res = audit_iam(policy)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("IAM-008", rule_ids)

    def test_iam_passrole_empty_service_condition(self):
        """Validates that iam:PassedToService mapped to empty string or empty list is rejected."""
        policy_empty_str = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": "   "}},
                }
            ],
        })
        res1 = audit_iam(policy_empty_str)
        self.assertIn("IAM-009", [f["id"] for f in res1["findings"]])

        policy_empty_list = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"iam:PassedToService": []}},
                }
            ],
        })
        res2 = audit_iam(policy_empty_list)
        self.assertIn("IAM-009", [f["id"] for f in res2["findings"]])

    def test_tf_ingress_swapped_ports_and_ipv6_attribute(self):
        """Validates detection of sensitive ports when from_port > to_port and with ipv6_cidr_blocks."""
        hcl_swapped = """
resource "aws_security_group" "swapped_sg" {
  name = "swapped-sg"
  ingress {
    from_port   = 25
    to_port     = 20
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        res_swapped = audit_terraform(hcl_swapped)
        self.assertIn("TF-001", [f["id"] for f in res_swapped["findings"]])

        hcl_ipv6 = """
resource "aws_security_group" "ipv6_sg" {
  name = "ipv6-sg"
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
        res_ipv6 = audit_terraform(hcl_ipv6)
        self.assertIn("TF-001", [f["id"] for f in res_ipv6["findings"]])

    def test_tf_quoted_encryption_and_acl_whitespace(self):
        """Validates detection of quoted booleans in encryption and whitespace in S3 ACL."""
        hcl = """
resource "aws_ebs_volume" "quoted_ebs" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = "false"
}
resource "aws_db_instance" "quoted_db" {
  instance_class    = "db.t3.micro"
  engine            = "postgres"
  storage_encrypted = "false"
}
resource "aws_s3_bucket" "spaced_bucket" {
  bucket = "spaced-acl-bucket"
  acl    = "  public-read  "
}
"""
        res = audit_terraform(hcl)
        rule_ids = [f["id"] for f in res["findings"]]
        self.assertIn("TF-006", rule_ids)
        self.assertIn("TF-007", rule_ids)
        self.assertIn("TF-002", rule_ids)


if __name__ == "__main__":
    unittest.main()
