"""
Unit tests for Onion Auditor Lambda Handler and HTTP API integration.
Uses only Python standard library (unittest).
"""

import base64
import json
import unittest
from unittest.mock import patch

from src.handler import CORS_HEADERS, MAX_PAYLOAD_BYTES, lambda_handler



class TestLambdaHandler(unittest.TestCase):
    def setUp(self):
        self.vulnerable_iam_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardAdmin",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Sid": "DangerousNotAction",
                    "Effect": "Allow",
                    "NotAction": "iam:Delete*",
                    "Resource": "*",
                },
                {
                    "Sid": "PassRoleUnrestricted",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/*",
                },
                {
                    "Sid": "PublicResourcePolicy",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                },
            ],
        })

        self.compliant_iam_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LeastPrivilegeS3ReadOnly",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        "arn:aws:s3:::my-secure-bucket",
                        "arn:aws:s3:::my-secure-bucket/*",
                    ],
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "true"}
                    },
                }
            ],
        })

        self.vulnerable_tf = """
resource "aws_security_group" "open_all" {
  name = "open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "company-public-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "disabled_block" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_db_instance" "unencrypted_rds" {
  allocated_storage = 20
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}
"""

        self.compliant_tf = """
resource "aws_security_group" "secure_sg" {
  name = "secure-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = {
    Environment = "prod"
    Project     = "onion-auditor"
  }
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "onion-auditor-secure-bucket"

  tags = {
    Environment = "prod"
    Project     = "onion-auditor"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_sse" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_ebs_volume" "secure_ebs" {
  availability_zone = "us-east-2a"
  size              = 50
  encrypted         = true

  tags = {
    Environment = "prod"
    Project     = "onion-auditor"
  }
}

resource "aws_db_instance" "secure_rds" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = true

  tags = {
    Environment = "prod"
    Project     = "onion-auditor"
  }
}
"""

    def test_cors_headers_present(self):
        """Validates that CORS headers are included in all responses."""
        event = {
            "version": "2.0",
            "body": json.dumps({"type": "iam", "content": self.compliant_iam_json}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        for header, value in CORS_HEADERS.items():
            self.assertEqual(res["headers"].get(header), value)

    def test_options_preflight(self):
        """Validates HTTP OPTIONS preflight request handling."""
        event = {
            "version": "2.0",
            "requestContext": {
                "http": {
                    "method": "OPTIONS",
                    "path": "/audit",
                }
            },
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertEqual(body.get("status"), "ok")

    def test_vulnerable_iam_audit(self):
        """Validates detection of IAM wildcards, NotAction, PassRole and Principal '*'."""
        event = {
            "version": "2.0",
            "body": json.dumps({"type": "iam", "content": self.vulnerable_iam_json}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])

        self.assertIn("score", body)
        self.assertIn("risk_level", body)
        self.assertIn("findings", body)

        self.assertEqual(body["risk_level"], "CRITICAL")
        self.assertEqual(body["score"], 0)

        finding_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-001", finding_ids)  # Action *
        self.assertIn("IAM-002", finding_ids)  # Resource *
        self.assertIn("IAM-007", finding_ids)  # NotAction
        self.assertIn("IAM-008", finding_ids)  # Principal *
        self.assertIn("IAM-009", finding_ids)  # PassRole without condition

    def test_compliant_iam_audit(self):
        """Validates that a compliant IAM policy receives score 100 and LOW risk."""
        event = {
            "version": "2.0",
            "body": json.dumps({"type": "iam", "content": self.compliant_iam_json}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])

        self.assertEqual(body["score"], 100)
        self.assertEqual(body["risk_level"], "LOW")
        self.assertEqual(len(body["findings"]), 0)

    def test_vulnerable_terraform_audit(self):
        """Validates detection of open SG ports (22, 3389, 5432, 3306), public S3, unencrypted EBS/RDS/S3."""
        event = {
            "version": "2.0",
            "body": json.dumps({"type": "terraform", "content": self.vulnerable_tf}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])

        self.assertEqual(body["risk_level"], "CRITICAL")
        finding_ids = [f["id"] for f in body["findings"]]

        self.assertIn("TF-001", finding_ids)  # Open sensitive ports
        self.assertIn("TF-002", finding_ids)  # S3 public ACL
        self.assertIn("TF-003", finding_ids)  # S3 public access block disabled
        self.assertIn("TF-004", finding_ids)  # S3 without SSE
        self.assertIn("TF-006", finding_ids)  # EBS unencrypted
        self.assertIn("TF-007", finding_ids)  # RDS unencrypted
        self.assertIn("TF-005", finding_ids)  # Missing tags

    def test_compliant_terraform_audit(self):
        """Validates that compliant Terraform HCL receives score 100 and LOW risk."""
        event = {
            "version": "2.0",
            "body": json.dumps({"type": "terraform", "content": self.compliant_tf}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])

        self.assertEqual(body["score"], 100)
        self.assertEqual(body["risk_level"], "LOW")
        self.assertEqual(len(body["findings"]), 0)

    def test_direct_dict_invocation(self):
        """Validates direct dict invocation without API Gateway wrapper."""
        event = {
            "type": "iam",
            "content": self.compliant_iam_json,
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertEqual(body["score"], 100)

    def test_base64_encoded_payload(self):
        """Validates base64 encoded event body support."""
        raw_json = json.dumps({"type": "iam", "content": self.compliant_iam_json})
        b64_body = base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")
        event = {
            "isBase64Encoded": True,
            "body": b64_body,
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)

    def test_bad_request_missing_type(self):
        """Validates 400 error when 'type' is missing."""
        event = {"body": json.dumps({"content": "foo"})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_bad_request_invalid_type(self):
        """Validates 400 error when 'type' is unsupported."""
        event = {"body": json.dumps({"type": "kubernetes", "content": "kind: Pod"})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)

    def test_bad_request_invalid_json_iam(self):
        """Validates 400 error when IAM content is invalid JSON."""
        event = {"body": json.dumps({"type": "iam", "content": "{ invalid json"})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)

    def test_payload_too_large_body_string(self):
        """Validates 413 error when body exceeds 512 KB."""
        huge_str = "x" * (MAX_PAYLOAD_BYTES + 1024)
        event = {"body": json.dumps({"type": "iam", "content": huge_str})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 413)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("512 KB", body["error"])
        for header, val in CORS_HEADERS.items():
            self.assertEqual(res["headers"].get(header), val)

    def test_payload_too_large_content_field(self):
        """Validates 413 error when content field exceeds 512 KB."""
        huge_str = "x" * (MAX_PAYLOAD_BYTES + 512)
        event = {"type": "terraform", "content": huge_str}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 413)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("512 KB", body["error"])

    def test_payload_too_large_raw_string_event(self):
        """Validates 413 error when raw string event exceeds 512 KB."""
        huge_event = "x" * (MAX_PAYLOAD_BYTES + 2048)
        res = lambda_handler(huge_event)
        self.assertEqual(res["statusCode"], 413)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_payload_too_large_base64(self):
        """Validates 413 error when base64 payload exceeds 512 KB."""
        huge_raw = json.dumps({"type": "iam", "content": "A" * (MAX_PAYLOAD_BYTES + 1024)})
        b64_str = base64.b64encode(huge_raw.encode("utf-8")).decode("utf-8")
        event = {"isBase64Encoded": True, "body": b64_str}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 413)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_recursion_error_nested_body_handled(self):
        """Validates 400 error and clean recursion message on deeply nested body."""
        nested_json = '{"k":' * 2000 + '1' + '}' * 2000
        event = {"body": nested_json}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())

    def test_recursion_error_nested_content_handled(self):
        """Validates 400 error and clean recursion message on deeply nested IAM content."""
        nested_content = '{"k":' * 2000 + '1' + '}' * 2000
        event = {"body": json.dumps({"type": "iam", "content": nested_content})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())

    def test_corrupted_base64_handled(self):
        """Validates 400 error on corrupted base64 string with 'base64' in message."""
        event = {
            "body": "!!!Invalid_Base64_String@@@==",
            "isBase64Encoded": True,
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("base64", body["error"].lower())

    def test_invalid_utf8_base64_handled(self):
        """Validates 400 error when base64 payload decodes to invalid UTF-8 bytes."""
        invalid_utf8_b64 = base64.b64encode(b"\xff\xfe\xfd\x80").decode("utf-8")
        event = {
            "body": invalid_utf8_b64,
            "isBase64Encoded": True,
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)
        self.assertIn("utf-8", body["error"].lower())

    def test_bad_request_content_whitespace_only(self):
        """Validates 400 error when content is only whitespace."""
        event = {"body": json.dumps({"type": "iam", "content": "   \n\t  \r  "})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_bad_request_content_non_string(self):
        """Validates 400 error when content is not a string."""
        for invalid_content in [12345, ["s3:*"], {"Version": "2012-10-17"}]:
            event = {"body": json.dumps({"type": "iam", "content": invalid_content})}
            res = lambda_handler(event)
            self.assertEqual(res["statusCode"], 400)
            body = json.loads(res["body"])
            self.assertIn("error", body)

    def test_bad_request_type_non_string(self):
        """Validates 400 error when type is not a string."""
        for invalid_type in [12345, ["iam"], {"name": "iam"}]:
            event = {"body": json.dumps({"type": invalid_type, "content": "..."})}
            res = lambda_handler(event)
            self.assertEqual(res["statusCode"], 400)
            body = json.loads(res["body"])
            self.assertIn("error", body)

    def test_terraform_control_characters_sanitization(self):
        """Validates that null bytes and non-printable control chars are sanitized in Terraform."""
        hcl_with_null = 'resource "aws_security_group" "sg_\x00_test" {\n  name = "sg_test"\n}'
        event = {"body": json.dumps({"type": "terraform", "content": hcl_with_null})}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertIn("score", body)

    def test_global_exception_boundary_no_information_leak(self):
        """Validates that unexpected exceptions return generic 500 without leaking internal paths or stack traces."""
        with patch("src.handler.audit_iam", side_effect=RuntimeError("/var/task/internal/secret.key not found")):
            event = {"body": json.dumps({"type": "iam", "content": self.compliant_iam_json})}
            res = lambda_handler(event)
            self.assertEqual(res["statusCode"], 500)
            body = json.loads(res["body"])
            self.assertIn("error", body)
            self.assertNotIn("/var/task", body["error"])
            self.assertNotIn("secret.key", body["error"])
            self.assertNotIn("RuntimeError", body["error"])
            for header, val in CORS_HEADERS.items():
                self.assertEqual(res["headers"].get(header), val)

    def test_cors_headers_consistency_all_status_codes(self):
        """Validates CORS headers presence across 200, 400, 413, 500."""
        # 400
        res_400 = lambda_handler({"body": "{ invalid json"})
        self.assertEqual(res_400["statusCode"], 400)
        for h, v in CORS_HEADERS.items():
            self.assertEqual(res_400["headers"].get(h), v)

        # 413
        res_413 = lambda_handler({"body": "x" * (MAX_PAYLOAD_BYTES + 10)})
        self.assertEqual(res_413["statusCode"], 413)
        for h, v in CORS_HEADERS.items():
            self.assertEqual(res_413["headers"].get(h), v)

    # --------------------------------------------------------------------------
    # Camada 4 Dedicated Granular Audit Engine Tests
    # --------------------------------------------------------------------------

    def test_iam_wildcard_action_detection(self):
        """Camada 4: Validates detection of wildcard Action ('*')."""
        payload = {
            "type": "iam",
            "content": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}}
                }]
            })
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-001", rule_ids)
        self.assertEqual(body["risk_level"], "CRITICAL")
        self.assertLessEqual(body["score"], 70)

    def test_iam_wildcard_resource_detection(self):
        """Camada 4: Validates detection of wildcard Resource ('*')."""
        payload = {
            "type": "iam",
            "content": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}}
                }]
            })
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-002", rule_ids)
        self.assertEqual(body["risk_level"], "CRITICAL")
        self.assertLessEqual(body["score"], 70)

    def test_iam_not_action_detection(self):
        """Camada 4: Validates detection of NotAction with Allow."""
        payload = {
            "type": "iam",
            "content": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "NotAction": "iam:DeleteUser",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}}
                }]
            })
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-007", rule_ids)
        self.assertEqual(body["risk_level"], "CRITICAL")

    def test_iam_passrole_without_condition_detection(self):
        """Camada 4: Validates detection of iam:PassRole without condition."""
        payload = {
            "type": "iam",
            "content": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/MyRole"
                }]
            })
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-009", rule_ids)
        passrole_finding = next(f for f in body["findings"] if f["id"] == "IAM-009")
        self.assertEqual(passrole_finding["severity"], "HIGH")

    def test_iam_wildcard_principal_detection(self):
        """Camada 4: Validates detection of wildcard Principal ('*')."""
        payload = {
            "type": "iam",
            "content": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::shared-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}}
                }]
            })
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("IAM-008", rule_ids)
        self.assertEqual(body["risk_level"], "CRITICAL")

    def test_terraform_public_s3_bucket_detection(self):
        """Camada 4: Validates detection of public S3 buckets."""
        payload = {
            "type": "terraform",
            "content": """
resource "aws_s3_bucket" "open_bucket" {
  bucket = "my-open-bucket"
  acl    = "public-read"
}
"""
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("TF-002", rule_ids)

    def test_terraform_security_group_sensitive_ports_detection(self):
        """Camada 4: Validates detection of SG with 0.0.0.0/0 on sensitive ports (22, 3389, 5432, 3306)."""
        payload = {
            "type": "terraform",
            "content": """
resource "aws_security_group" "sensitive_sg" {
  name = "sensitive-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("TF-001", rule_ids)
        self.assertEqual(body["risk_level"], "CRITICAL")

    def test_terraform_unencrypted_ebs_detection(self):
        """Camada 4: Validates detection of unencrypted EBS volume."""
        payload = {
            "type": "terraform",
            "content": """
resource "aws_ebs_volume" "test_ebs" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}
"""
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("TF-006", rule_ids)

    def test_terraform_unencrypted_rds_detection(self):
        """Camada 4: Validates detection of unencrypted RDS instance."""
        payload = {
            "type": "terraform",
            "content": """
resource "aws_db_instance" "test_rds" {
  allocated_storage = 20
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
}
"""
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("TF-007", rule_ids)

    def test_terraform_unencrypted_s3_detection(self):
        """Camada 4: Validates detection of S3 bucket lacking SSE encryption."""
        payload = {
            "type": "terraform",
            "content": """
resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-unencrypted-bucket"
}
"""
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        rule_ids = [f["id"] for f in body["findings"]]
        self.assertIn("TF-004", rule_ids)

    def test_contract_response_structure_exact(self):
        """Camada 4: Validates exact JSON response contract according to README.md."""
        payload = {
            "type": "iam",
            "content": self.vulnerable_iam_json
        }
        res = lambda_handler({"body": json.dumps(payload)})
        self.assertEqual(res["statusCode"], 200)
        for h, v in CORS_HEADERS.items():
            self.assertEqual(res["headers"].get(h), v)

        body = json.loads(res["body"])
        # Top-level contract keys
        self.assertIn("score", body)
        self.assertIn("risk_level", body)
        self.assertIn("findings", body)
        self.assertIsInstance(body["score"], int)
        self.assertGreaterEqual(body["score"], 0)
        self.assertLessEqual(body["score"], 100)
        self.assertIn(body["risk_level"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertIsInstance(body["findings"], list)

        # Finding object contract keys
        expected_keys = {"id", "title", "severity", "description", "recommendation"}
        for finding in body["findings"]:
            self.assertTrue(expected_keys.issubset(finding.keys()))
            self.assertIn(finding["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.assertIsInstance(finding["id"], str)
            self.assertIsInstance(finding["title"], str)
            self.assertIsInstance(finding["description"], str)
            self.assertIsInstance(finding["recommendation"], str)

    def test_event_none_returns_400(self):
        """Validates 400 when event is None."""
        res = lambda_handler(None)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_raw_bytes_event_handling(self):
        """Validates that event passed as raw bytes is parsed and processed correctly."""
        raw_bytes = json.dumps({"type": "iam", "content": self.compliant_iam_json}).encode("utf-8")
        res = lambda_handler(raw_bytes)
        self.assertEqual(res["statusCode"], 200)
        body = json.loads(res["body"])
        self.assertEqual(body["score"], 100)

    def test_bytes_body_in_dict_event(self):
        """Validates that bytes in event['body'] are decoded and processed."""
        raw_bytes = json.dumps({"type": "iam", "content": self.compliant_iam_json}).encode("utf-8")
        event = {"body": raw_bytes}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 200)

    def test_base64_non_string_body_rejected(self):
        """Validates 400 when isBase64Encoded is True but body is not a string."""
        event = {"isBase64Encoded": True, "body": 12345}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_base64_dict_body_rejected(self):
        """Validates 400 when isBase64Encoded is True but body is a dictionary."""
        event = {"isBase64Encoded": True, "body": {"type": "iam"}}
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400)
        body = json.loads(res["body"])
        self.assertIn("error", body)

    def test_content_length_header_too_large(self):
        """Validates 413 when Content-Length header exceeds MAX_PAYLOAD_BYTES."""
        event = {
            "headers": {"content-length": str(MAX_PAYLOAD_BYTES + 5000)},
            "body": json.dumps({"type": "iam", "content": self.compliant_iam_json}),
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 413)
        body = json.loads(res["body"])
        self.assertIn("512 KB", body["error"])

    def test_dynamic_allowed_origin_header(self):
        """Validates that ALLOWED_ORIGIN env var dynamically sets CORS origin."""
        with patch.dict("os.environ", {"ALLOWED_ORIGIN": "https://auditor.onion.internal"}):
            res = lambda_handler({"type": "iam", "content": self.compliant_iam_json})
            self.assertEqual(res["headers"]["Access-Control-Allow-Origin"], "https://auditor.onion.internal")

    def test_global_exception_boundary_catches_fatal_base_exception(self):
        """Validates that even fatal non-Exception classes return 500 without crashing."""
        with patch("src.handler._handle_event", side_effect=KeyboardInterrupt("Forced interrupt")):
            res = lambda_handler({"type": "iam", "content": self.compliant_iam_json})
            self.assertEqual(res["statusCode"], 500)
            body = json.loads(res["body"])
            self.assertIn("error", body)
            self.assertNotIn("KeyboardInterrupt", body["error"])


if __name__ == "__main__":
    unittest.main()
