"""
Unit tests for Onion Auditor Lambda Handler and HTTP API integration.
Uses only Python standard library (unittest).
"""

import base64
import json
import unittest

from src.handler import CORS_HEADERS, lambda_handler


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


if __name__ == "__main__":
    unittest.main()
