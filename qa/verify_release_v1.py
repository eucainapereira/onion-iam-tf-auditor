#!/usr/bin/env python3
"""
Onion Auditor - Verificador de Release v1.0.0 em Produção & Verificação Pós-Hardening.

Valida a integridade, resiliência, regras anti-evasão e conformidade de segurança
diretamente contra os endpoints reais de produção na AWS (API Gateway v2 e Amazon S3 SPA).

TRAVAS RÍGIDAS DE SEGURANÇA E EXECUÇÃO:
- Limite estrito de no máximo 15 requisições HTTP (orçamento inviolável).
- Intervalo obrigatório de 1,0 segundo entre requisições.
- Apenas biblioteca padrão Python 3 (urllib.request, json, time, re, sys, etc.).
- Verificação sistemática de vazamento de informações (stack traces, caminhos internos).
- Exige 100% de sucesso em todas as asserções para aprovação de release.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Constantes e Diretórios
REPO_ROOT = Path(__file__).resolve().parent.parent
QA_DIR = REPO_ROOT / "qa"
RESULTS_FILE = QA_DIR / "results_release_v1.json"
README_FILE = REPO_ROOT / "README.md"
CONFIG_JS_FILE = REPO_ROOT / "web" / "config.js"

# URLs de Produção (com fallback seguro para os recursos oficiais na AWS us-east-2)
DEFAULT_API_URL = "https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit"
DEFAULT_FRONTEND_URL = "http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com"

# Travas Rígidas de Segurança
MAX_ALLOWED_HTTP_REQUESTS: int = 15
INTER_REQUEST_DELAY_SECONDS: float = 1.0


class SecurityBudgetExceeded(Exception):
    """Exceção levantada quando o limite rígido de requisições HTTP é atingido."""
    pass


class ReleaseVerifierV1:
    """Validador oficial da release v1.0.0 contra o ambiente de produção."""

    def __init__(self, api_url: Optional[str] = None, frontend_url: Optional[str] = None) -> None:
        self.api_url = api_url or self._resolve_api_url()
        self.frontend_url = (frontend_url or self._resolve_frontend_url()).rstrip("/")
        self.request_count: int = 0
        self.test_results: List[Dict[str, Any]] = []

    def _resolve_api_url(self) -> str:
        """Descobre dinamicamente a URL do API Gateway via config.js, README.md ou env."""
        if os.environ.get("API_URL"):
            return os.environ["API_URL"].strip()

        if CONFIG_JS_FILE.exists():
            content = CONFIG_JS_FILE.read_text(encoding="utf-8")
            match = re.search(r"https://[a-zA-Z0-9-]+\.execute-api\.[a-zA-Z0-9-]+\.amazonaws\.com/audit", content)
            if match:
                return match.group(0)

        if README_FILE.exists():
            content = README_FILE.read_text(encoding="utf-8")
            match = re.search(r"https://[a-zA-Z0-9-]+\.execute-api\.[a-zA-Z0-9-]+\.amazonaws\.com/audit", content)
            if match:
                return match.group(0)

        return DEFAULT_API_URL

    def _resolve_frontend_url(self) -> str:
        """Descobre dinamicamente a URL do Frontend S3 via README.md ou env."""
        if os.environ.get("FRONTEND_URL"):
            return os.environ["FRONTEND_URL"].strip()

        if README_FILE.exists():
            content = README_FILE.read_text(encoding="utf-8")
            match = re.search(r"http://[a-zA-Z0-9.-]+\.s3-website\.[a-zA-Z0-9-]+\.amazonaws\.com", content)
            if match:
                return match.group(0)

        return DEFAULT_FRONTEND_URL

    def _execute_http(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 15.0,
    ) -> Tuple[int, Dict[str, str], str, float]:
        """
        Executa requisição HTTP aplicando trava de contagem e intervalo obrigatório.
        """
        if self.request_count >= MAX_ALLOWED_HTTP_REQUESTS:
            raise SecurityBudgetExceeded(
                f"TRAVA RÍGIDA ACIONADA: Teto de {MAX_ALLOWED_HTTP_REQUESTS} requisições HTTP atingido! Abortando."
            )

        self.request_count += 1
        req_headers = headers or {}
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        t_start = time.perf_counter()
        status_code: int = 0
        resp_headers: Dict[str, str] = {}
        resp_body: str = ""

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.status
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                resp_body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status_code = e.code
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
            resp_body = e.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            status_code = 0
            resp_body = f"URLError: {str(e.reason)}"
        except Exception as e:
            status_code = -1
            resp_body = f"Exception: {str(e)}"
        finally:
            latency_ms = (time.perf_counter() - t_start) * 1000

        # Pausa obrigatória de 1 segundo entre requisições para estabilidade de produção
        time.sleep(INTER_REQUEST_DELAY_SECONDS)

        return status_code, resp_headers, resp_body, latency_ms

    def _check_information_leakage(self, body: str) -> Dict[str, Any]:
        """Verifica se há vazamento de stack traces, caminhos internos ou credenciais."""
        patterns = {
            "stack_trace": r"Traceback \(most recent call last\):",
            "internal_lambda_path": r"/var/task/",
            "internal_file_reference": r'File ".*\.py", line \d+',
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "internal_system_path": r"/root/|/home/|/app/",
        }
        leaks_found: List[str] = []
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                leaks_found.append(name)

        return {
            "has_leak": len(leaks_found) > 0,
            "leaks": leaks_found,
        }

    # =========================================================================
    # BATERIA DE TESTES DE PRODUÇÃO (RELEASE v1.0.0)
    # =========================================================================

    def test_01_cors_preflight(self) -> Dict[str, Any]:
        """
        Teste 1: Preflight OPTIONS /audit confirmando headers CORS válidos.
        """
        test_id = "V1-01-CORS-PREFLIGHT"
        name = "Preflight CORS OPTIONS /audit"
        headers = {
            "Origin": self.frontend_url,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="OPTIONS", headers=headers
        )

        cors_origin = resp_headers.get("access-control-allow-origin", "")
        cors_methods = resp_headers.get("access-control-allow-methods", "")
        cors_headers_val = resp_headers.get("access-control-allow-headers", "")

        origin_valid = (cors_origin == "*" or cors_origin == self.frontend_url)
        methods_valid = "POST" in cors_methods
        status_valid = status in (200, 204)
        leak_info = self._check_information_leakage(body)

        assertions = {
            "http_status_valid": status_valid,
            "cors_origin_valid": origin_valid,
            "cors_methods_valid": methods_valid,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "OPTIONS",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "cors_origin": cors_origin,
            "cors_methods": cors_methods,
            "cors_headers": cors_headers_val,
            "assertions": assertions,
            "passed": passed,
            "details": "Headers CORS e preflight conformes com RFC no API Gateway v2." if passed else "Falha na validação de preflight CORS.",
        }
        self.test_results.append(result)
        return result

    def test_02_valid_iam_audit(self) -> Dict[str, Any]:
        """
        Teste 2: Auditoria IAM válida retornando HTTP 200 e score esperado (100).
        """
        test_id = "V1-02-VALID-IAM"
        name = "Auditoria IAM Válida (HTTP 200, Score 100)"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "StrictReadOnlyS3",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        "arn:aws:s3:::prod-app-assets-2026/*",
                        "arn:aws:s3:::prod-app-assets-2026"
                    ],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "true"
                        }
                    }
                }
            ]
        }
        req_data = json.dumps({"type": "iam", "content": json.dumps(policy)}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_data
        )

        parsed_data: Dict[str, Any] = {}
        parse_ok = False
        try:
            parsed_data = json.loads(body)
            parse_ok = True
        except Exception:
            parse_ok = False

        score = parsed_data.get("score")
        risk_level = parsed_data.get("risk_level")
        findings = parsed_data.get("findings", [])
        leak_info = self._check_information_leakage(body)

        assertions = {
            "http_status_200": status == 200,
            "json_parsed_ok": parse_ok,
            "score_expected_100": score == 100,
            "risk_level_low": risk_level == "LOW",
            "zero_findings_clean": len(findings) == 0,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "score": score,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "assertions": assertions,
            "passed": passed,
            "details": "Política IAM legítima avaliada com Score 100 (LOW) e sem achados." if passed else "Falha na auditoria de política IAM válida.",
        }
        self.test_results.append(result)
        return result

    def test_03_valid_terraform_audit(self) -> Dict[str, Any]:
        """
        Teste 3: Auditoria Terraform HCL válida retornando HTTP 200 e score esperado (100).
        """
        test_id = "V1-03-VALID-TERRAFORM"
        name = "Auditoria Terraform HCL Válida (HTTP 200, Score 100)"
        hcl_content = """
resource "aws_s3_bucket" "prod_secure_bucket" {
  bucket = "secure-prod-infra-data-2026"
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.prod_secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.prod_secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
        req_data = json.dumps({"type": "terraform", "content": hcl_content}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_data
        )

        parsed_data: Dict[str, Any] = {}
        parse_ok = False
        try:
            parsed_data = json.loads(body)
            parse_ok = True
        except Exception:
            parse_ok = False

        score = parsed_data.get("score")
        risk_level = parsed_data.get("risk_level")
        findings = parsed_data.get("findings", [])
        leak_info = self._check_information_leakage(body)

        assertions = {
            "http_status_200": status == 200,
            "json_parsed_ok": parse_ok,
            "score_expected_100": score == 100,
            "risk_level_low": risk_level == "LOW",
            "zero_findings_clean": len(findings) == 0,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "score": score,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "assertions": assertions,
            "passed": passed,
            "details": "Código Terraform seguro avaliado com Score 100 (LOW) e sem achados." if passed else "Falha na auditoria de Terraform seguro.",
        }
        self.test_results.append(result)
        return result

    def test_04_evasion_iam_action_wildcard(self) -> Dict[str, Any]:
        """
        Teste 4: Tentativa de evasão IAM com wildcard misturado em lista:
                 Action: ["s3:GetObject", "*"]
                 Deve ser detectada com severidade CRITICAL/HIGH (IAM-001).
        """
        test_id = "V1-04-EVASION-IAM-WILDCARD-LIST"
        name = "Detecção de Evasão IAM: Wildcard em Lista ['s3:GetObject', '*']"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SneakyWildcardInList",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "*"],
                    "Resource": "arn:aws:s3:::sensitive-financial-data/*"
                }
            ]
        }
        req_data = json.dumps({"type": "iam", "content": json.dumps(policy)}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_data
        )

        parsed_data: Dict[str, Any] = {}
        parse_ok = False
        try:
            parsed_data = json.loads(body)
            parse_ok = True
        except Exception:
            parse_ok = False

        findings = parsed_data.get("findings", [])
        iam_001_findings = [f for f in findings if f.get("id") == "IAM-001"]
        has_iam_001 = len(iam_001_findings) > 0
        iam_001_sev = iam_001_findings[0].get("severity") if has_iam_001 else None
        sev_critical_or_high = iam_001_sev in ("CRITICAL", "HIGH")
        risk_level = parsed_data.get("risk_level")
        leak_info = self._check_information_leakage(body)

        assertions = {
            "http_status_200": status == 200,
            "json_parsed_ok": parse_ok,
            "iam_001_detected": has_iam_001,
            "severity_critical_or_high": sev_critical_or_high,
            "overall_risk_elevated": risk_level in ("CRITICAL", "HIGH"),
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "score": parsed_data.get("score"),
            "risk_level": risk_level,
            "detected_findings": [f.get("id") for f in findings],
            "iam_001_severity": iam_001_sev,
            "assertions": assertions,
            "passed": passed,
            "details": f"Evasão detectada com sucesso: IAM-001 disparado com severidade {iam_001_sev}." if passed else "Falha na detecção de wildcard em lista de ações IAM.",
        }
        self.test_results.append(result)
        return result

    def test_05_evasion_tf_broad_port_range(self) -> Dict[str, Any]:
        """
        Teste 5: Tentativa de evasão Terraform: Security Group 0.0.0.0/0 com faixa ampla (0-65535).
                 Deve ser detectada com severidade CRITICAL/HIGH (TF-001).
        """
        test_id = "V1-05-EVASION-TF-SG-BROAD-RANGE"
        name = "Detecção de Evasão TF: SG 0.0.0.0/0 com Faixa 0-65535"
        hcl_content = """
resource "aws_security_group" "sg_broad_range_evasion" {
  name = "sg_broad_range_evasion"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        req_data = json.dumps({"type": "terraform", "content": hcl_content}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_data
        )

        parsed_data: Dict[str, Any] = {}
        parse_ok = False
        try:
            parsed_data = json.loads(body)
            parse_ok = True
        except Exception:
            parse_ok = False

        findings = parsed_data.get("findings", [])
        tf_001_findings = [f for f in findings if f.get("id") == "TF-001"]
        has_tf_001 = len(tf_001_findings) > 0
        tf_001_sev = tf_001_findings[0].get("severity") if has_tf_001 else None
        sev_critical_or_high = tf_001_sev in ("CRITICAL", "HIGH")
        risk_level = parsed_data.get("risk_level")
        leak_info = self._check_information_leakage(body)

        assertions = {
            "http_status_200": status == 200,
            "json_parsed_ok": parse_ok,
            "tf_001_detected": has_tf_001,
            "severity_critical_or_high": sev_critical_or_high,
            "overall_risk_elevated": risk_level in ("CRITICAL", "HIGH"),
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "score": parsed_data.get("score"),
            "risk_level": risk_level,
            "detected_findings": [f.get("id") for f in findings],
            "tf_001_severity": tf_001_sev,
            "assertions": assertions,
            "passed": passed,
            "details": f"Evasão detectada com sucesso: TF-001 disparado com severidade {tf_001_sev}." if passed else "Falha na detecção de faixa ampla 0-65535 no SG.",
        }
        self.test_results.append(result)
        return result

    def test_06_payload_limit_rejection(self) -> Dict[str, Any]:
        """
        Teste 6: Payload acima de 512 KB (~600 KB) sendo rejeitado com HTTP 413 limpo.
        """
        test_id = "V1-06-PAYLOAD-LIMIT-512KB"
        name = "Hardening de Limite de Payload: Rejeição com HTTP 413 (>512 KB)"
        # Gera payload de ~600 KB (614.400 bytes)
        target_size_bytes = 600 * 1024
        filler = "a" * (target_size_bytes - 50)
        large_json = json.dumps({"type": "iam", "content": filler}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=large_json
        )

        leak_info = self._check_information_leakage(body)
        error_clean = ("excede" in body.lower() or "512" in body.lower() or "limite" in body.lower())

        assertions = {
            "http_status_413": status == 413,
            "clean_error_message": error_clean,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "payload_bytes": len(large_json),
            "payload_kb": round(len(large_json) / 1024, 2),
            "status_code": status,
            "latency_ms": round(latency, 2),
            "response_snippet": body[:140],
            "assertions": assertions,
            "passed": passed,
            "details": "Payload excessivo bloqueado com HTTP 413 e mensagem limpa." if passed else "Falha na rejeição de payload acima de 512 KB.",
        }
        self.test_results.append(result)
        return result

    def test_07_malformed_json_rejection(self) -> Dict[str, Any]:
        """
        Teste 7: JSON malformado retornando HTTP 400 sem expor stack trace ou caminhos internos.
        """
        test_id = "V1-07-MALFORMED-JSON-400"
        name = "Tratamento de JSON Malformado: HTTP 400 sem Vazamentos"
        malformed_bytes = b'{"type": "iam", "content": "broken json payload without closing brace'
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=malformed_bytes
        )

        leak_info = self._check_information_leakage(body)
        error_controlled = ("json" in body.lower() or "inválido" in body.lower() or "error" in body.lower())

        assertions = {
            "http_status_400": status == 400,
            "error_controlled": error_controlled,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "response_snippet": body[:140],
            "leaks_detected": leak_info["leaks"],
            "assertions": assertions,
            "passed": passed,
            "details": "JSON malformado tratado de forma defensiva com HTTP 400 e zero vazamento." if passed else "Falha no tratamento controlado de JSON malformado.",
        }
        self.test_results.append(result)
        return result

    def test_08_frontend_availability(self) -> Dict[str, Any]:
        """
        Teste 8: Requisição GET no frontend_url retornando HTTP 200 e integridade da SPA.
        """
        test_id = "V1-08-FRONTEND-AVAILABILITY"
        name = "Disponibilidade do Frontend S3 (GET frontend_url HTTP 200)"

        status, resp_headers, body, latency = self._execute_http(
            self.frontend_url, method="GET"
        )

        leak_info = self._check_information_leakage(body)
        is_html = ("<!doctype html>" in body.lower() or "<html" in body.lower())
        has_scripts = ("app.js" in body and "config.js" in body)

        assertions = {
            "http_status_200": status == 200,
            "html_structure_valid": is_html,
            "app_scripts_referenced": has_scripts,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "GET",
            "url": self.frontend_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "content_length": len(body),
            "assertions": assertions,
            "passed": passed,
            "details": "Frontend SPA no S3 disponível, íntegro e referenciando os assets corretos." if passed else "Falha na validação de disponibilidade do frontend.",
        }
        self.test_results.append(result)
        return result

    def test_09_frontend_anti_xss_escape(self) -> Dict[str, Any]:
        """
        Teste 9: Confirmação da função de escape anti-XSS no app.js publicado no S3.
        """
        test_id = "V1-09-FRONTEND-ANTI-XSS"
        name = "Validação Anti-XSS: Presença de escapeHtml no app.js em Produção"
        app_js_url = f"{self.frontend_url}/app.js"

        status, resp_headers, body, latency = self._execute_http(
            app_js_url, method="GET"
        )

        leak_info = self._check_information_leakage(body)
        has_escape_fn = "function escapeHtml" in body
        has_amp_escape = "&amp;" in body
        has_lt_escape = "&lt;" in body
        has_gt_escape = "&gt;" in body
        has_defensive_coercion = "String(str)" in body or "str === null" in body

        assertions = {
            "http_status_200": status == 200,
            "escape_function_defined": has_escape_fn,
            "ampersand_escaped": has_amp_escape,
            "lt_gt_escaped": has_lt_escape and has_gt_escape,
            "defensive_type_coercion": has_defensive_coercion,
            "no_info_leakage": not leak_info["has_leak"],
        }
        passed = all(assertions.values())

        result = {
            "id": test_id,
            "name": name,
            "method": "GET",
            "url": app_js_url,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "assertions": assertions,
            "passed": passed,
            "details": "Controle anti-XSS confirmado no asset publicado: escapeHtml ativo e robusto." if passed else "Falha: função de escape anti-XSS ausente no app.js publicado.",
        }
        self.test_results.append(result)
        return result

    # =========================================================================
    # EXECUÇÃO DA SUÍTE COMPLETA E GERAÇÃO DE EVIDÊNCIAS
    # =========================================================================

    def run_all(self) -> Dict[str, Any]:
        """Executa sequencialmente a suíte de validação v1.0.0."""
        print("=" * 80)
        print("🧅 ONION AUDITOR — SUÍTE DE RE-TESTE & VERIFICAÇÃO PÓS-HARDENING (RELEASE v1.0.0)")
        print("=" * 80)
        print(f"[*] API Gateway Target:  {self.api_url}")
        print(f"[*] Frontend S3 Target:  {self.frontend_url}")
        print(f"[*] Limite de Segurança: Máx {MAX_ALLOWED_HTTP_REQUESTS} requisições HTTP (Delay {INTER_REQUEST_DELAY_SECONDS}s)")
        print("-" * 80)

        # Executa as 9 baterias sequencialmente
        self.test_01_cors_preflight()
        self.test_02_valid_iam_audit()
        self.test_03_valid_terraform_audit()
        self.test_04_evasion_iam_action_wildcard()
        self.test_05_evasion_tf_broad_port_range()
        self.test_06_payload_limit_rejection()
        self.test_07_malformed_json_rejection()
        self.test_08_frontend_availability()
        self.test_09_frontend_anti_xss_escape()

        # Apuração dos Resultados
        total_tests = len(self.test_results)
        passed_tests = sum(1 for t in self.test_results if t["passed"])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests) * 100.0 if total_tests > 0 else 0.0
        all_passed = (failed_tests == 0 and total_tests > 0)

        print("-" * 80)
        for t in self.test_results:
            icon = "✅" if t["passed"] else "❌"
            print(f"  {icon} [{t['id']}] {t['name']} (Status: {t['status_code']} | Latência: {t['latency_ms']}ms)")
            if not t["passed"]:
                print(f"     ⚠️ Detalhes: {t['details']}")
                for a_name, a_val in t.get("assertions", {}).items():
                    if not a_val:
                        print(f"        -> Asserção Falha: {a_name} == False")

        print("-" * 80)
        print(f"[*] Requisições HTTP Executadas: {self.request_count}/{MAX_ALLOWED_HTTP_REQUESTS}")
        print(f"[*] Total de Testes: {total_tests} | Aprovados: {passed_tests} | Falhas: {failed_tests}")
        print(f"[*] Taxa de Sucesso: {success_rate:.1f}%")

        if all_passed:
            print("\n🎉 PARECER FINAL: 100% DE APROVAÇÃO — RELEASE v1.0.0 CONFIRMADA EM PRODUÇÃO COM SUCESSO!")
        else:
            print("\n🚨 PARECER FINAL: FALHA DE VERIFICAÇÃO — UMA OU MAIS ASSERÇÕES NÃO FORAM ATENDIDAS.")
        print("=" * 80)

        evidence = {
            "report_title": "Onion Auditor - Verificação de Release v1.0.0 em Produção & Pós-Hardening",
            "release_version": "v1.0.0",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "python_runtime": sys.version.split()[0],
                "platform": sys.platform,
                "api_gateway_url": self.api_url,
                "frontend_s3_url": self.frontend_url,
                "working_directory": str(REPO_ROOT),
            },
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate_percent": round(success_rate, 2),
                "all_passed": all_passed,
                "total_http_requests": self.request_count,
                "max_http_requests_budget": MAX_ALLOWED_HTTP_REQUESTS,
                "inter_request_delay_seconds": INTER_REQUEST_DELAY_SECONDS,
                "information_leakage_detected": any(
                    not t.get("assertions", {}).get("no_info_leakage", True) for t in self.test_results
                ),
            },
            "verifications": self.test_results,
            "release_verdict": (
                "RELEASE v1.0.0 COMPROVADA E APROVADA: Todos os controles de segurança, resiliência, "
                "anti-evasão e sanitização validados diretamente no ambiente produtivo da AWS."
                if all_passed else
                "RELEASE REJEITADA: Falhas detectadas nos testes de produção."
            ),
        }

        # Salva o arquivo de evidências
        RESULTS_FILE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[*] Evidências oficiais persistidas com sucesso em: {RESULTS_FILE}")

        if not all_passed:
            sys.exit(1)

        return evidence


if __name__ == "__main__":
    verifier = ReleaseVerifierV1()
    verifier.run_all()
