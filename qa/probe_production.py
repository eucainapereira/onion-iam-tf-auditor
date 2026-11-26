"""
Módulo de Sondas Cirúrgicas em Produção (Camada 4 - Onion Flow).
Executa sondas controladas de borda contra o AWS API Gateway e o Frontend S3.

TRAVA RÍGIDA DE SEGURANÇA:
- No máximo 12 requisições HTTP no total (orçamento estrito).
- Pausa obrigatória de 1,0 segundo entre requisições.
- Proibição absoluta de flood ou payloads multi-megabyte.
- Verificação de vazamento de stack trace ou caminhos internos da AWS Lambda (/var/task, etc).
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
README_FILE = REPO_ROOT / "README.md"
CONFIG_JS_FILE = REPO_ROOT / "web" / "config.js"
RESULTS_FILE = QA_DIR / "results_prod_probes.json"

# URLs padrão de fallback (caso não encontradas dinamicamente)
DEFAULT_API_URL = "https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit"
DEFAULT_FRONTEND_URL = "http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com"

# Trava Rígida de Segurança
MAX_ALLOWED_HTTP_REQUESTS = 12
INTER_REQUEST_DELAY_SECONDS = 1.0
MAX_PAYLOAD_BYTES_LIMIT = 300 * 1024  # 300 KB máximo (moderado)


class SecurityGuardViolation(Exception):
    """Exceção levantada quando um limite de segurança é violado."""
    pass


class ProductionProber:
    """Controlador de sondas cirúrgicas com travas de segurança ativas."""

    def __init__(self, api_url: Optional[str] = None, frontend_url: Optional[str] = None) -> None:
        self.api_url = api_url or self._discover_api_url()
        self.frontend_url = frontend_url or self._discover_frontend_url()
        self.request_count = 0
        self.probe_records: List[Dict[str, Any]] = []

    def _discover_api_url(self) -> str:
        """Descobre dinamicamente a URL da API a partir do README.md ou config.js."""
        if README_FILE.exists():
            content = README_FILE.read_text(encoding="utf-8")
            match = re.search(r"https://[a-zA-Z0-9-]+\.execute-api\.[a-zA-Z0-9-]+\.amazonaws\.com/audit", content)
            if match:
                return match.group(0)

        if CONFIG_JS_FILE.exists():
            content = CONFIG_JS_FILE.read_text(encoding="utf-8")
            match = re.search(r"https://[a-zA-Z0-9-]+\.execute-api\.[a-zA-Z0-9-]+\.amazonaws\.com/audit", content)
            if match:
                return match.group(0)

        return DEFAULT_API_URL

    def _discover_frontend_url(self) -> str:
        """Descobre dinamicamente a URL do Frontend a partir do README.md."""
        if README_FILE.exists():
            content = README_FILE.read_text(encoding="utf-8")
            match = re.search(r"http://[a-zA-Z0-9.-]+\.s3-website\.[a-zA-Z0-9-]+\.amazonaws\.com", content)
            if match:
                return match.group(0)

        return DEFAULT_FRONTEND_URL

    def _enforce_safety_guards(self, payload_bytes: int = 0) -> None:
        """Aplica as travas rígidas de segurança antes de disparar qualquer requisição."""
        if self.request_count >= MAX_ALLOWED_HTTP_REQUESTS:
            raise SecurityGuardViolation(
                f"TRAVA RÍGIDA ATIVADA: Limite máximo de {MAX_ALLOWED_HTTP_REQUESTS} requisições atingido. Abortando!"
            )
        if payload_bytes > MAX_PAYLOAD_BYTES_LIMIT:
            raise SecurityGuardViolation(
                f"TRAVA RÍGIDA ATIVADA: Payload de {payload_bytes} bytes excede o teto de {MAX_PAYLOAD_BYTES_LIMIT} bytes."
            )

    def _execute_http(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 10.0,
    ) -> Tuple[int, Dict[str, str], str, float]:
        """Executa uma requisição HTTP controlada com medição de latência e delay obrigatório."""
        payload_len = len(data) if data else 0
        self._enforce_safety_guards(payload_len)

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

        # Pausa obrigatória de segurança (1 segundo entre requisições)
        time.sleep(INTER_REQUEST_DELAY_SECONDS)

        return status_code, resp_headers, resp_body, latency_ms

    def _check_information_leakage(self, body: str) -> Dict[str, Any]:
        """Inspeciona o corpo da resposta em busca de vazamentos de dados internos."""
        leak_patterns = {
            "stack_trace": r"Traceback \(most recent call last\):",
            "internal_lambda_path": r"/var/task/",
            "internal_python_file": r'File ".*\.py", line \d+',
            "aws_keys": r"AKIA[0-9A-Z]{16}",
            "internal_sys_path": r"/root/|/home/|/app/",
        }

        detected_leaks: List[str] = []
        for leak_name, pattern in leak_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                detected_leaks.append(leak_name)

        return {
            "has_leak": len(detected_leaks) > 0,
            "detected_leaks": detected_leaks,
        }

    # =========================================================================
    # SONDAS CIRÚRGICAS ESPECIFICADAS
    # =========================================================================

    def probe_options_cors(self) -> Dict[str, Any]:
        """Sonda 1: Preflight OPTIONS /audit validando headers CORS."""
        headers = {
            "Origin": self.frontend_url,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        }
        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="OPTIONS", headers=headers
        )

        cors_origin = resp_headers.get("access-control-allow-origin")
        cors_methods = resp_headers.get("access-control-allow-methods", "")
        cors_valid = (cors_origin in ["*", self.frontend_url]) and ("POST" in cors_methods)

        leak_check = self._check_information_leakage(body)
        passed = (status in [200, 204]) and cors_valid and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-01-CORS-OPTIONS",
            "name": "Preflight CORS OPTIONS /audit",
            "method": "OPTIONS",
            "url": self.api_url,
            "status_code": status,
            "expected_status": "200 ou 204",
            "latency_ms": round(latency, 2),
            "cors_origin": cors_origin,
            "cors_methods": cors_methods,
            "cors_headers_compliant": cors_valid,
            "leaks_detected": leak_check["detected_leaks"],
            "passed": passed,
            "verdict": "APROVADO: CORS corretamente configurado no API Gateway v2" if passed else "FALHA: CORS ausente ou inválido",
        }
        self.probe_records.append(result)
        return result

    def probe_valid_iam(self) -> Dict[str, Any]:
        """Sonda 2: Requisição válida IAM confirmando HTTP 200 e schema JSON."""
        iam_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnlyS3",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"],
                }
            ],
        }
        req_body = json.dumps({"type": "iam", "content": json.dumps(iam_policy)}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_body
        )

        schema_valid = False
        parsed_data: Optional[Dict[str, Any]] = None
        try:
            parsed_data = json.loads(body)
            schema_valid = (
                isinstance(parsed_data.get("score"), int)
                and 0 <= parsed_data["score"] <= 100
                and parsed_data.get("risk_level") in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                and isinstance(parsed_data.get("findings"), list)
            )
        except Exception:
            schema_valid = False

        leak_check = self._check_information_leakage(body)
        passed = (status == 200) and schema_valid and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-02-VALID-IAM",
            "name": "Requisição Válida IAM (HTTP 200 e Schema JSON)",
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "expected_status": 200,
            "latency_ms": round(latency, 2),
            "response_score": parsed_data.get("score") if parsed_data else None,
            "response_risk_level": parsed_data.get("risk_level") if parsed_data else None,
            "findings_count": len(parsed_data.get("findings", [])) if parsed_data else 0,
            "schema_compliant": schema_valid,
            "leaks_detected": leak_check["detected_leaks"],
            "passed": passed,
            "verdict": "APROVADO: Auditoria IAM executada com sucesso em produção" if passed else "FALHA: Resposta com erro ou fora do schema",
        }
        self.probe_records.append(result)
        return result

    def probe_valid_terraform(self) -> Dict[str, Any]:
        """Sonda 3: Requisição válida Terraform confirmando HTTP 200 e schema JSON."""
        tf_code = """
        resource "aws_s3_bucket" "secure_bucket" {
          bucket = "onion-secure-prod-bucket-12345"
          tags = {
            Environment = "production"
            ManagedBy   = "terraform"
          }
        }
        """
        req_body = json.dumps({"type": "terraform", "content": tf_code}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_body
        )

        schema_valid = False
        parsed_data: Optional[Dict[str, Any]] = None
        try:
            parsed_data = json.loads(body)
            schema_valid = (
                isinstance(parsed_data.get("score"), int)
                and 0 <= parsed_data["score"] <= 100
                and parsed_data.get("risk_level") in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                and isinstance(parsed_data.get("findings"), list)
            )
        except Exception:
            schema_valid = False

        leak_check = self._check_information_leakage(body)
        passed = (status == 200) and schema_valid and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-03-VALID-TERRAFORM",
            "name": "Requisição Válida Terraform (HTTP 200 e Schema JSON)",
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "expected_status": 200,
            "latency_ms": round(latency, 2),
            "response_score": parsed_data.get("score") if parsed_data else None,
            "response_risk_level": parsed_data.get("risk_level") if parsed_data else None,
            "findings_count": len(parsed_data.get("findings", [])) if parsed_data else 0,
            "schema_compliant": schema_valid,
            "leaks_detected": leak_check["detected_leaks"],
            "passed": passed,
            "verdict": "APROVADO: Auditoria Terraform executada com sucesso em produção" if passed else "FALHA: Resposta com erro ou fora do schema",
        }
        self.probe_records.append(result)
        return result

    def probe_malformed_json(self) -> Dict[str, Any]:
        """Sonda 4: Requisição com JSON malformado (deve retornar HTTP 400 controlado sem vazamento)."""
        malformed_raw = b'{"type": "iam", "content": "broken string... unclosed brace'
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=malformed_raw
        )

        leak_check = self._check_information_leakage(body)
        is_controlled = (status == 400) and ("error" in body.lower() or "json" in body.lower())
        passed = is_controlled and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-04-MALFORMED-JSON",
            "name": "JSON Malformado no Corpo da Requisição",
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "expected_status": 400,
            "latency_ms": round(latency, 2),
            "controlled_error": is_controlled,
            "leaks_detected": leak_check["detected_leaks"],
            "response_snippet": body[:120],
            "passed": passed,
            "verdict": "APROVADO: Erro 400 controlado sem vazamento de stack trace" if passed else "FALHA: Resposta inesperada ou vazamento interno",
        }
        self.probe_records.append(result)
        return result

    def probe_disallowed_method_get(self) -> Dict[str, Any]:
        """Sonda 5: Método HTTP não permitido (GET /audit - deve retornar 404/405 controlado)."""
        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="GET"
        )

        leak_check = self._check_information_leakage(body)
        # API Gateway HTTP API v2 retorna 404 Not Found para rotas não configuradas com o método GET
        is_controlled = status in [404, 405]
        passed = is_controlled and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-05-METHOD-NOT-ALLOWED",
            "name": "Método HTTP Não Permitido (GET /audit)",
            "method": "GET",
            "url": self.api_url,
            "status_code": status,
            "expected_status": "404 ou 405",
            "latency_ms": round(latency, 2),
            "controlled_error": is_controlled,
            "leaks_detected": leak_check["detected_leaks"],
            "response_snippet": body[:120],
            "passed": passed,
            "verdict": "APROVADO: Rota bloqueada com código HTTP controlado na borda" if passed else "FALHA: Método aceito indevidamente ou vazamento interno",
        }
        self.probe_records.append(result)
        return result

    def probe_missing_fields(self) -> Dict[str, Any]:
        """Sonda 6: Campos obrigatórios ausentes (deve retornar HTTP 400 controlado)."""
        req_body = json.dumps({"type": "iam"}).encode("utf-8")  # Falta campo content
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_body
        )

        leak_check = self._check_information_leakage(body)
        is_controlled = (status == 400) and ("content" in body.lower() or "obrigatório" in body.lower() or "error" in body.lower())
        passed = is_controlled and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-06-MISSING-FIELDS",
            "name": "Campos Obrigatórios Ausentes (content omitido)",
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "expected_status": 400,
            "latency_ms": round(latency, 2),
            "controlled_error": is_controlled,
            "leaks_detected": leak_check["detected_leaks"],
            "response_snippet": body[:120],
            "passed": passed,
            "verdict": "APROVADO: Validação estrita de contrato retornou HTTP 400" if passed else "FALHA: Ausência de validação de campo obrigatório",
        }
        self.probe_records.append(result)
        return result

    def probe_invalid_type(self) -> Dict[str, Any]:
        """Sonda 7: Tipo de auditoria inválido (deve retornar HTTP 400 controlado)."""
        req_body = json.dumps({"type": "kubernetes", "content": "kind: Pod"}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_body
        )

        leak_check = self._check_information_leakage(body)
        is_controlled = (status == 400) and ("inválido" in body.lower() or "type" in body.lower() or "error" in body.lower())
        passed = is_controlled and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-07-INVALID-AUDIT-TYPE",
            "name": "Tipo de Auditoria Inválido (type='kubernetes')",
            "method": "POST",
            "url": self.api_url,
            "status_code": status,
            "expected_status": 400,
            "latency_ms": round(latency, 2),
            "controlled_error": is_controlled,
            "leaks_detected": leak_check["detected_leaks"],
            "response_snippet": body[:120],
            "passed": passed,
            "verdict": "APROVADO: Rejeição limpa de tipo não suportado com HTTP 400" if passed else "FALHA: Tipo inválido não rejeitado adequadamente",
        }
        self.probe_records.append(result)
        return result

    def probe_moderate_payload(self) -> Dict[str, Any]:
        """Sonda 8: Payload moderado (~250 KB) avaliando limites de transporte e resposta controlada."""
        comment_line = "# " + ("A" * 98) + "\n"
        large_tf = 'resource "aws_s3_bucket" "b" {\n' + (comment_line * 2500) + '  bucket = "moderate-size-test"\n}'
        req_body = json.dumps({"type": "terraform", "content": large_tf}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        payload_size_bytes = len(req_body)

        status, resp_headers, body, latency = self._execute_http(
            self.api_url, method="POST", headers=headers, data=req_body
        )

        leak_check = self._check_information_leakage(body)
        # Resposta aceitável: HTTP 200 (processou), HTTP 400 ou HTTP 413 (Payload Too Large), sem crash
        is_controlled = status in [200, 400, 413]
        passed = is_controlled and not leak_check["has_leak"]

        result = {
            "probe_id": "PROBE-08-MODERATE-PAYLOAD",
            "name": "Payload Moderado em Rede (~250 KB)",
            "method": "POST",
            "url": self.api_url,
            "payload_bytes": payload_size_bytes,
            "payload_kb": round(payload_size_bytes / 1024, 2),
            "status_code": status,
            "expected_status": "200, 400 ou 413",
            "latency_ms": round(latency, 2),
            "controlled_error": is_controlled,
            "leaks_detected": leak_check["detected_leaks"],
            "passed": passed,
            "verdict": f"APROVADO: Processamento estável com status {status} para {round(payload_size_bytes/1024, 1)} KB" if passed else "FALHA: Falha de transporte ou vazamento",
        }
        self.probe_records.append(result)
        return result

    def probe_frontend_availability(self) -> Dict[str, Any]:
        """Sonda 9: Requisição GET no frontend_url confirmando disponibilidade HTTP 200."""
        status, resp_headers, body, latency = self._execute_http(
            self.frontend_url, method="GET"
        )

        content_type = resp_headers.get("content-type", "")
        has_title = "<title>" in body and "Onion Auditor" in body
        passed = (status == 200) and ("text/html" in content_type) and has_title

        result = {
            "probe_id": "PROBE-09-FRONTEND-AVAILABILITY",
            "name": "Disponibilidade do Frontend SPA (S3 Static Hosting)",
            "method": "GET",
            "url": self.frontend_url,
            "status_code": status,
            "expected_status": 200,
            "content_type": content_type,
            "latency_ms": round(latency, 2),
            "html_verified": has_title,
            "passed": passed,
            "verdict": "APROVADO: Frontend online, retornando HTML com status 200" if passed else "FALHA: Frontend inacessível ou corrompido",
        }
        self.probe_records.append(result)
        return result

    def run_all_probes(self) -> Dict[str, Any]:
        """Executa a sequência de 9 sondas respeitando estritamente o limite de segurança."""
        print(f"[*] Iniciando Sondas Cirúrgicas em Produção...")
        print(f"[*] Target API Gateway: {self.api_url}")
        print(f"[*] Target Frontend S3: {self.frontend_url}")
        print(f"[*] Trava de Segurança: máx {MAX_ALLOWED_HTTP_REQUESTS} requisições, {INTER_REQUEST_DELAY_SECONDS}s delay.")
        print("-" * 75)

        # Execução das 9 sondas planejadas
        self.probe_options_cors()
        self.probe_valid_iam()
        self.probe_valid_terraform()
        self.probe_malformed_json()
        self.probe_disallowed_method_get()
        self.probe_missing_fields()
        self.probe_invalid_type()
        self.probe_moderate_payload()
        self.probe_frontend_availability()

        total_probes = len(self.probe_records)
        passed_probes = sum(1 for p in self.probe_records if p.get("passed"))
        failed_probes = total_probes - passed_probes
        all_passed = (passed_probes == total_probes)

        for p in self.probe_records:
            icon = "✅" if p.get("passed") else "❌"
            print(f" {icon} [{p['probe_id']}] {p['name']} -> HTTP {p['status_code']} ({p['latency_ms']} ms)")

        print("-" * 75)
        print(f"[*] Total de requisições disparadas: {self.request_count} / {MAX_ALLOWED_HTTP_REQUESTS}")
        print(f"[*] Veredito Geral: {passed_probes}/{total_probes} sondas aprovadas.")

        consolidated = {
            "summary": {
                "total_probes": total_probes,
                "passed_probes": passed_probes,
                "failed_probes": failed_probes,
                "success_rate_percent": round((passed_probes / total_probes) * 100, 1) if total_probes else 0,
                "all_passed": all_passed,
                "total_requests_executed": self.request_count,
                "max_requests_budget": MAX_ALLOWED_HTTP_REQUESTS,
            },
            "safety_enforcement": {
                "max_allowed_requests": MAX_ALLOWED_HTTP_REQUESTS,
                "inter_request_delay_seconds": INTER_REQUEST_DELAY_SECONDS,
                "max_payload_limit_kb": round(MAX_PAYLOAD_BYTES_LIMIT / 1024, 1),
                "flood_prevention_engaged": True,
                "information_leakage_detected": any(len(p.get("leaks_detected", [])) > 0 for p in self.probe_records),
            },
            "targets": {
                "api_gateway_url": self.api_url,
                "frontend_s3_url": self.frontend_url,
            },
            "probes": self.probe_records,
        }

        self._save_results(consolidated)
        return consolidated

    def _save_results(self, probes_data: Dict[str, Any]) -> None:
        """Salva ou atualiza os resultados no arquivo qa/results_prod_probes.json preservando o contexto consolidado."""
        existing_data: Dict[str, Any] = {}
        if RESULTS_FILE.exists():
            try:
                existing_data = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
            except Exception:
                existing_data = {}

        existing_data["report_title"] = "Onion Auditor - Relatório de Sondas em Produção & Auditoria Frontend (Camada 4)"
        existing_data["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        existing_data["environment"] = {
            "python_version": sys.version.split()[0],
            "api_gateway_url": self.api_url,
            "frontend_s3_url": self.frontend_url,
            "working_directory": str(REPO_ROOT),
        }
        existing_data["production_probes"] = probes_data

        RESULTS_FILE.write_text(json.dumps(existing_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[*] Resultados de sondas salvos em: {RESULTS_FILE}")


if __name__ == "__main__":
    prober = ProductionProber()
    prober.run_all_probes()
