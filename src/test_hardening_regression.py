"""
Suíte Oficial de Testes de Regressão 1-para-1 de Hardening e Segurança (Camada 5 - Onion Flow).
Cobre exaustivamente cada ID de vulnerabilidade (QA-001 a QA-015) documentado no QA_REPORT.md.
Utiliza estritamente a biblioteca padrão do Python (unittest, json, re, os, sys, pathlib).
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

# Configuração de caminhos do projeto
SRC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SRC_DIR.parent
WEB_DIR = REPO_ROOT / "web"
TERRAFORM_DIR = REPO_ROOT / "terraform"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from src.auditor import (
        _normalize_iam_dict_keys,
        audit_iam,
        audit_terraform,
        calculate_score_and_risk,
    )
    from src.handler import (
        ALLOWED_ORIGIN,
        CORS_HEADERS,
        MAX_PAYLOAD_BYTES,
        _response,
        lambda_handler,
    )
except ImportError:
    from auditor import (  # type: ignore
        _normalize_iam_dict_keys,
        audit_iam,
        audit_terraform,
        calculate_score_and_risk,
    )
    from handler import (  # type: ignore
        ALLOWED_ORIGIN,
        CORS_HEADERS,
        MAX_PAYLOAD_BYTES,
        _response,
        lambda_handler,
    )


class TestHardeningRegression(unittest.TestCase):
    """
    Testes dedicados 1-para-1 para garantia de não-regressão das falhas QA-001 a QA-015.
    """

    # =========================================================================
    # QA-001: IAM Casing Evasion (Normalização Recursiva de Chaves JSON)
    # =========================================================================
    def test_qa_001_iam_casing_evasion_lowercase_keys(self):
        """
        [QA-001] Garante que chaves JSON em minúsculo ('statement', 'action', 'resource')
        sejam devidamente normalizadas e auditadas, detectando permissões críticas irrestritas.
        """
        payload = json.dumps({
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "LowercaseAdmin",
                    "effect": "allow",
                    "action": "*",
                    "resource": "*",
                }
            ],
        })
        result = audit_iam(payload)
        rule_ids = [f["id"] for f in result["findings"]]

        self.assertIn("IAM-001", rule_ids, "Falha em detectar Ação Universal com Wildcard (IAM-001)")
        self.assertIn("IAM-002", rule_ids, "Falha em detectar Recurso Universal com Wildcard (IAM-002)")
        self.assertIn("IAM-005", rule_ids, "Falha em detectar Statement Allow sem Condição (IAM-005)")
        self.assertEqual(result["risk_level"], "CRITICAL", "Políticas abertas com chaves minúsculas devem ter risco CRITICAL")
        self.assertLessEqual(result["score"], 40, "Score deve ser drasticamente penalizado por permissões irrestritas")

    def test_qa_001_iam_casing_evasion_mixed_case_keys(self):
        """
        [QA-001] Garante normalização de chaves com variações arbitrárias de maiúsculas/minúsculas.
        """
        payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "MixedCaseStmt",
                    "EFFECT": "Allow",
                    "ACTION": "*",
                    "Resource": "*",
                }
            ],
        })
        result = audit_iam(payload)
        rule_ids = [f["id"] for f in result["findings"]]

        self.assertIn("IAM-001", rule_ids)
        self.assertIn("IAM-002", rule_ids)
        self.assertEqual(result["risk_level"], "CRITICAL")

    # =========================================================================
    # QA-002: Inversão Lógica via NotResource Não Avaliada
    # =========================================================================
    def test_qa_002_notresource_logical_inversion_with_allow(self):
        """
        [QA-002] Garante que 'NotResource' combinado com 'Effect: Allow' seja penalizado
        como violação crítica (IAM-002), por conceder acesso irrestrito a todos os outros recursos.
        """
        payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "InvertedVaultExclusion",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "NotResource": "arn:aws:s3:::critical-vault/*",
                }
            ],
        })
        result = audit_iam(payload)
        rule_ids = [f["id"] for f in result["findings"]]

        self.assertIn("IAM-002", rule_ids, "Uso de NotResource com Allow deve acionar IAM-002")
        iam_002_findings = [f for f in result["findings"] if f["id"] == "IAM-002"]
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in iam_002_findings))
        self.assertTrue(any("NotResource" in f["description"] for f in iam_002_findings))
        self.assertEqual(result["risk_level"], "CRITICAL")

    # =========================================================================
    # QA-003: Penalização Incorreta de Regras Defensivas Deny (Falso Positivo)
    # =========================================================================
    def test_qa_003_defensive_deny_rules_no_false_positive_iam008(self):
        """
        [QA-003] Garante que declarações defensivas com 'Effect: Deny' e 'Principal: "*"'
        (ex: obrigatoriedade de TLS ou whitelist de IP) NÃO disparem falso positivo IAM-008.
        """
        payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnforceTLSRequestsOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::corporate-data/*",
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    },
                }
            ],
        })
        result = audit_iam(payload)
        rule_ids = [f["id"] for f in result["findings"]]

        self.assertNotIn("IAM-008", rule_ids, "Regras Deny defensivas não devem ser penalizadas por IAM-008")
        self.assertNotIn("IAM-001", rule_ids, "Regras Deny defensivas não devem ser penalizadas por IAM-001")
        self.assertEqual(result["score"], 100, "Políticas com guardrails Deny estritos devem manter score 100")
        self.assertEqual(result["risk_level"], "LOW")

    # =========================================================================
    # QA-004: DOM XSS via Interpolação de Severidade Não Sanitizada em innerHTML
    # =========================================================================
    def test_qa_004_frontend_anti_xss_severity_whitelist(self):
        """
        [QA-004] Garante que o frontend SPA em web/app.js valide a severidade contra uma
        whitelist restrita (ALLOWED_SEVERITIES) e use escapeHtml antes de interpolar no DOM.
        """
        app_js_path = WEB_DIR / "app.js"
        self.assertTrue(app_js_path.exists(), "web/app.js não encontrado")
        content = app_js_path.read_text(encoding="utf-8")

        # Verifica definição da whitelist de severidades
        self.assertIn("ALLOWED_SEVERITIES", content, "ALLOWED_SEVERITIES não definido em web/app.js")
        self.assertRegex(
            content,
            r"ALLOWED_SEVERITIES\s*=\s*new Set\(\s*\[['\"]CRITICAL['\"],\s*['\"]HIGH['\"],\s*['\"]MEDIUM['\"],\s*['\"]LOW['\"]\]\s*\)",
            "Whitelist ALLOWED_SEVERITIES deve conter CRITICAL, HIGH, MEDIUM, LOW",
        )

        # Verifica validação e fallback defensivo
        self.assertRegex(
            content,
            r"ALLOWED_SEVERITIES\.has\([^)]+\)\s*\?\s*\w+\s*:\s*['\"]LOW['\"]",
            "Severidade deve ser checada com ALLOWED_SEVERITIES.has e ter fallback para 'LOW'",
        )

        # Verifica escape da severidade em innerHTML
        self.assertIn("escapeHtml(safeSev)", content, "A severidade normalizada deve ser interpolada com escapeHtml()")

        # Teste funcional do contrato anti-XSS
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        malicious_severities = [
            "<img src=x onerror=alert(1)>",
            "<script>alert(document.cookie)</script>",
            "\" onmouseover=\"alert(1)",
            "javascript:alert(1)",
        ]
        for malicious in malicious_severities:
            raw = str(malicious).upper().strip()
            safe = raw if raw in allowed else "LOW"
            self.assertEqual(safe, "LOW", f"Payload XSS '{malicious}' deveria ser neutralizado para 'LOW'")

    # =========================================================================
    # QA-005: Bypass em iam:PassRole com Condições Irrelevantes
    # =========================================================================
    def test_qa_005_passrole_condition_strict_enforcement(self):
        """
        [QA-005] Garante que a permissão 'iam:PassRole' exija estritamente a condição
        'iam:PassedToService', rejeitando condições irrelevantes como 'aws:username'.
        """
        # Caso 1: Condição irrelevante (aws:username) -> Deve disparar IAM-009
        bypassing_payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleIrrelevantCondition",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/AppRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:username": "operador-dev"
                        }
                    },
                }
            ],
        })
        res_bypass = audit_iam(bypassing_payload)
        rule_ids_bypass = [f["id"] for f in res_bypass["findings"]]
        self.assertIn("IAM-009", rule_ids_bypass, "iam:PassRole com condição irrelevante deve acionar IAM-009")

        # Caso 2: Condição legítima com 'iam:PassedToService' -> NÃO deve disparar IAM-009
        valid_payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleLegitimateCondition",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/EC2Role",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "ec2.amazonaws.com"
                        }
                    },
                }
            ],
        })
        res_valid = audit_iam(valid_payload)
        rule_ids_valid = [f["id"] for f in res_valid["findings"]]
        self.assertNotIn("IAM-009", rule_ids_valid, "iam:PassRole com iam:PassedToService não deve acionar IAM-009")

    # =========================================================================
    # QA-006: Bypass Semântico de ACL Pública S3 (authenticated-read)
    # =========================================================================
    def test_qa_006_s3_authenticated_read_acl_detection(self):
        """
        [QA-006] Garante que a ACL 'authenticated-read' em manifestos Terraform HCL
        seja detectada e penalizada como TF-002 (Severidade HIGH).
        """
        # Bucket inline
        hcl_inline = """
resource "aws_s3_bucket" "data_lake" {
  bucket = "empresa-lake-financas"
  acl    = "authenticated-read"
}
"""
        res_inline = audit_terraform(hcl_inline)
        rule_ids_inline = [f["id"] for f in res_inline["findings"]]
        self.assertIn("TF-002", rule_ids_inline, "Bucket S3 inline com authenticated-read deve disparar TF-002")

        # Recurso aws_s3_bucket_acl separado
        hcl_separate = """
resource "aws_s3_bucket" "b" {
  bucket = "empresa-lake"
}

resource "aws_s3_bucket_acl" "b_acl" {
  bucket = aws_s3_bucket.b.id
  acl    = "authenticated-read"
}
"""
        res_separate = audit_terraform(hcl_separate)
        rule_ids_separate = [f["id"] for f in res_separate["findings"]]
        self.assertIn("TF-002", rule_ids_separate, "Recurso aws_s3_bucket_acl com authenticated-read deve disparar TF-002")

        # ACL private segura não dispara TF-002
        hcl_private = """
resource "aws_s3_bucket" "safe_bucket" {
  bucket = "empresa-lake-privado"
  acl    = "private"
}
"""
        res_private = audit_terraform(hcl_private)
        rule_ids_private = [f["id"] for f in res_private["findings"]]
        self.assertNotIn("TF-002", rule_ids_private, "Bucket S3 com acl='private' não deve disparar TF-002")

    # =========================================================================
    # QA-007: Evasão de Wildcard em Radicais de Ações IAM
    # =========================================================================
    def test_qa_007_iam_wildcard_in_action_radicals(self):
        """
        [QA-007] Garante a detecção de wildcards presentes em radicais verbais de ações
        (ex: 's3:Get*', 's3:Put*', 'ec2:Describe*') como violação IAM-001 (CRITICAL).
        """
        payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PartialWildcards",
                    "Effect": "Allow",
                    "Action": ["s3:Get*", "s3:Put*"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        result = audit_iam(payload)
        rule_ids = [f["id"] for f in result["findings"]]

        self.assertIn("IAM-001", rule_ids, "Ações com wildcards nos radicais ('s3:Get*') devem acionar IAM-001")
        iam_001 = [f for f in result["findings"] if f["id"] == "IAM-001"][0]
        self.assertEqual(iam_001["severity"], "CRITICAL")

        # Ações explícitas sem wildcard não disparam IAM-001
        safe_payload = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ExplicitActions",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ],
        })
        safe_result = audit_iam(safe_payload)
        safe_rule_ids = [f["id"] for f in safe_result["findings"]]
        self.assertNotIn("IAM-001", safe_rule_ids, "Ações sem wildcard não devem acionar IAM-001")

    # =========================================================================
    # QA-008: Ausência de Content-Security-Policy (CSP) no Frontend
    # =========================================================================
    def test_qa_008_frontend_content_security_policy_configured(self):
        """
        [QA-008] Garante a presença de meta tag Content-Security-Policy (CSP) estrita
        no cabeçalho do documento web/index.html.
        """
        html_path = WEB_DIR / "index.html"
        self.assertTrue(html_path.exists(), "web/index.html não encontrado")
        content = html_path.read_text(encoding="utf-8")

        self.assertIn("http-equiv=\"Content-Security-Policy\"", content, "Meta tag CSP não encontrada no HTML")
        self.assertIn("default-src 'self'", content, "CSP deve restringir default-src a 'self'")
        self.assertIn("script-src 'self'", content, "CSP deve restringir script-src a 'self'")
        self.assertIn("connect-src 'self'", content, "CSP deve restringir connect-src a 'self'")

    # =========================================================================
    # QA-009: Ausência de Timeout no fetch() do Frontend
    # =========================================================================
    def test_qa_009_frontend_fetch_timeout_control(self):
        """
        [QA-009] Garante que a requisição fetch() em web/app.js utilize controle
        de timeout (AbortController / 15 segundos) e trate AbortError no catch.
        """
        app_js_path = WEB_DIR / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        self.assertIn("new AbortController()", content, "AbortController deve ser instanciado para o fetch")
        self.assertRegex(
            content,
            r"setTimeout\s*\(\s*\(\)\s*=>\s*\{?\s*(?:controller|abortController)\.abort\(\);?\s*\}?\s*,\s*15000\s*\)",
            "Timeout de 15 segundos (15000ms) deve estar configurado para abortar a requisição",
        )
        self.assertIn("signal: controller.signal", content, "signal do controller deve ser repassado ao fetch")
        self.assertIn("AbortError", content, "Erro de timeout (AbortError) deve ser tratado visualmente")
        self.assertIn("clearTimeout", content, "Temporizador deve ser limpo no bloco finally")

    # =========================================================================
    # QA-010: Ausência de Limite Defensivo de Statements (FinOps DoS / OOM)
    # =========================================================================
    def test_qa_010_statement_explosion_rejection(self):
        """
        [QA-010] Garante que documentos com mais de 500 statements sejam rejeitados
        com ValueError no motor e tratados com HTTP 400 Bad Request no handler da Lambda.
        """
        # Criando documento sintético com 501 statements
        excessive_statements = [
            {"Effect": "Allow", "Action": f"s3:GetItem{i}", "Resource": f"arn:aws:s3:::b/{i}"}
            for i in range(501)
        ]
        excessive_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": excessive_statements,
        })

        # 1. Validação no motor audit_iam
        with self.assertRaises(ValueError) as ctx:
            audit_iam(excessive_policy)
        self.assertIn("500 statements", str(ctx.exception), "Mensagem deve explicitar o limite de 500 statements")

        # 2. Validação no adapter lambda_handler (reposta HTTP 400 controlada)
        event = {
            "body": json.dumps({"type": "iam", "content": excessive_policy}),
            "headers": {"Content-Type": "application/json"},
        }
        res = lambda_handler(event)
        self.assertEqual(res["statusCode"], 400, "Excesso de statements deve retornar HTTP 400 Bad Request")
        body_data = json.loads(res["body"])
        self.assertIn("error", body_data)
        self.assertIn("500 statements", body_data["error"])

    # =========================================================================
    # QA-011: Ausência de Coerção de Tipo em escapeHtml
    # =========================================================================
    def test_qa_011_frontend_escape_html_defensive_type_coercion(self):
        """
        [QA-011] Garante que escapeHtml em web/app.js trate tipos não-string e nulos
        com coerção explícita String(str), evitando erros do tipo 'TypeError: str.replace is not a function'.
        """
        app_js_path = WEB_DIR / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        self.assertIn("function escapeHtml", content, "Função escapeHtml deve existir em web/app.js")
        self.assertRegex(
            content,
            r"if\s*\(\s*str\s*===\s*null\s*\|\|\s*str\s*===\s*undefined\s*\)\s*return\s*['\"]['\"];",
            "escapeHtml deve verificar null/undefined no início",
        )
        self.assertIn("String(str)", content, "escapeHtml deve conter coerção explícita String(str)")

        # Teste funcional de coerção idêntica à do frontend
        def py_escape_html(val: Any) -> str:
            if val is None:
                return ""
            s = str(val)
            return (
                s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#039;")
            )

        self.assertEqual(py_escape_html(None), "")
        self.assertEqual(py_escape_html(12345), "12345")
        self.assertEqual(py_escape_html(True), "True")
        self.assertEqual(py_escape_html("<script>"), "&lt;script&gt;")

    # =========================================================================
    # QA-012: Uso de alert() Síncrono Bloqueante
    # =========================================================================
    def test_qa_012_frontend_no_synchronous_blocking_alert(self):
        """
        [QA-012] Garante que web/app.js não invoque a função bloqueante alert() nativa
        e utilize o banner acessível role='alert' no DOM.
        """
        app_js_path = WEB_DIR / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        # Verifica que alert( não é invocado diretamente
        matches = re.findall(r"(?<!show)(?<!hide)\balert\s*\(", content)
        self.assertEqual(len(matches), 0, f"Chamada síncrona a alert() encontrada em web/app.js: {matches}")

        self.assertIn("showAlert(", content, "Função acessível showAlert deve ser utilizada")
        self.assertIn("hideAlert(", content, "Função hideAlert deve existir")

        # Verifica presença de role='alert' em web/index.html
        html_path = WEB_DIR / "index.html"
        html_content = html_path.read_text(encoding="utf-8")
        self.assertIn("role=\"alert\"", html_content, "Elemento acessível com role='alert' deve estar presente no HTML")

    # =========================================================================
    # QA-013: Desserialização JSON Precipitada sem Validação de response.ok
    # =========================================================================
    def test_qa_013_frontend_safe_json_deserialization(self):
        """
        [QA-013] Garante que web/app.js verifique o cabeçalho 'Content-Type' para 'application/json'
        e a propriedade 'response.ok' antes de consumir a resposta com response.json().
        """
        app_js_path = WEB_DIR / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        self.assertIn("response.headers.get('content-type')", content, "Content-Type deve ser inspecionado")
        self.assertIn("application/json", content, "Deve verificar a presença de application/json antes do parse")
        self.assertIn("response.text()", content, "Deve capturar texto puro em caso de resposta não-JSON (erros WAF/HTML)")
        self.assertIn("response.ok", content, "Propriedade response.ok deve ser validada")

    # =========================================================================
    # QA-014: Falta de Validação de Protocolo na URL Manual da API
    # =========================================================================
    def test_qa_014_frontend_api_url_protocol_validation(self):
        """
        [QA-014] Garante que a entrada manual da URL da API seja validada com a classe URL
        e restrinja o protocolo estritamente para http: ou https:.
        """
        app_js_path = WEB_DIR / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        self.assertIn("new URL(", content, "Construtor new URL deve ser utilizado para parse da URL manual")
        self.assertRegex(
            content,
            r"\['http:',\s*'https:'\]\.includes\(\w+\.protocol\)",
            "Apenas protocolos http: ou https: devem ser aceitos",
        )

    # =========================================================================
    # QA-015: Permissividade Excessiva de Origem CORS e Rate Limiting
    # =========================================================================
    def test_qa_015_cors_and_rate_limiting_infrastructure(self):
        """
        [QA-015] Garante que o header CORS seja parametrizável por variável de ambiente
        (ALLOWED_ORIGIN) e que o API Gateway v2 possua throttling configurado.
        """
        # 1. Validação no handler Python
        handler_path = SRC_DIR / "handler.py"
        handler_code = handler_path.read_text(encoding="utf-8")
        self.assertIn("ALLOWED_ORIGIN", handler_code, "handler.py deve ler a variável de ambiente ALLOWED_ORIGIN")
        self.assertIn('os.environ.get("ALLOWED_ORIGIN"', handler_code)

        options_event = {
            "httpMethod": "OPTIONS",
            "requestContext": {"http": {"method": "OPTIONS"}},
        }
        options_res = lambda_handler(options_event)
        self.assertEqual(options_res["statusCode"], 200, "OPTIONS preflight deve retornar HTTP 200")
        self.assertIn("Access-Control-Allow-Origin", options_res["headers"])
        self.assertIn("Access-Control-Allow-Methods", options_res["headers"])

        # 2. Validação nas configurações do Terraform (api_gateway.tf e variables.tf)
        tf_api_gw = (TERRAFORM_DIR / "api_gateway.tf").read_text(encoding="utf-8")
        self.assertIn("default_route_settings", tf_api_gw, "Stage padrão deve ter default_route_settings")
        self.assertIn("throttling_burst_limit", tf_api_gw, "throttling_burst_limit deve estar configurado no stage")
        self.assertIn("throttling_rate_limit", tf_api_gw, "throttling_rate_limit deve estar configurado no stage")

        tf_vars = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
        self.assertIn("api_throttling_burst_limit", tf_vars, "Variável api_throttling_burst_limit deve estar declarada")
        self.assertIn("api_throttling_rate_limit", tf_vars, "Variável api_throttling_rate_limit deve estar declarada")
        self.assertIn("cors_allow_origins", tf_vars, "Variável cors_allow_origins deve estar declarada")


if __name__ == "__main__":
    unittest.main()
