"""
Suíte de Testes de Evasão, Bypasses e Falsos Positivos/Negativos (Camada 3 - Onion Flow).
Testa a resiliência semântica e limites de detecção do motor Onion Auditor (src/handler.py e src/auditor.py).
Utiliza estritamente bibliotecas padrão do Python (unittest, json, time, tracemalloc, base64).
Gera relatório estruturado com métricas e classificações em qa/results_evasion.json.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
import tracemalloc
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configura caminhos para importação do módulo src
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
QA_DIR = REPO_ROOT / "qa"
RESULTS_FILE = QA_DIR / "results_evasion.json"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import handler  # type: ignore

# Registro global de cenários de evasão executados
ALL_EVASION_SCENARIOS: List[Dict[str, Any]] = []


def record_evasion_scenario(
    scenario_id: str,
    category: str,
    vector: str,
    description: str,
    audit_type: str,
    status_code: Optional[int],
    duration_ms: float,
    peak_memory_kb: float,
    score: Optional[int],
    risk_level: Optional[str],
    findings_detected: List[str],
    expected_outcome: str,
    classification: str,
    security_verdict: str,
    passed: bool,
    unhandled_exception: Optional[str] = None,
) -> None:
    """Registra as métricas e vereditos de segurança de um cenário de evasão."""
    record: Dict[str, Any] = {
        "id": scenario_id,
        "category": category,
        "vector": vector,
        "description": description,
        "audit_type": audit_type,
        "status_code": status_code,
        "response_time_ms": round(duration_ms, 2),
        "peak_memory_kb": round(peak_memory_kb, 2),
        "score": score,
        "risk_level": risk_level,
        "findings_detected": findings_detected,
        "findings_count": len(findings_detected),
        "expected_outcome": expected_outcome,
        "classification": classification,
        "security_verdict": security_verdict,
        "passed": passed,
        "unhandled_exception": unhandled_exception,
    }
    ALL_EVASION_SCENARIOS.append(record)


def save_structured_evasion_results() -> None:
    """Gera e salva o relatório consolidado em qa/results_evasion.json."""
    total_tests = len(ALL_EVASION_SCENARIOS)
    passed_tests = sum(1 for s in ALL_EVASION_SCENARIOS if s["passed"])
    failed_tests = total_tests - passed_tests
    unhandled_errors = sum(1 for s in ALL_EVASION_SCENARIOS if s["unhandled_exception"] is not None)

    # Classificações de segurança
    blocked_count = sum(1 for s in ALL_EVASION_SCENARIOS if s["classification"] == "BLOCKED")
    bypass_count = sum(1 for s in ALL_EVASION_SCENARIOS if s["classification"] == "BYPASS")
    fp_count = sum(1 for s in ALL_EVASION_SCENARIOS if s["classification"] == "FALSE_POSITIVE")
    fn_count = sum(1 for s in ALL_EVASION_SCENARIOS if s["classification"] == "FALSE_NEGATIVE")
    legitimate_allow_count = sum(1 for s in ALL_EVASION_SCENARIOS if s["classification"] in ["LEGITIMATE_ALLOW", "INTENDED_DETECTION", "ANTI_FALSE_POSITIVE"])

    total_duration_ms = sum(s["response_time_ms"] for s in ALL_EVASION_SCENARIOS)

    # Categorias consolidadas
    categories_summary: Dict[str, Dict[str, int]] = {}
    for s in ALL_EVASION_SCENARIOS:
        cat = s["category"]
        if cat not in categories_summary:
            categories_summary[cat] = {"total": 0, "blocked": 0, "bypass": 0, "false_positive": 0, "false_negative": 0}
        categories_summary[cat]["total"] += 1
        if s["classification"] == "BLOCKED":
            categories_summary[cat]["blocked"] += 1
        elif s["classification"] == "BYPASS":
            categories_summary[cat]["bypass"] += 1
        elif s["classification"] == "FALSE_POSITIVE":
            categories_summary[cat]["false_positive"] += 1
        elif s["classification"] == "FALSE_NEGATIVE":
            categories_summary[cat]["false_negative"] += 1

    summary = {
        "total_tests": total_tests,
        "passed": passed_tests,
        "failed": failed_tests,
        "unhandled_exceptions_count": unhandled_errors,
        "blocked_evasions": blocked_count,
        "confirmed_bypasses": bypass_count,
        "false_positives": fp_count,
        "false_negatives": fn_count,
        "legitimate_controls_verified": legitimate_allow_count,
        "total_duration_ms": round(total_duration_ms, 2),
    }

    report = {
        "report_title": "Onion Auditor - Relatório de Testes de Evasão, Bypasses e Falsos Positivos/Negativos (IAM & Terraform)",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "target_module": "src.handler.lambda_handler",
            "working_directory": str(REPO_ROOT),
        },
        "summary": summary,
        "categories_breakdown": categories_summary,
        "scenarios": ALL_EVASION_SCENARIOS,
    }

    QA_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


class EvasionTestBase(unittest.TestCase):
    """Classe base provendo runner de medição e extração de achados do motor."""

    def invoke_engine(
        self,
        scenario_id: str,
        category: str,
        vector: str,
        description: str,
        audit_type: str,
        content: str,
        expected_outcome: str,
        classification: str,
        security_verdict: str,
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Invoca o motor medindo tempo e memória, e registra o resultado detalhado."""
        event = {"body": json.dumps({"type": audit_type, "content": content})}
        tracemalloc.start()
        t0 = time.perf_counter()

        response: Optional[Dict[str, Any]] = None
        unhandled_exc: Optional[str] = None
        status_code: Optional[int] = None
        parsed_body: Dict[str, Any] = {}
        findings_detected: List[str] = []

        try:
            response = handler.lambda_handler(event, None)
            status_code = response.get("statusCode")
            raw_body = response.get("body", "{}")
            if isinstance(raw_body, str):
                parsed_body = json.loads(raw_body)
            elif isinstance(raw_body, dict):
                parsed_body = raw_body

            if "findings" in parsed_body and isinstance(parsed_body["findings"], list):
                findings_detected = [f.get("id", "") for f in parsed_body["findings"] if "id" in f]
        except Exception as exc:
            unhandled_exc = f"{type(exc).__name__}: {str(exc)}"

        t1 = time.perf_counter()
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        duration_ms = (t1 - t0) * 1000.0
        peak_kb = peak_bytes / 1024.0

        passed = unhandled_exc is None and status_code == 200

        record_evasion_scenario(
            scenario_id=scenario_id,
            category=category,
            vector=vector,
            description=description,
            audit_type=audit_type,
            status_code=status_code,
            duration_ms=duration_ms,
            peak_memory_kb=peak_kb,
            score=parsed_body.get("score"),
            risk_level=parsed_body.get("risk_level"),
            findings_detected=findings_detected,
            expected_outcome=expected_outcome,
            classification=classification,
            security_verdict=security_verdict,
            passed=passed,
            unhandled_exception=unhandled_exc,
        )

        if unhandled_exc:
            self.fail(f"Exceção não tratada capturada em {scenario_id}: {unhandled_exc}")

        self.assertEqual(
            status_code,
            200,
            f"{scenario_id}: Esperava status HTTP 200, recebeu {status_code}. Resposta: {parsed_body}",
        )

        return parsed_body, findings_detected


class TestIAMEvasionBypass(EvasionTestBase):
    """Suíte de Evasão Semântica e Falsos Positivos/Negativos em Políticas IAM JSON."""

    # ----------------------------------------------------------------------
    # 1. Action como lista misturando ações seguras e wildcard
    # ----------------------------------------------------------------------
    def test_eva_iam_action_mixed_list_wildcard(self) -> None:
        """TC-EVA-IAM-01: Action como lista contendo ação específica e wildcard global (*)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "MixedActionListSuffix",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "*"],
                    "Resource": "arn:aws:s3:::corporate-data/*",
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-ACTION-LIST-MIXED",
            category="IAM Action Evasion",
            vector="Action List Camouflage",
            description="Tentativa de ocultar wildcard universal '*' como segundo item em array de ações seguras",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 (Ação Universal com Wildcard)",
            classification="BLOCKED",
            security_verdict="Motor inspecionou iterativamente a lista de ações e detectou o '*' isolado com sucesso.",
        )
        self.assertIn("IAM-001", findings)
        self.assertEqual(body.get("risk_level"), "CRITICAL")

    def test_eva_iam_action_mixed_list_wildcard_prefix(self) -> None:
        """TC-EVA-IAM-02: Action como lista contendo wildcard global no início e ação segura."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "MixedActionListPrefix",
                    "Effect": "Allow",
                    "Action": ["*", "ec2:DescribeInstances"],
                    "Resource": "arn:aws:s3:::corporate-data/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-ACTION-LIST-PREFIX",
            category="IAM Action Evasion",
            vector="Action List Camouflage",
            description="Tentativa de inclusão de '*' como primeiro item seguido de ação de leitura segura",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001",
            classification="BLOCKED",
            security_verdict="Motor detectou o wildcard global no início da lista de ações.",
        )
        self.assertIn("IAM-001", findings)

    def test_eva_iam_action_safe_list_no_fp(self) -> None:
        """TC-EVA-IAM-03: Action legítima como lista de ações restritas (não deve gerar IAM-001)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SafeActionsList",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::corporate-data/*",
                    "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::123:role/app"}},
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-ACTION-SAFE-LIST",
            category="IAM Action Evasion",
            vector="Legitimate Action List",
            description="Lista de ações permitidas sem wildcards ('s3:GetObject', 's3:PutObject')",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-001",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor reconheceu lista legítima de ações sem disparar falso positivo de IAM-001.",
        )
        self.assertNotIn("IAM-001", findings)

    # ----------------------------------------------------------------------
    # 2. Wildcards parciais de serviço (iam:*, s3:*, etc.)
    # ----------------------------------------------------------------------
    def test_eva_iam_partial_service_wildcard_iam(self) -> None:
        """TC-EVA-IAM-04: Wildcard parcial no serviço IAM ('iam:*')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IAMWildcardService",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "arn:aws:iam::123456789012:role/DevOpsRole",
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-WILDCARD-PARTIAL-IAM",
            category="IAM Partial Wildcards",
            vector="Service-Level Wildcard (iam:*)",
            description="Concessão de todas as ações administrativas do IAM via 'iam:*'",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 e IAM-009 (PassRole implícito)",
            classification="BLOCKED",
            security_verdict="Motor detectou terminação ':*' e associou corretamente à regra IAM-001 e escalação IAM-009.",
        )
        self.assertIn("IAM-001", findings)
        self.assertIn("IAM-009", findings)

    def test_eva_iam_partial_service_wildcard_s3(self) -> None:
        """TC-EVA-IAM-05: Wildcard parcial no serviço S3 ('s3:*')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3WildcardService",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-WILDCARD-PARTIAL-S3",
            category="IAM Partial Wildcards",
            vector="Service-Level Wildcard (s3:*)",
            description="Concessão de todas as ações de objeto e bucket do S3 via 's3:*'",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001",
            classification="BLOCKED",
            security_verdict="Motor identificou 's3:*' como wildcard de serviço abrangente (IAM-001).",
        )
        self.assertIn("IAM-001", findings)

    def test_eva_iam_partial_service_wildcard_dynamodb(self) -> None:
        """TC-EVA-IAM-06: Wildcard parcial no serviço DynamoDB ('dynamodb:*')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DynamoDBWildcardService",
                    "Effect": "Allow",
                    "Action": "dynamodb:*",
                    "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/AppTable",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-WILDCARD-PARTIAL-DDB",
            category="IAM Partial Wildcards",
            vector="Service-Level Wildcard (dynamodb:*)",
            description="Concessão de todas as operações DynamoDB via wildcard de serviço",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001",
            classification="BLOCKED",
            security_verdict="Motor detectou wildcard de serviço 'dynamodb:*' acionando IAM-001.",
        )
        self.assertIn("IAM-001", findings)

    def test_eva_iam_partial_wildcard_action_bypass(self) -> None:
        """TC-EVA-IAM-07: Wildcard parcial em nível de verbo ('s3:Get*', 's3:Put*')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SubActionWildcard",
                    "Effect": "Allow",
                    "Action": ["s3:Get*", "s3:Put*"],
                    "Resource": "arn:aws:s3:::sensitive-data/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-WILDCARD-VERB-BYPASS",
            category="IAM Partial Wildcards",
            vector="Verb-Level Wildcard (s3:Get*, s3:Put*)",
            description="Uso de wildcards no radical da ação ('s3:Get*') sem usar a terminação literal ':*'",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 (Ação Universal com Wildcard)",
            classification="BLOCKED",
            security_verdict="Motor detectou wildcard no radical da ação acionando IAM-001 com sucesso.",
        )
        self.assertIn("IAM-001", findings)

    # ----------------------------------------------------------------------
    # 3. Chaves em minúsculo ou misto (action, resource, etc.)
    # ----------------------------------------------------------------------
    def test_eva_iam_lowercase_keys_bypass(self) -> None:
        """TC-EVA-IAM-08: Chaves normativas do IAM em minúsculo ('action', 'resource', 'statement')."""
        policy = {
            "version": "2012-10-17",
            "statement": [
                {
                    "sid": "LowercaseEvasion",
                    "effect": "allow",
                    "action": "*",
                    "resource": "*",
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-LOWERCASE-KEYS-BYPASS",
            category="IAM Casing Evasion",
            vector="Lowercase JSON Keys",
            description="Injeção de chaves normativas em minúsculo ('version', 'statement', 'action', 'resource')",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 e IAM-002",
            classification="BLOCKED",
            security_verdict="Normalização recursiva de chaves tratou chaves em minúsculo e acionou IAM-001 e IAM-002 com sucesso.",
        )
        self.assertIn("IAM-001", findings)
        self.assertIn("IAM-002", findings)
        self.assertEqual(body.get("risk_level"), "CRITICAL")

    def test_eva_iam_mixed_case_keys_bypass(self) -> None:
        """TC-EVA-IAM-09: Chaves mistas com maiúsculas/minúsculas não padronizadas ('ACTION', 'resource')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "ACTION": "*",
                    "resource": "*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-MIXED-CASE-KEYS-BYPASS",
            category="IAM Casing Evasion",
            vector="Upper/Mixed Case Keys ('ACTION', 'resource')",
            description="Statement com 'ACTION' em maiúsculo e 'resource' em minúsculo dentro de Statement válido",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 e IAM-002",
            classification="BLOCKED",
            security_verdict="Normalização recursiva tratou chaves mistas e acionou IAM-001 e IAM-002 com sucesso.",
        )
        self.assertIn("IAM-001", findings)
        self.assertIn("IAM-002", findings)

    # ----------------------------------------------------------------------
    # 4. Principal: {"AWS": "*"} e variações
    # ----------------------------------------------------------------------
    def test_eva_iam_principal_wildcard_dict_aws(self) -> None:
        """TC-EVA-IAM-10: Principal como dicionário contendo 'AWS': '*'."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardPrincipalDictAWS",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::shared-bucket/*",
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PRINCIPAL-DICT-AWS",
            category="IAM Principal Evasion",
            vector="Principal: {'AWS': '*'}",
            description="Declaração de entidade Principal aberta como dicionário com chave AWS wildcard",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-008 (Uso de Wildcard Global em Principal)",
            classification="BLOCKED",
            security_verdict="Motor inspecionou os valores internos do dicionário Principal e detectou '*' na chave AWS.",
        )
        self.assertIn("IAM-008", findings)
        self.assertEqual(body.get("risk_level"), "CRITICAL")

    def test_eva_iam_principal_wildcard_dict_federated(self) -> None:
        """TC-EVA-IAM-11: Principal como dicionário com wildcard em provedor federado."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardPrincipalFederated",
                    "Effect": "Allow",
                    "Principal": {"Federated": "*"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Resource": "*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PRINCIPAL-DICT-FEDERATED",
            category="IAM Principal Evasion",
            vector="Principal: {'Federated': '*'}",
            description="Declaração de entidade Principal federada aberta para qualquer provedor identity",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-008",
            classification="BLOCKED",
            security_verdict="Motor iterou sobre as chaves do dicionário Principal capturando o wildcard federado.",
        )
        self.assertIn("IAM-008", findings)

    def test_eva_iam_principal_wildcard_list_in_dict(self) -> None:
        """TC-EVA-IAM-12: Principal com array dentro de chave de dicionário contendo '*' camuflado."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardPrincipalListInDict",
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PRINCIPAL-LIST-IN-DICT",
            category="IAM Principal Evasion",
            vector="Principal: {'AWS': [..., '*']}",
            description="Camuflagem de '*' misturado com ARN corporativo legítimo dentro de lista no Principal",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-008",
            classification="BLOCKED",
            security_verdict="Motor inspecionou listas aninhadas em valores de dicionário do Principal, detectando o '*'.",
        )
        self.assertIn("IAM-008", findings)

    def test_eva_iam_principal_direct_string_wildcard(self) -> None:
        """TC-EVA-IAM-13: Principal como string direta '*'."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "WildcardPrincipalString",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PRINCIPAL-STRING-WILDCARD",
            category="IAM Principal Evasion",
            vector="Principal: '*'",
            description="Principal universal declarado como string plana '*'",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-008",
            classification="BLOCKED",
            security_verdict="Motor validou diretamente a igualdade principal == '*'.",
        )
        self.assertIn("IAM-008", findings)

    def test_eva_iam_principal_legitimate_specific_arn(self) -> None:
        """TC-EVA-IAM-14: Principal legítimo apontando para ARN específico (não deve gerar IAM-008)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SpecificPrincipalArn",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/ProductionBackendRole"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {"StringEquals": {"aws:SecureTransport": "true"}},
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PRINCIPAL-LEGITIMATE",
            category="IAM Principal Evasion",
            vector="Specific Role ARN Principal",
            description="Principal configurado estritamente com ARN de role de produção",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-008",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor reconheceu ARN qualificado sem emitir falso positivo para IAM-008.",
        )
        self.assertNotIn("IAM-008", findings)

    # ----------------------------------------------------------------------
    # 5. NotResource (Evasão semântica e falso negativo)
    # ----------------------------------------------------------------------
    def test_eva_iam_notresource_bypass(self) -> None:
        """TC-EVA-IAM-15: Uso de NotResource com Allow (concede acesso a todos os outros recursos)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "NotResourceEvasion",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "NotResource": "arn:aws:s3:::exempt-internal-bucket/*",
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-NOTRESOURCE-BYPASS",
            category="IAM Resource Evasion",
            vector="NotResource Inversion",
            description="Concessão de acesso irrestrito a todos os recursos da conta exceto um ('NotResource')",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-002 (Uso Perigoso de NotResource com Permissão Allow)",
            classification="BLOCKED",
            security_verdict="Motor inspecionou NotResource com efeito Allow e disparou IAM-002 com sucesso.",
        )
        self.assertIn("IAM-002", findings)

    def test_eva_iam_notresource_with_wildcard_action(self) -> None:
        """TC-EVA-IAM-16: NotResource combinado com Action wildcard ('*')."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "NotResourceWithActionWildcard",
                    "Effect": "Allow",
                    "Action": "*",
                    "NotResource": "arn:aws:s3:::exempt-internal-bucket/*",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-NOTRESOURCE-ACTION-WILDCARD",
            category="IAM Resource Evasion",
            vector="NotResource + Action Wildcard",
            description="Ação universal '*' combinada com exclusão de recurso único via 'NotResource'",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-001 e IAM-002",
            classification="BLOCKED",
            security_verdict="Motor detectou tanto a ação universal IAM-001 quanto o recurso universal via NotResource IAM-002.",
        )
        self.assertIn("IAM-001", findings)
        self.assertIn("IAM-002", findings)

    # ----------------------------------------------------------------------
    # 6. iam:PassRole com Condition vazia ({}) e validações
    # ----------------------------------------------------------------------
    def test_eva_iam_passrole_empty_condition(self) -> None:
        """TC-EVA-IAM-17: iam:PassRole com bloco Condition presente porém vazio ({})."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleEmptyConditionDict",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/AppRole",
                    "Condition": {},
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PASSROLE-EMPTY-COND",
            category="IAM Privilege Escalation",
            vector="PassRole with Empty Condition ({})",
            description="Tentativa de bypass da regra IAM-009 declarando Condition como dicionário vazio",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-009 (iam:PassRole sem Restrição de Condição)",
            classification="BLOCKED",
            security_verdict="Motor validou 'len(condition) > 0' e rejeitou condição vazia, acionando IAM-009 com sucesso.",
        )
        self.assertIn("IAM-009", findings)

    def test_eva_iam_passrole_missing_condition(self) -> None:
        """TC-EVA-IAM-18: iam:PassRole sem bloco Condition."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleNoCondition",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/AppRole",
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PASSROLE-NO-COND",
            category="IAM Privilege Escalation",
            vector="PassRole without Condition key",
            description="Permissão iam:PassRole sem nenhuma restrição contextual",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-009",
            classification="BLOCKED",
            security_verdict="Motor detectou a ausência de Condition e disparou IAM-009.",
        )
        self.assertIn("IAM-009", findings)

    def test_eva_iam_passrole_valid_service_condition(self) -> None:
        """TC-EVA-IAM-19: iam:PassRole com condição normativa legítima ('iam:PassedToService')."""
        policy = {
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
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PASSROLE-VALID-COND",
            category="IAM Privilege Escalation",
            vector="Legitimate PassRole Condition",
            description="iam:PassRole devidamente restrito pelo serviço autorizado ('iam:PassedToService': 'ec2.amazonaws.com')",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-009",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor reconheceu 'iam:PassedToService' em Condition e aprovou a restrição.",
        )
        self.assertNotIn("IAM-009", findings)

    def test_eva_iam_passrole_irrelevant_condition_bypass(self) -> None:
        """TC-EVA-IAM-20: iam:PassRole com StringEquals genérico não restringindo iam:PassedToService."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PassRoleIrrelevantCondition",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:username": "developer-alice"
                        }
                    },
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-PASSROLE-IRRELEVANT-COND-BYPASS",
            category="IAM Privilege Escalation",
            vector="StringEquals Bypass on Irrelevant Key",
            description="iam:PassRole protegido apenas por aws:username em vez de iam:PassedToService",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Detectar IAM-009 (iam:PassRole sem Restrição de Condição)",
            classification="BLOCKED",
            security_verdict="Motor exigiu presença mandatória de iam:PassedToService e detectou IAM-009 com sucesso.",
        )
        self.assertIn("IAM-009", findings)

    # ----------------------------------------------------------------------
    # 7. Falsos positivos em statements legítimos com "Effect": "Deny"
    # ----------------------------------------------------------------------
    def test_eva_iam_deny_tls_enforcement_false_positive(self) -> None:
        """TC-EVA-IAM-21: Política defensiva de negação de tráfego HTTP sem TLS (Effect: Deny + Principal: *)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnforceTLSRequestsOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        "arn:aws:s3:::secure-data-bucket",
                        "arn:aws:s3:::secure-data-bucket/*",
                    ],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                        }
                    },
                }
            ],
        }
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-DENY-TLS-FALSE-POSITIVE",
            category="IAM False Positives (Deny Statements)",
            vector="Defensive Deny Statement (TLS Guardrail)",
            description="Regra de segurança padrão AWS que nega acesso caso não use HTTPS ('aws:SecureTransport': 'false')",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-008 para regra defensiva Deny",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Filtro de Effect: Deny suprimiu IAM-008 para regra defensiva de TLS com sucesso.",
        )
        self.assertNotIn("IAM-008", findings)
        self.assertEqual(body.get("risk_level"), "LOW")

    def test_eva_iam_deny_ip_restriction_false_positive(self) -> None:
        """TC-EVA-IAM-22: Bloqueio defensivo de IPs não autorizados com Effect: Deny."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyNonCorporateIPs",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "NotIpAddress": {
                            "aws:SourceIp": ["198.51.100.0/24"]
                        }
                    },
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-DENY-IP-FALSE-POSITIVE",
            category="IAM False Positives (Deny Statements)",
            vector="Defensive Deny Statement (IP Whitelist)",
            description="Negação geral de qualquer requisição externa a faixa corporativa autorizada",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-008 para regra defensiva Deny",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Filtro de Effect: Deny suprimiu IAM-008 para regra defensiva de IP com sucesso.",
        )
        self.assertNotIn("IAM-008", findings)
        self.assertNotIn("IAM-001", findings)
        self.assertNotIn("IAM-002", findings)

    def test_eva_iam_deny_wildcard_actions_properly_ignored(self) -> None:
        """TC-EVA-IAM-23: Statement Deny comum sem Principal (Action:* e Resource:* não devem gerar falso positivo)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyAllWithoutPrincipal",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {"aws:PrincipalTag/Team": "Security"}
                    },
                }
            ],
        }
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-IAM-DENY-PROPER-IGNORING",
            category="IAM False Positives (Deny Statements)",
            vector="Effect: Deny without Principal",
            description="Statement Deny com wildcards em Action e Resource, demonstrando isolamento pós-verificação de Allow",
            audit_type="iam",
            content=json.dumps(policy),
            expected_outcome="Não disparar IAM-001, IAM-002 nem IAM-005",
            classification="INTENDED_DETECTION",
            security_verdict="O filtro 'if not is_allow: continue' evitou falsos positivos para IAM-001, IAM-002 e IAM-005.",
        )
        self.assertNotIn("IAM-001", findings)
        self.assertNotIn("IAM-002", findings)
        self.assertNotIn("IAM-005", findings)


class TestTerraformEvasionBypass(EvasionTestBase):
    """Suíte de Evasão Semântica e Falsos Positivos/Negativos em Terraform HCL."""

    # ----------------------------------------------------------------------
    # 1. Blocos com quebras de linha e indentação irregular
    # ----------------------------------------------------------------------
    def test_eva_tf_irregular_whitespace_and_newlines(self) -> None:
        """TC-EVA-TF-01: Resource HCL com quebras de linha e tabs anômalos entre tokens."""
        hcl = """
resource
    "aws_security_group"
       "sg_anomalous_formatting"
{
  name        = "sg_anomalous"
  description = "Security Group com indentação irregular extrema"

  ingress
  {
    from_port   =
        22
    to_port     =
        22
    protocol    = "tcp"
    cidr_blocks = [
        "0.0.0.0/0"
    ]
  }

  tags = {
    Environment = "qa-evasion"
    Project     = "onion-auditor"
  }
}
"""
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-IRREGULAR-FORMATTING",
            category="Terraform Syntax & Indentation",
            vector="Multiline Whitespace Token Injection",
            description="Definição de resource e blocos com quebras de linha entre resource, tipo, nome e chaves",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001 (Porta Administrativa Aberta para a Internet)",
            classification="BLOCKED",
            security_verdict="O parser baseado em contagem de chaves e regex com '\\s+' tolerou com sucesso formatações irregulares.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_irregular_cidr_array_newlines(self) -> None:
        """TC-EVA-TF-02: Array cidr_blocks formatado com quebras de linha e espaços dispersos."""
        hcl = """
resource "aws_security_group" "sg_irregular_cidr" {
  name = "sg_irregular_cidr"
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [


        "0.0.0.0/0"


    ]
  }
  tags = { Environment = "qa", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-IRREGULAR-CIDR-ARRAY",
            category="Terraform Syntax & Indentation",
            vector="Multiline Array Spacing",
            description="Array cidr_blocks contendo quebras de linha e espaços antes da string '0.0.0.0/0'",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001",
            classification="BLOCKED",
            security_verdict="A flag re.DOTALL na busca de cidr_blocks permitiu extrair e detectar o CIDR aberto com sucesso.",
        )
        self.assertIn("TF-001", findings)

    # ----------------------------------------------------------------------
    # 2. Comentários (# e //) contendo palavras-chave perigosas ou mascarando atributos
    # ----------------------------------------------------------------------
    def test_eva_tf_comment_hash_dangerous_keywords_safe(self) -> None:
        """TC-EVA-TF-03: Comentário '#' contendo regras sensíveis comentadas (anti-falso positivo)."""
        hcl = """
resource "aws_security_group" "sg_commented_rules" {
  name = "sg_commented_rules"
  # ingress {
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-COMMENT-HASH-SAFE",
            category="Terraform Comments & Masking",
            vector="Comment Hash (#) Keyword Poisoning",
            description="Comentário '#' embutindo regras SSH abertas em recurso estritamente seguro",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-001",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Função _strip_hcl_comments removeu comentários '#' evitando falsos positivos de regras comentadas.",
        )
        self.assertNotIn("TF-001", findings)

    def test_eva_tf_comment_slash_dangerous_keywords_safe(self) -> None:
        """TC-EVA-TF-04: Comentário '//' contendo atributo perigoso em volume EBS (anti-falso positivo)."""
        hcl = """
resource "aws_ebs_volume" "vol_commented_slash" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  // encrypted = false
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-COMMENT-SLASH-SAFE",
            category="Terraform Comments & Masking",
            vector="Comment Double-Slash (//) Attribute Poisoning",
            description="Comentário '//' contendo 'encrypted = false' enquanto recurso real tem 'encrypted = true'",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-006",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Comentários '//' foram expurgados antes da análise sem interferir no atributo válido.",
        )
        self.assertNotIn("TF-006", findings)

    def test_eva_tf_comment_block_dangerous_keywords_safe(self) -> None:
        """TC-EVA-TF-05: Comentário de bloco '/* ... */' contendo ACL pública (anti-falso positivo)."""
        hcl = """
resource "aws_s3_bucket" "bucket_block_comment" {
  bucket = "private-corp-bucket"
  acl    = "private"
  /*
  acl = "public-read"
  acl = "public-read-write"
  */
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-COMMENT-BLOCK-SAFE",
            category="Terraform Comments & Masking",
            vector="Multiline Block Comment (/* ... */)",
            description="Comentário multilinhas '/*' contendo menção a ACL pública",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-002",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Substituição regex de bloco removeu o trecho comentado antes da checagem de ACLs.",
        )
        self.assertNotIn("TF-002", findings)

    def test_eva_tf_comment_masking_real_attribute(self) -> None:
        """TC-EVA-TF-06: Mascaramento: atributo de segurança legítimo desativado por comentário."""
        hcl = """
resource "aws_ebs_volume" "vol_masked_security" {
  availability_zone = "us-east-1a"
  size              = 50
  # encrypted = true
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-COMMENT-MASK-SECURITY",
            category="Terraform Comments & Masking",
            vector="Attribute Masking via Comment (#)",
            description="Recurso com 'encrypted = true' transformado em comentário, tornando o volume desprotegido",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-006 (Volume EBS sem Criptografia em Repouso)",
            classification="INTENDED_DETECTION",
            security_verdict="Motor removeu o comentário e detectou a ausência de criptografia ativa (TF-006).",
        )
        self.assertIn("TF-006", findings)

    def test_eva_tf_comment_inline_safe(self) -> None:
        """TC-EVA-TF-07: Comentário inline no final da linha contendo dados perigosos."""
        hcl = """
resource "aws_security_group" "sg_inline_comment" {
  name = "sg_inline"
  ingress {
    from_port   = 80 # to_port = 22 cidr_blocks = ["0.0.0.0/0"]
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-COMMENT-INLINE-SAFE",
            category="Terraform Comments & Masking",
            vector="Inline Comment Trailing Keywords",
            description="Comentário '#' na mesma linha após valor legítimo embutindo porta 22 e 0.0.0.0/0",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-001",
            classification="ANTI_FALSE_POSITIVE",
            security_verdict="Tratamento caractere a caractere em _strip_hcl_comments truncou a linha no '#' sem gerar falso positivo.",
        )
        self.assertNotIn("TF-001", findings)

    # ----------------------------------------------------------------------
    # 3. Security Groups com cidr_blocks = ["0.0.0.0/0"] usando faixas amplas
    # ----------------------------------------------------------------------
    def test_eva_tf_broad_port_range_0_to_65535(self) -> None:
        """TC-EVA-TF-08: Faixa ampla de portas 0 a 65535 aberta para 0.0.0.0/0."""
        hcl = """
resource "aws_security_group" "sg_broad_all_ports" {
  name = "sg_broad_all_ports"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-BROAD-RANGE-FULL",
            category="Terraform Port Range Evasion",
            vector="Full Port Range (from_port: 0, to_port: 65535)",
            description="Exposição irrestrita da faixa total de portas cobrindo implicitamente portas 22, 3389, 5432 e 3306",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001",
            classification="BLOCKED",
            security_verdict="Motor calculou a intersecção de intervalo (0 <= p <= 65535) e disparou TF-001 para todas as portas sensíveis.",
        )
        self.assertIn("TF-001", findings)
        self.assertEqual(body.get("risk_level"), "CRITICAL")

    def test_eva_tf_broad_port_range_0_to_0(self) -> None:
        """TC-EVA-TF-09: Convenção AWS de todo o tráfego com from_port = 0 e to_port = 0."""
        hcl = """
resource "aws_security_group" "sg_traffic_all_zero" {
  name = "sg_traffic_all_zero"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-BROAD-RANGE-ZERO",
            category="Terraform Port Range Evasion",
            vector="All-Traffic Protocol (from_port: 0, to_port: 0)",
            description="Convenção AWS onde from_port = 0 e to_port = 0 com protocolo '-1' significa tráfego irrestrito",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001",
            classification="BLOCKED",
            security_verdict="Lógica do auditor detectou explicitamente from_port == 0 and to_port == 0 como exposição de portas sensíveis.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_broad_port_range_intermediate_range(self) -> None:
        """TC-EVA-TF-10: Faixa intermediária 20 a 25 aberta (porta 22 inclusa implicitamente sem literal 22)."""
        hcl = """
resource "aws_security_group" "sg_range_20_25" {
  name = "sg_range_20_25"
  ingress {
    from_port   = 20
    to_port     = 25
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-BROAD-RANGE-SUB-20-25",
            category="Terraform Port Range Evasion",
            vector="Sub-Range Encompassing Sensitive Port (20-25)",
            description="Abertura de portas 20 a 25 onde a porta SSH 22 não é explicitada como literal",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001 (SSH 22)",
            classification="BLOCKED",
            security_verdict="Verificação aritmética 'from_port <= 22 <= to_port' capturou a porta SSH exposta no sub-range.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_broad_port_range_db_range(self) -> None:
        """TC-EVA-TF-11: Faixa de portas 3300 a 3310 aberta (porta MySQL 3306 inclusa)."""
        hcl = """
resource "aws_security_group" "sg_range_mysql" {
  name = "sg_range_mysql"
  ingress {
    from_port   = 3300
    to_port     = 3310
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-BROAD-RANGE-DB-3306",
            category="Terraform Port Range Evasion",
            vector="Database Port Sub-Range (3300-3310)",
            description="Abertura de portas 3300 a 3310 cobrindo implicitamente a porta 3306 do MySQL",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001 (MySQL 3306)",
            classification="BLOCKED",
            security_verdict="Motor calculou corretamente a inclusão da porta 3306 no intervalo de banco de dados.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_broad_port_range_omitted_ports(self) -> None:
        """TC-EVA-TF-12: Ingress com from_port e to_port omitidos (default 0 a 65535)."""
        hcl = """
resource "aws_security_group" "sg_omitted_ports" {
  name = "sg_omitted_ports"
  ingress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-BROAD-RANGE-OMITTED-PORTS",
            category="Terraform Port Range Evasion",
            vector="Default Range Ingress (Omitted Ports)",
            description="Regra de ingress sem definição de portas assumindo abertura irrestrita por omissão",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001",
            classification="BLOCKED",
            security_verdict="Motor aplicou fallback defensivo para 0-65535 e sinalizou a exposição em TF-001.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_ipv6_world_cidr(self) -> None:
        """TC-EVA-TF-13: Regra de ingress usando CIDR global IPv6 ('::/0') na porta 22."""
        hcl = """
resource "aws_security_group" "sg_ipv6_ssh" {
  name = "sg_ipv6_ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["::/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-IPV6-WORLD-CIDR",
            category="Terraform Port Range Evasion",
            vector="IPv6 Universal CIDR (::/0)",
            description="Abertura de porta administrativa SSH para o universo via endereço IPv6 '::/0'",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-001",
            classification="BLOCKED",
            security_verdict="O motor contemplou expressamente a verificação de '::/0' identificando o CIDR irrestrito IPv6.",
        )
        self.assertIn("TF-001", findings)

    def test_eva_tf_safe_port_allow_not_flagged(self) -> None:
        """TC-EVA-TF-14: Ingress na porta 443 para 0.0.0.0/0 (legítimo para web pública, não deve gerar TF-001)."""
        hcl = """
resource "aws_security_group" "sg_public_web" {
  name = "sg_public_web"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-SAFE-PORT-WEB",
            category="Terraform Port Range Evasion",
            vector="Legitimate Public Web Port (HTTPS 443)",
            description="Exposição pública padrão de porta web segura (HTTPS 443)",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-001",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor filtrou estritamente a lista de portas administrativas e sensíveis (22, 3389, 5432, 3306), aprovando porta 443.",
        )
        self.assertNotIn("TF-001", findings)

    # ----------------------------------------------------------------------
    # 4. Buckets S3 com acl = "public-read-write" e variações de ACL
    # ----------------------------------------------------------------------
    def test_eva_tf_s3_public_read_write_inline(self) -> None:
        """TC-EVA-TF-15: Bucket S3 inline com acl = 'public-read-write'."""
        hcl = """
resource "aws_s3_bucket" "bucket_pub_rw" {
  bucket = "totally-open-upload-bucket"
  acl    = "public-read-write"
  tags   = { Environment = "prod", Project = "onion" }
}
"""
        body, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-PUBLIC-RW-INLINE",
            category="Terraform S3 ACL Evasion",
            vector="Inline ACL: 'public-read-write'",
            description="Definição inline de permissão irrestrita de leitura e escrita anônima no bucket S3",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-002 (Bucket S3 com ACL Pública)",
            classification="BLOCKED",
            security_verdict="Regex 'public-(read|read-write)' interceptou 'public-read-write' inline com precisão.",
        )
        self.assertIn("TF-002", findings)

    def test_eva_tf_s3_public_read_inline(self) -> None:
        """TC-EVA-TF-16: Bucket S3 inline com acl = 'public-read'."""
        hcl = """
resource "aws_s3_bucket" "bucket_pub_read" {
  bucket = "public-asset-bucket"
  acl    = "public-read"
  tags   = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-PUBLIC-READ-INLINE",
            category="Terraform S3 ACL Evasion",
            vector="Inline ACL: 'public-read'",
            description="Definição de leitura pública inline no bucket S3",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-002",
            classification="BLOCKED",
            security_verdict="Motor capturou a flag 'public-read' disparando a regra TF-002.",
        )
        self.assertIn("TF-002", findings)

    def test_eva_tf_s3_public_read_write_external_acl(self) -> None:
        """TC-EVA-TF-17: Recurso separado aws_s3_bucket_acl com acl = 'public-read-write'."""
        hcl = """
resource "aws_s3_bucket" "b" {
  bucket = "my-external-bucket"
  tags   = { Environment = "prod", Project = "onion" }
}

resource "aws_s3_bucket_acl" "b_acl" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read-write"
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-PUBLIC-RW-EXTERNAL-ACL",
            category="Terraform S3 ACL Evasion",
            vector="External Resource: aws_s3_bucket_acl",
            description="Declaração de ACL pública desvinculada do bloco principal do bucket",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-002",
            classification="BLOCKED",
            security_verdict="Motor analisou o bloco externo 'aws_s3_bucket_acl' e disparou TF-002.",
        )
        self.assertIn("TF-002", findings)

    def test_eva_tf_s3_private_acl_safe(self) -> None:
        """TC-EVA-TF-18: Bucket S3 com acl = 'private' (não deve disparar TF-002)."""
        hcl = """
resource "aws_s3_bucket" "bucket_private" {
  bucket = "private-secure-bucket"
  acl    = "private"
  tags   = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-PRIVATE-SAFE",
            category="Terraform S3 ACL Evasion",
            vector="Private Bucket ACL",
            description="Configuração restritiva de ACL como 'private'",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-002",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor reconheceu acl='private' sem gerar falso positivo de ACL pública.",
        )
        self.assertNotIn("TF-002", findings)

    def test_eva_tf_s3_authenticated_read_bypass(self) -> None:
        """TC-EVA-TF-19: Evasão semântica via ACL 'authenticated-read' (abre para qualquer conta AWS)."""
        hcl = """
resource "aws_s3_bucket" "bucket_auth_read" {
  bucket = "leak-to-all-aws-users"
  acl    = "authenticated-read"
  tags   = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-AUTH-READ-BYPASS",
            category="Terraform S3 ACL Evasion",
            vector="Semantic ACL Bypass: 'authenticated-read'",
            description="Concessão de leitura para qualquer entidade autenticada na AWS no mundo ('authenticated-read')",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-002 (Bucket S3 com ACL Pública)",
            classification="BLOCKED",
            security_verdict="Regex expandida capturou a ACL authenticated-read acionando TF-002 com sucesso.",
        )
        self.assertIn("TF-002", findings)

    # ----------------------------------------------------------------------
    # 5. Recursos RDS/EBS/S3: atributo encrypted omitido vs encrypted = false
    # ----------------------------------------------------------------------
    def test_eva_tf_ebs_encryption_omitted(self) -> None:
        """TC-EVA-TF-20: Volume EBS com atributo 'encrypted' omitido por completo."""
        hcl = """
resource "aws_ebs_volume" "vol_enc_omitted" {
  availability_zone = "us-east-1a"
  size              = 30
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-EBS-ENC-OMITTED",
            category="Terraform Encryption Rules",
            vector="EBS Encryption Attribute Omission",
            description="Provisionamento padrão de volume EBS sem mencionar 'encrypted' (inseguro por padrão)",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-006 (Volume EBS sem Criptografia em Repouso)",
            classification="INTENDED_DETECTION",
            security_verdict="Motor tratou a omissão do atributo como ausência de criptografia e gerou TF-006.",
        )
        self.assertIn("TF-006", findings)

    def test_eva_tf_ebs_encryption_explicit_false(self) -> None:
        """TC-EVA-TF-21: Volume EBS com 'encrypted = false' explícito."""
        hcl = """
resource "aws_ebs_volume" "vol_enc_false" {
  availability_zone = "us-east-1a"
  size              = 30
  encrypted         = false
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-EBS-ENC-EXPLICIT-FALSE",
            category="Terraform Encryption Rules",
            vector="EBS Encryption Explicit False",
            description="Desativação explícita de criptografia em volume EBS",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-006",
            classification="INTENDED_DETECTION",
            security_verdict="Motor capturou a atribuição 'encrypted = false' e gerou TF-006.",
        )
        self.assertIn("TF-006", findings)

    def test_eva_tf_ebs_encryption_explicit_true(self) -> None:
        """TC-EVA-TF-22: Volume EBS devidamente protegido com 'encrypted = true'."""
        hcl = """
resource "aws_ebs_volume" "vol_enc_true" {
  availability_zone = "us-east-1a"
  size              = 30
  encrypted         = true
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-EBS-ENC-EXPLICIT-TRUE",
            category="Terraform Encryption Rules",
            vector="EBS Encryption Explicit True",
            description="Volume EBS configurado com criptografia em repouso ativada",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-006",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor reconheceu 'encrypted = true' sem emitir falso positivo.",
        )
        self.assertNotIn("TF-006", findings)

    def test_eva_tf_rds_encryption_omitted(self) -> None:
        """TC-EVA-TF-23: Banco RDS com atributo 'storage_encrypted' omitido."""
        hcl = """
resource "aws_db_instance" "db_enc_omitted" {
  instance_class = "db.t3.micro"
  allocated_storage = 20
  tags           = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-RDS-ENC-OMITTED",
            category="Terraform Encryption Rules",
            vector="RDS Storage Encryption Omission",
            description="Instância RDS provisionada sem especificar criptografia de disco",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-007 (Instância RDS sem Criptografia em Repouso)",
            classification="INTENDED_DETECTION",
            security_verdict="Motor detectou a ausência de 'storage_encrypted = true' disparando TF-007.",
        )
        self.assertIn("TF-007", findings)

    def test_eva_tf_rds_encryption_explicit_false(self) -> None:
        """TC-EVA-TF-24: Banco RDS com 'storage_encrypted = false' explícito."""
        hcl = """
resource "aws_db_instance" "db_enc_false" {
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-RDS-ENC-EXPLICIT-FALSE",
            category="Terraform Encryption Rules",
            vector="RDS Storage Encryption Explicit False",
            description="Desativação intencional de criptografia no banco de dados RDS",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-007",
            classification="INTENDED_DETECTION",
            security_verdict="Motor identificou a flag 'storage_encrypted = false' e gerou TF-007.",
        )
        self.assertIn("TF-007", findings)

    def test_eva_tf_rds_encryption_explicit_true(self) -> None:
        """TC-EVA-TF-25: Banco RDS devidamente criptografado com 'storage_encrypted = true'."""
        hcl = """
resource "aws_db_instance" "db_enc_true" {
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = true
  tags              = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-RDS-ENC-EXPLICIT-TRUE",
            category="Terraform Encryption Rules",
            vector="RDS Storage Encryption Explicit True",
            description="Banco de dados RDS com criptografia em repouso habilitada",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-007",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor validou 'storage_encrypted = true' sem emitir falso positivo.",
        )
        self.assertNotIn("TF-007", findings)

    def test_eva_tf_ec2_root_block_encryption_omitted(self) -> None:
        """TC-EVA-TF-26: Instância EC2 com root_block_device sem atributo encrypted."""
        hcl = """
resource "aws_instance" "ec2_unencrypted_root" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"
  root_block_device {
    volume_size = 50
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-EC2-ROOT-ENC-OMITTED",
            category="Terraform Encryption Rules",
            vector="EC2 Root Block Encryption Omission",
            description="Instância EC2 cujo volume root não declara 'encrypted = true'",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-006",
            classification="INTENDED_DETECTION",
            security_verdict="Motor inspecionou blocos root_block_device e emitiu TF-006 por falta de criptografia.",
        )
        self.assertIn("TF-006", findings)

    def test_eva_tf_s3_sse_omitted(self) -> None:
        """TC-EVA-TF-27: Bucket S3 sem nenhuma configuração de criptografia SSE."""
        hcl = """
resource "aws_s3_bucket" "bucket_unencrypted" {
  bucket = "unencrypted-storage-bucket"
  tags   = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-SSE-OMITTED",
            category="Terraform Encryption Rules",
            vector="S3 SSE Encryption Omission",
            description="Bucket S3 sem bloco inline ou recurso externo de criptografia do lado do servidor (SSE)",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Detectar TF-004 (Bucket S3 sem Criptografia em Repouso)",
            classification="INTENDED_DETECTION",
            security_verdict="Motor identificou ausência de configuração SSE inline e externa gerando TF-004.",
        )
        self.assertIn("TF-004", findings)

    def test_eva_tf_s3_sse_inline_present(self) -> None:
        """TC-EVA-TF-28: Bucket S3 com bloco inline server_side_encryption_configuration."""
        hcl = """
resource "aws_s3_bucket" "bucket_sse_inline" {
  bucket = "encrypted-inline-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = { Environment = "prod", Project = "onion" }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-SSE-INLINE-PRESENT",
            category="Terraform Encryption Rules",
            vector="S3 SSE Inline Block",
            description="Bucket S3 protegido por bloco inline de criptografia AES256",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-004",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor detectou a presença do bloco inline de SSE e aprovou o bucket.",
        )
        self.assertNotIn("TF-004", findings)

    def test_eva_tf_s3_sse_external_present(self) -> None:
        """TC-EVA-TF-29: Bucket S3 com recurso complementar aws_s3_bucket_server_side_encryption_configuration."""
        hcl = """
resource "aws_s3_bucket" "bucket_sse_external" {
  bucket = "encrypted-external-bucket"
  tags   = { Environment = "prod", Project = "onion" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse_ext" {
  bucket = aws_s3_bucket.bucket_sse_external.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""
        _, findings = self.invoke_engine(
            scenario_id="TC-EVA-TF-S3-SSE-EXTERNAL-PRESENT",
            category="Terraform Encryption Rules",
            vector="S3 SSE External Resource",
            description="Bucket S3 com recurso moderno aws_s3_bucket_server_side_encryption_configuration",
            audit_type="terraform",
            content=hcl,
            expected_outcome="Não disparar TF-004",
            classification="LEGITIMATE_ALLOW",
            security_verdict="Motor identificou o recurso externo de criptografia SSE e suprimiu TF-004.",
        )
        self.assertNotIn("TF-004", findings)


def run_and_save_suite() -> unittest.TestResult:
    """Executa a suíte completa de testes e persiste os resultados em qa/results_evasion.json."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestIAMEvasionBypass))
    suite.addTests(loader.loadTestsFromTestCase(TestTerraformEvasionBypass))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    save_structured_evasion_results()
    return result


if __name__ == "__main__":
    result = run_and_save_suite()
    sys.exit(0 if result.wasSuccessful() else 1)
