"""
Suíte de Testes de Estresse, Fuzzing e Resiliência Local (Camada 2 - Onion Flow).
Testa diretamente src/handler.py e src/auditor.py em memória via handler.lambda_handler.
Utiliza estritamente bibliotecas padrão do Python (unittest, json, time, tracemalloc, base64).
Gera relatório estruturado com métricas de tempo e memória em qa/results_local_stress.json.
"""

from __future__ import annotations

import base64
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
RESULTS_FILE = QA_DIR / "results_local_stress.json"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ["MAX_PAYLOAD_BYTES"] = str(15 * 1024 * 1024)

import handler  # type: ignore
handler.MAX_PAYLOAD_BYTES = 15 * 1024 * 1024

# Registro global de métricas e cenários executados
ALL_SCENARIOS: List[Dict[str, Any]] = []


def record_scenario(
    scenario_id: str,
    category: str,
    description: str,
    payload_size_bytes: int,
    status_code: Optional[int],
    duration_ms: float,
    peak_memory_kb: float,
    peak_memory_mb: float,
    passed: bool,
    unhandled_exception: Optional[str] = None,
    error_message: Optional[str] = None,
    findings_count: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Registra as métricas estruturadas de um cenário de teste."""
    human_size = (
        f"{payload_size_bytes / (1024 * 1024):.2f} MB"
        if payload_size_bytes >= 1024 * 1024
        else f"{payload_size_bytes / 1024:.2f} KB"
        if payload_size_bytes >= 1024
        else f"{payload_size_bytes} B"
    )

    record: Dict[str, Any] = {
        "id": scenario_id,
        "category": category,
        "description": description,
        "payload_size_bytes": payload_size_bytes,
        "payload_size_human": human_size,
        "status_code": status_code,
        "response_time_ms": round(duration_ms, 2),
        "peak_memory_kb": round(peak_memory_kb, 2),
        "peak_memory_mb": round(peak_memory_mb, 2),
        "passed": passed,
        "unhandled_exception": unhandled_exception,
        "error_message": error_message,
        "findings_count": findings_count,
    }
    if extra:
        record["details"] = extra
    ALL_SCENARIOS.append(record)


def save_structured_results() -> None:
    """Gera e salva o relatório consolidado em qa/results_local_stress.json."""
    total_tests = len(ALL_SCENARIOS)
    passed_tests = sum(1 for s in ALL_SCENARIOS if s["passed"])
    failed_tests = total_tests - passed_tests
    unhandled_errors = sum(1 for s in ALL_SCENARIOS if s["unhandled_exception"] is not None)

    total_duration_ms = sum(s["response_time_ms"] for s in ALL_SCENARIOS)
    max_duration_scenario = max(ALL_SCENARIOS, key=lambda s: s["response_time_ms"]) if ALL_SCENARIOS else None
    max_memory_scenario = max(ALL_SCENARIOS, key=lambda s: s["peak_memory_mb"]) if ALL_SCENARIOS else None

    summary = {
        "total_tests": total_tests,
        "passed": passed_tests,
        "failed": failed_tests,
        "unhandled_exceptions_count": unhandled_errors,
        "total_duration_ms": round(total_duration_ms, 2),
        "max_duration_ms": max_duration_scenario["response_time_ms"] if max_duration_scenario else 0.0,
        "max_duration_scenario": max_duration_scenario["id"] if max_duration_scenario else None,
        "max_memory_mb": max_memory_scenario["peak_memory_mb"] if max_memory_scenario else 0.0,
        "max_memory_scenario": max_memory_scenario["id"] if max_memory_scenario else None,
    }

    report = {
        "report_title": "Onion Auditor - Relatório de Estresse Local, Payloads Gigantes e Fuzzing",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "target_module": "src.handler.lambda_handler",
            "working_directory": str(REPO_ROOT),
        },
        "summary": summary,
        "scenarios": ALL_SCENARIOS,
    }

    QA_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


class StressTestBase(unittest.TestCase):
    """Classe base provendo runner de medição precisa com tracemalloc e time.perf_counter."""

    def invoke_handler_measured(
        self,
        scenario_id: str,
        category: str,
        description: str,
        event: Any,
        expected_status: Optional[int] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Executa handler.lambda_handler medindo tempo (ms) e memória de pico (tracemalloc)."""
        # Mede tamanho aproximado do evento
        try:
            if isinstance(event, str):
                payload_size = len(event.encode("utf-8"))
            elif isinstance(event, dict):
                body_val = event.get("body")
                if isinstance(body_val, str):
                    payload_size = len(body_val.encode("utf-8"))
                else:
                    payload_size = len(json.dumps(event).encode("utf-8"))
            else:
                payload_size = len(str(event).encode("utf-8"))
        except Exception:
            payload_size = 0

        tracemalloc.start()
        t0 = time.perf_counter()
        response: Optional[Dict[str, Any]] = None
        unhandled_exc: Optional[str] = None
        status_code: Optional[int] = None
        error_msg: Optional[str] = None
        findings_count: Optional[int] = None
        parsed_body: Dict[str, Any] = {}

        try:
            response = handler.lambda_handler(event, None)
            status_code = response.get("statusCode")
            raw_body = response.get("body", "{}")
            if isinstance(raw_body, str):
                try:
                    parsed_body = json.loads(raw_body)
                    if "error" in parsed_body:
                        error_msg = parsed_body["error"]
                    if "findings" in parsed_body and isinstance(parsed_body["findings"], list):
                        findings_count = len(parsed_body["findings"])
                except Exception:
                    parsed_body = {"raw": raw_body}
            elif isinstance(raw_body, dict):
                parsed_body = raw_body
                if "error" in parsed_body:
                    error_msg = parsed_body["error"]
                if "findings" in parsed_body and isinstance(parsed_body["findings"], list):
                    findings_count = len(parsed_body["findings"])
        except Exception as exc:
            unhandled_exc = f"{type(exc).__name__}: {str(exc)}"

        t1 = time.perf_counter()
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        duration_ms = (t1 - t0) * 1000.0
        peak_kb = peak_bytes / 1024.0
        peak_mb = peak_bytes / (1024.0 * 1024.0)

        passed = True
        if unhandled_exc is not None:
            passed = False
        elif expected_status is not None and status_code != expected_status:
            passed = False

        record_scenario(
            scenario_id=scenario_id,
            category=category,
            description=description,
            payload_size_bytes=payload_size,
            status_code=status_code,
            duration_ms=duration_ms,
            peak_memory_kb=peak_kb,
            peak_memory_mb=peak_mb,
            passed=passed,
            unhandled_exception=unhandled_exc,
            error_message=error_msg,
            findings_count=findings_count,
            extra={
                "risk_level": parsed_body.get("risk_level"),
                "score": parsed_body.get("score"),
            }
            if "score" in parsed_body
            else None,
        )

        if unhandled_exc:
            self.fail(f"Exceção não tratada capturada em {scenario_id}: {unhandled_exc}")

        if expected_status is not None:
            self.assertEqual(
                status_code,
                expected_status,
                f"{scenario_id}: Esperava status HTTP {expected_status}, recebeu {status_code}. Resposta: {parsed_body}",
            )

        return response or {}, parsed_body


class TestGiantPayloads(StressTestBase):
    """Cenário 1: Payloads Gigantes de 1 MB, 5 MB e 10 MB (IAM e Terraform)."""

    @staticmethod
    def _create_giant_iam_payload(target_mb: float) -> str:
        """Gera política IAM sintética válida com tamanho atingindo target_mb."""
        target_bytes = int(target_mb * 1024 * 1024)
        statements = []
        for i in range(50):
            statements.append({
                "Sid": f"StressStatement{i:03d}",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:*",
                    "iam:PassRole",
                    "ec2:DescribeInstances",
                ],
                "Resource": f"arn:aws:s3:::stress-bucket-onion-auditor-{i:03d}/*",
            })

        policy: Dict[str, Any] = {
            "Version": "2012-10-17",
            "Statement": statements,
        }
        current_str = json.dumps(policy)
        needed = target_bytes - len(current_str)
        if needed > 0:
            # Insere campo Description estruturado com preenchimento exato
            pad_len = needed - 25
            policy["Description"] = "P" * max(10, pad_len)
            current_str = json.dumps(policy)
            if len(current_str) < target_bytes:
                current_str += " " * (target_bytes - len(current_str))
        return current_str

    @staticmethod
    def _create_giant_tf_payload(target_mb: float) -> str:
        """Gera manifesto Terraform HCL válido com tamanho atingindo target_mb."""
        target_bytes = int(target_mb * 1024 * 1024)
        blocks = []
        for i in range(25):
            blocks.append(f"""
resource "aws_security_group" "sg_stress_{i:03d}" {{
  name        = "sg_stress_{i:03d}"
  description = "Security Group de teste de estresse número {i:03d}"
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  tags = {{
    Environment = "qa-stress"
    Project     = "onion-auditor"
  }}
}}
""")
        hcl_content = "\n".join(blocks)
        needed = target_bytes - len(hcl_content)
        if needed > 0:
            # Preenche com comentário HCL sintético
            hcl_content += "\n# " + ("X" * max(10, needed - 5))
        return hcl_content

    def test_str_iam_1mb(self) -> None:
        """TC-STR-IAM-1MB: Payload IAM de 1 MB."""
        raw_content = self._create_giant_iam_payload(1.0)
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-IAM-1MB",
            category="Giant Payloads (IAM)",
            description="Payload IAM sintético de 1 MB com 50 statements e metadados",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_iam_5mb(self) -> None:
        """TC-STR-IAM-5MB: Payload IAM de 5 MB."""
        raw_content = self._create_giant_iam_payload(5.0)
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-IAM-5MB",
            category="Giant Payloads (IAM)",
            description="Payload IAM sintético de 5 MB com 50 statements e metadados",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_iam_10mb(self) -> None:
        """TC-STR-IAM-10MB: Payload IAM de 10 MB (limite teórico do API Gateway)."""
        raw_content = self._create_giant_iam_payload(10.0)
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-IAM-10MB",
            category="Giant Payloads (IAM)",
            description="Payload IAM sintético de 10 MB (limite API Gateway) com 50 statements e metadados",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_tf_1mb(self) -> None:
        """TC-STR-TF-1MB: Payload Terraform HCL de 1 MB."""
        raw_content = self._create_giant_tf_payload(1.0)
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-TF-1MB",
            category="Giant Payloads (Terraform)",
            description="Payload Terraform HCL sintético de 1 MB com 25 Security Groups e regras",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_tf_5mb(self) -> None:
        """TC-STR-TF-5MB: Payload Terraform HCL de 5 MB."""
        raw_content = self._create_giant_tf_payload(5.0)
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-TF-5MB",
            category="Giant Payloads (Terraform)",
            description="Payload Terraform HCL sintético de 5 MB com 25 Security Groups e regras",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_tf_10mb(self) -> None:
        """TC-STR-TF-10MB: Payload Terraform HCL de 10 MB."""
        raw_content = self._create_giant_tf_payload(10.0)
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-TF-10MB",
            category="Giant Payloads (Terraform)",
            description="Payload Terraform HCL sintético de 10 MB (limite API Gateway) com 25 Security Groups",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_str_iam_density_500_statements(self) -> None:
        """TC-STR-IAM-500-STMTS: Carga densa de 500 statements individuais para verificar complexidade O(N)."""
        stmts = [
            {
                "Sid": f"DensityStmt{i:04d}",
                "Effect": "Allow",
                "Action": ["s3:*", "iam:PassRole"],
                "Resource": "*",
            }
            for i in range(500)
        ]
        policy = {"Version": "2012-10-17", "Statement": stmts}
        raw_content = json.dumps(policy)
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-IAM-500-STMTS",
            category="High-Density Entities (IAM)",
            description="Política IAM com 500 statements ativos para avaliar dedução e geração em lote de achados",
            event=event,
            expected_status=200,
        )
        self.assertEqual(body.get("risk_level"), "CRITICAL")
        self.assertEqual(body.get("score"), 0)
        self.assertGreater(len(body.get("findings", [])), 500)

    def test_str_tf_density_100_sgs(self) -> None:
        """TC-STR-TF-100-SGS: Carga densa de 100 recursos aws_security_group com regras ingress."""
        resources = []
        for i in range(100):
            resources.append(f"""
resource "aws_security_group" "sg_dense_{i:03d}" {{
  name = "sg_dense_{i:03d}"
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  tags = {{
    Environment = "prod"
    Project     = "onion"
  }}
}}
""")
        raw_content = "\n".join(resources)
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-STR-TF-100-SGS",
            category="High-Density Entities (Terraform)",
            description="Manifesto Terraform com 100 Security Groups com portas 22 abertas para 0.0.0.0/0",
            event=event,
            expected_status=200,
        )
        self.assertEqual(body.get("risk_level"), "CRITICAL")
        self.assertEqual(body.get("score"), 0)
        self.assertGreaterEqual(len(body.get("findings", [])), 100)


class TestDeeplyNestedJSON(StressTestBase):
    """Cenário 2: JSON com aninhamento profundo (600 níveis) e teste de RecursionError."""

    def test_nst_object_600_levels_in_body(self) -> None:
        """TC-NST-OBJ-600: 600 níveis de objetos aninhados no corpo da requisição."""
        # Cria string {"a": {"a": ... 1 ... }} com 600 níveis
        nested_json = '{"nest":' * 600 + '1' + '}' * 600
        event = {"body": nested_json}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-OBJ-600",
            category="Deeply Nested JSON",
            description="JSON com 600 níveis de objetos aninhados no body da requisição HTTP",
            event=event,
            expected_status=400,
        )
        # O handler deve rejeitar com 400 por não conter 'type' e 'content' na raiz
        self.assertIn("error", body)

    def test_nst_array_600_levels_in_body(self) -> None:
        """TC-NST-ARR-600: 600 níveis de listas aninhadas no corpo da requisição."""
        nested_json = '[' * 600 + '"leaf"' + ']' * 600
        event = {"body": nested_json}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-ARR-600",
            category="Deeply Nested JSON",
            description="JSON com 600 níveis de arrays aninhados no body da requisição HTTP",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_nst_iam_condition_nested_300_levels(self) -> None:
        """TC-NST-IAM-COND-300: Política IAM válida contendo 300 níveis em Condition."""
        # Constrói condition profundamente aninhada: {"Cond": {"Cond": ... {"iam:PassedToService": "ec2.amazonaws.com"} ... }}
        deep_cond_str = '{"Cond":' * 300 + '{"iam:PassedToService": "ec2.amazonaws.com"}' + '}' * 300
        policy_str = (
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*", "Condition": '
            + deep_cond_str
            + '}]}'
        )
        event = {"body": json.dumps({"type": "iam", "content": policy_str})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-IAM-COND-300",
            category="Deeply Nested JSON",
            description="Política IAM com 300 níveis de dicionários aninhados no bloco Condition",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_nst_recursion_limit_2000_body(self) -> None:
        """TC-NST-REC-2000-BODY: 2.000 níveis de aninhamento provocando RecursionError no json.loads."""
        nested_json = '{"k":' * 2000 + '1' + '}' * 2000
        event = {"body": nested_json}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-REC-2000-BODY",
            category="Deeply Nested JSON (Recursion Limit)",
            description="Disparo de RecursionError via 2.000 níveis de aninhamento no body, validando captura segura com HTTP 400",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())

    def test_nst_recursion_limit_2000_content(self) -> None:
        """TC-NST-REC-2000-CONTENT: 2.000 níveis de aninhamento dentro do campo content de política IAM."""
        nested_content = '{"k":' * 2000 + '1' + '}' * 2000
        event = {"body": json.dumps({"type": "iam", "content": nested_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-REC-2000-CONTENT",
            category="Deeply Nested JSON (Recursion Limit)",
            description="Disparo de RecursionError via 2.000 níveis de aninhamento no campo content do IAM, validando captura sem 500",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())

    def test_nst_recursion_limit_600_iam_objects(self) -> None:
        """TC-NST-REC-600-IAM-OBJ: 600 níveis de objetos aninhados no campo content de IAM, disparando RecursionError."""
        nested_content = '{"Statement":' * 600 + '[]' + '}' * 600
        event = {"body": json.dumps({"type": "iam", "content": nested_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-REC-600-IAM-OBJ",
            category="Deeply Nested JSON (Recursion Limit)",
            description="Disparo de RecursionError via 600 níveis de aninhamento de objetos em política IAM, tratado com HTTP 400",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())

    def test_nst_recursion_limit_600_iam_arrays(self) -> None:
        """TC-NST-REC-600-IAM-ARR: 600 níveis de listas aninhadas no campo content de IAM, disparando RecursionError."""
        nested_content = '{"Statement":' + '[' * 600 + ']' * 600 + '}'
        event = {"body": json.dumps({"type": "iam", "content": nested_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-NST-REC-600-IAM-ARR",
            category="Deeply Nested JSON (Recursion Limit)",
            description="Disparo de RecursionError via 600 níveis de aninhamento de arrays em política IAM, tratado com HTTP 400",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("recursion", body["error"].lower())


class TestContractFuzzing(StressTestBase):
    """Cenário 3: Fuzzing de Contrato, Entradas Malformadas, Base64 e Unicode."""

    def test_fuz_empty_body(self) -> None:
        """TC-FUZ-01: Corpo da requisição vazio."""
        event = {"body": ""}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-EMPTY-BODY",
            category="Contract Fuzzing",
            description="Requisição com campo body contendo string vazia",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_none_body(self) -> None:
        """TC-FUZ-02: Corpo da requisição como None."""
        event = {"body": None}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NONE-BODY",
            category="Contract Fuzzing",
            description="Requisição com campo body contendo valor None",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_invalid_json_body(self) -> None:
        """TC-FUZ-03: Corpo com sintaxe JSON corrompida."""
        event = {"body": '{"type": "iam", "content": '}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-INVALID-JSON",
            category="Contract Fuzzing",
            description="Requisição com JSON corrompido / sintaxe incompleta no body",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_missing_body_empty_event(self) -> None:
        """TC-FUZ-04: Evento vazio sem corpo ({}) e sem campos."""
        event: Dict[str, Any] = {}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-MISSING-BODY",
            category="Contract Fuzzing",
            description="Evento Lambda vazio sem chave body e sem campos de auditoria",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_non_dict_event_raw_string(self) -> None:
        """TC-FUZ-05: Evento recebido como string plana não-JSON."""
        event = "Esta é uma string arbitrária que não é JSON."
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NON-DICT-STR",
            category="Contract Fuzzing",
            description="Invocação do handler recebendo string direta em vez de dicionário ou JSON",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_non_dict_event_primitive(self) -> None:
        """TC-FUZ-06: Evento recebido como tipo primitivo (int)."""
        event = 987654321
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NON-DICT-PRIMITIVE",
            category="Contract Fuzzing",
            description="Invocação do handler recebendo tipo numérico inteiro como event",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_non_dict_event_list(self) -> None:
        """TC-FUZ-07: Evento recebido como lista Python."""
        event = [{"type": "iam"}]
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NON-DICT-LIST",
            category="Contract Fuzzing",
            description="Invocação do handler recebendo lista em vez de dicionário de evento",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_base64_encoded_valid(self) -> None:
        """TC-FUZ-08: Corpo codificado em Base64 válido (isBase64Encoded=True)."""
        raw_obj = {
            "type": "iam",
            "content": json.dumps({"Version": "2012-10-17", "Statement": []}),
        }
        b64_bytes = base64.b64encode(json.dumps(raw_obj).encode("utf-8"))
        event = {
            "body": b64_bytes.decode("utf-8"),
            "isBase64Encoded": True,
        }
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-B64-VALID",
            category="Contract Fuzzing (Base64)",
            description="Payload válido codificado em Base64 com flag isBase64Encoded=True",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_fuz_base64_encoded_corrupted(self) -> None:
        """TC-FUZ-09: Corpo codificado com Base64 corrompido / caracteres inválidos."""
        event = {
            "body": "!!!Esta_Nao_E_Uma_String_Base64_Valida@@@==",
            "isBase64Encoded": True,
        }
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-B64-CORRUPTED",
            category="Contract Fuzzing (Base64)",
            description="Flag isBase64Encoded=True com string Base64 inválida/corrompida",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("base64", body["error"].lower())

    def test_fuz_type_none(self) -> None:
        """TC-FUZ-10: Campo type com valor None."""
        event = {"body": json.dumps({"type": None, "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-NONE",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' explicitamente nulo (None)",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_type_empty_string(self) -> None:
        """TC-FUZ-11: Campo type com string vazia."""
        event = {"body": json.dumps({"type": "", "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-EMPTY",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' contendo string vazia",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_type_unsupported(self) -> None:
        """TC-FUZ-12: Campo type com provedor não suportado (ex: arm_template)."""
        event = {"body": json.dumps({"type": "arm_template", "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-UNSUPPORTED",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' informando tecnologia não suportada ('arm_template')",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)
        self.assertIn("tipo de auditoria inválido", body["error"].lower())

    def test_fuz_type_int(self) -> None:
        """TC-FUZ-13: Campo type com valor inteiro."""
        event = {"body": json.dumps({"type": 12345, "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-INT",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' numérico (int)",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_type_list(self) -> None:
        """TC-FUZ-14: Campo type como lista."""
        event = {"body": json.dumps({"type": ["iam"], "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-LIST",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' como lista em vez de string",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_type_dict(self) -> None:
        """TC-FUZ-15: Campo type como dicionário."""
        event = {"body": json.dumps({"type": {"name": "iam"}, "content": "..."})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-TYPE-DICT",
            category="Contract Fuzzing (Type)",
            description="Requisição com campo 'type' como objeto JSON",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_none(self) -> None:
        """TC-FUZ-16: Campo content com valor None."""
        event = {"body": json.dumps({"type": "iam", "content": None})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-NONE",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' explicitamente nulo",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_empty_string(self) -> None:
        """TC-FUZ-17: Campo content com string vazia."""
        event = {"body": json.dumps({"type": "iam", "content": ""})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-EMPTY",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' vazio",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_whitespace_only(self) -> None:
        """TC-FUZ-18: Campo content contendo apenas espaços em branco, quebras de linha e tabs."""
        event = {"body": json.dumps({"type": "iam", "content": "   \n\t  \r  "})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-WHITESPACE",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' preenchido apenas com whitespace",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_int(self) -> None:
        """TC-FUZ-19: Campo content com valor numérico inteiro."""
        event = {"body": json.dumps({"type": "iam", "content": 99999})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-INT",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' como número inteiro em vez de string",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_list(self) -> None:
        """TC-FUZ-20: Campo content como lista."""
        event = {"body": json.dumps({"type": "iam", "content": ["s3:*", "iam:*"]})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-LIST",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' como lista de strings",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_content_dict(self) -> None:
        """TC-FUZ-21: Campo content como dicionário JSON bruto em vez de string serializada."""
        event = {"body": json.dumps({"type": "iam", "content": {"Version": "2012-10-17"}})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTENT-DICT",
            category="Contract Fuzzing (Content)",
            description="Requisição com campo 'content' como objeto JSON em vez de string",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_null_bytes_iam(self) -> None:
        """TC-FUZ-22: Injeção de byte nulo (\x00) no conteúdo de política IAM."""
        raw_content = '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Sid": "Null\x00Byte",\n      "Effect": "Allow",\n      "Action": "s3:*",\n      "Resource": "*"\n    }\n  ]\n}'
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NULL-BYTE-IAM",
            category="Contract Fuzzing (Unicode & Malformed Controls)",
            description="Tentativa de injeção de byte nulo literal (\\x00) dentro de string JSON do IAM",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_null_bytes_tf(self) -> None:
        """TC-FUZ-23: Injeção de byte nulo (\x00) no manifesto Terraform HCL."""
        raw_content = 'resource "aws_security_group" "sg_\x00_test" {\n  name = "sg_test"\n}'
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-NULL-BYTE-TF",
            category="Contract Fuzzing (Unicode & Malformed Controls)",
            description="Tentativa de injeção de byte nulo literal (\\x00) no manifesto HCL de Terraform",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)

    def test_fuz_control_characters_iam(self) -> None:
        """TC-FUZ-24: Caracteres de controle ASCII (\x01\x02\x08\x1b) em política IAM."""
        raw_content = '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Sid": "Ctrl\x01\x02\x08\x1bTest",\n      "Effect": "Allow",\n      "Action": "s3:*",\n      "Resource": "*"\n    }\n  ]\n}'
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTROL-CHARS-IAM",
            category="Contract Fuzzing (Unicode & Malformed Controls)",
            description="Injeção de caracteres de controle ASCII não escapados em JSON do IAM",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_unicode_multilingual(self) -> None:
        """TC-FUZ-25: Conteúdo com emojis, Cirílico, Chinês e Árabe (RTL)."""
        raw_content = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "🔐_Segurança_🛡️_Привет_世界_مرحبا_123",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ],
        })
        event = {"body": json.dumps({"type": "iam", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-UNICODE-MULTILINGUAL",
            category="Contract Fuzzing (Unicode & Malformed Controls)",
            description="Payload contendo caracteres Unicode multilíngues, emojis complexos e scripts RTL",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_fuz_parameter_pollution(self) -> None:
        """TC-FUZ-26: Parameter pollution com campos espúrios e protótipos."""
        polluted_obj = {
            "type": "iam",
            "content": json.dumps({"Version": "2012-10-17", "Statement": []}),
            "admin": True,
            "bypass_rules": ["IAM-001", "IAM-002"],
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"polluted": True}},
        }
        event = {"body": json.dumps(polluted_obj)}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-PARAM-POLLUTION",
            category="Contract Fuzzing (Security Probing)",
            description="Injeção de campos espúrios e poluição de parâmetros (admin, __proto__, bypass_rules)",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)
        self.assertIn("findings", body)

    def test_fuz_redos_unterminated_block_comment(self) -> None:
        """TC-FUZ-27: Teste anti-ReDoS com bloco de comentário /* não finalizado seguido de 200.000 caracteres."""
        malicious_comment = "/*" + ("A" * 200000)
        hcl_content = f"""
resource "aws_security_group" "sg_redos" {{
  name = "sg_redos"
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
{malicious_comment}
"""
        event = {"body": json.dumps({"type": "terraform", "content": hcl_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-REDOS-COMMENT",
            category="Contract Fuzzing (ReDoS Probe)",
            description="Verificação anti-ReDoS em regex de comentários HCL com bloco não-terminado de 200k chars",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)

    def test_fuz_options_preflight_v1(self) -> None:
        """TC-FUZ-28: Requisição OPTIONS preflight via formato REST / API Gateway v1 (httpMethod)."""
        event = {"httpMethod": "OPTIONS"}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-OPTIONS-V1",
            category="Contract Fuzzing (CORS Preflight)",
            description="Requisição OPTIONS preflight via evento legado/v1 (httpMethod='OPTIONS')",
            event=event,
            expected_status=200,
        )
        self.assertEqual(body.get("status"), "ok")

    def test_fuz_options_preflight_v2(self) -> None:
        """TC-FUZ-29: Requisição OPTIONS preflight via formato HTTP API v2 (requestContext.http.method)."""
        event = {
            "requestContext": {
                "http": {
                    "method": "OPTIONS",
                    "path": "/audit",
                }
            }
        }
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-OPTIONS-V2",
            category="Contract Fuzzing (CORS Preflight)",
            description="Requisição OPTIONS preflight via evento HTTP API v2 (requestContext.http.method='OPTIONS')",
            event=event,
            expected_status=200,
        )
        self.assertEqual(body.get("status"), "ok")

    def test_fuz_event_none(self) -> None:
        """TC-FUZ-30: Evento Lambda recebido como None."""
        event = None
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-EVENT-NONE",
            category="Contract Fuzzing",
            description="Invocação do handler recebendo None como evento Lambda",
            event=event,
            expected_status=400,
        )
        self.assertIn("error", body)

    def test_fuz_control_characters_tf(self) -> None:
        """TC-FUZ-31: Caracteres de controle ASCII (\x01\x07\x0b\x1f) em manifesto Terraform HCL."""
        raw_content = 'resource "aws_security_group" "sg_ctrl" {\n  name = "sg_\x01\x07\x0b\x1ftest"\n  ingress {\n    from_port = 80\n    to_port = 80\n    protocol = "tcp"\n    cidr_blocks = ["10.0.0.0/16"]\n  }\n}'
        event = {"body": json.dumps({"type": "terraform", "content": raw_content})}
        _, body = self.invoke_handler_measured(
            scenario_id="TC-FUZ-CONTROL-CHARS-TF",
            category="Contract Fuzzing (Unicode & Malformed Controls)",
            description="Sanitização de caracteres de controle ASCII em manifesto Terraform HCL",
            event=event,
            expected_status=200,
        )
        self.assertIn("score", body)


class TestPayloadSizeDefense(StressTestBase):
    """Cenário 4: Validação de Limite de Payload Estrito (512 KB / HTTP 413)."""

    def test_str_limit_exceeded_512kb(self) -> None:
        """TC-STR-LIMIT-EXCEEDED-512KB: Rejeição imediata de payload superior a 512 KB com HTTP 413."""
        saved_limit = handler.MAX_PAYLOAD_BYTES
        try:
            handler.MAX_PAYLOAD_BYTES = 512 * 1024
            # 525 KB payload
            large_content = "X" * (525 * 1024)
            event = {"body": json.dumps({"type": "iam", "content": large_content})}
            _, body = self.invoke_handler_measured(
                scenario_id="TC-STR-LIMIT-EXCEEDED-512KB",
                category="Payload Size Defense",
                description="Submissão de payload de 525 KB com limite estrito de 512 KB retornando HTTP 413",
                event=event,
                expected_status=413,
            )
            self.assertIn("error", body)
            self.assertIn("512 kb", body["error"].lower())
        finally:
            handler.MAX_PAYLOAD_BYTES = saved_limit

    def test_str_limit_exceeded_b64(self) -> None:
        """TC-STR-LIMIT-EXCEEDED-B64: Rejeição de payload Base64 decodificado superior a 512 KB com HTTP 413."""
        saved_limit = handler.MAX_PAYLOAD_BYTES
        try:
            handler.MAX_PAYLOAD_BYTES = 512 * 1024
            raw_data = "Y" * (530 * 1024)
            b64_str = base64.b64encode(raw_data.encode("utf-8")).decode("utf-8")
            event = {"body": b64_str, "isBase64Encoded": True}
            _, body = self.invoke_handler_measured(
                scenario_id="TC-STR-LIMIT-EXCEEDED-B64",
                category="Payload Size Defense",
                description="Payload Base64 com dados decodificados superiores a 512 KB retornando HTTP 413",
                event=event,
                expected_status=413,
            )
            self.assertIn("error", body)
            self.assertIn("512 kb", body["error"].lower())
        finally:
            handler.MAX_PAYLOAD_BYTES = saved_limit


def tearDownModule() -> None:
    """Executado após todos os testes para persistir o relatório consolidado."""
    save_structured_results()


if __name__ == "__main__":
    unittest.main()
