"""
Auditor Engine for AWS IAM Policies and Terraform HCL.
Implements static rule analysis using only the Python standard library.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple


SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 10,
    "LOW": 5,
}

SENSITIVE_PORTS: List[int] = [22, 3389, 5432, 3306]


def calculate_score_and_risk(findings: List[Dict[str, Any]]) -> Tuple[int, str]:
    """
    Calculates safety score (0-100) and consolidated risk level
    in accordance with README specification:
      - Initial score: 100
      - CRITICAL: -30
      - HIGH: -15
      - MEDIUM: -10
      - LOW: -5
      - Bounds: [0, 100]
      - Risk:
          CRITICAL: score < 40 or at least one CRITICAL finding
          HIGH: 40 <= score < 70
          MEDIUM: 70 <= score < 90
          LOW: 90 <= score <= 100
    """
    deductions = sum(SEVERITY_WEIGHTS.get(f.get("severity", ""), 0) for f in findings)
    score = max(0, min(100, 100 - deductions))
    has_critical = any(f.get("severity") == "CRITICAL" for f in findings)

    if score < 40 or has_critical:
        risk_level = "CRITICAL"
    elif 40 <= score < 70:
        risk_level = "HIGH"
    elif 70 <= score < 90:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level


def _create_finding(
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
) -> Dict[str, str]:
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }


def audit_iam(content: str) -> Dict[str, Any]:
    """
    Audits an AWS IAM Policy JSON document.
    Detects wildcards, NotAction, PassRole without conditions, wildcard principals,
    and missing best practice controls.
    """
    findings: List[Dict[str, Any]] = []

    try:
        policy = json.loads(content)
    except Exception as exc:
        raise ValueError(f"JSON de política IAM inválido: {str(exc)}") from exc

    if not isinstance(policy, dict):
        raise ValueError("O documento de política IAM deve ser um objeto JSON.")

    # Rule IAM-006: Version check
    version = policy.get("Version")
    if version != "2012-10-17":
        findings.append(
            _create_finding(
                rule_id="IAM-006",
                title="Versão de Política Incorreta ou Ausente",
                severity="LOW",
                description=(
                    f"A política especifica a versão '{version}' ou não define a versão normativa '2012-10-17'."
                    if version
                    else "A política não especifica a versão normativa '2012-10-17'."
                ),
                recommendation="Defina explicitamente '\"Version\": \"2012-10-17\"' no cabeçalho do documento de política IAM.",
            )
        )

    # Extract statements
    statements_raw = policy.get("Statement", [])
    if isinstance(statements_raw, dict):
        statements = [statements_raw]
    elif isinstance(statements_raw, list):
        statements = statements_raw
    else:
        # Fallback if the root object is a single statement
        if "Effect" in policy or "Action" in policy:
            statements = [policy]
        else:
            statements = []

    for idx, stmt in enumerate(statements, start=1):
        if not isinstance(stmt, dict):
            continue

        sid_info = f" (Sid: '{stmt['Sid']}')" if "Sid" in stmt else f" (Statement #{idx})"
        effect = stmt.get("Effect", "Allow")
        is_allow = str(effect).lower() == "allow"

        # Rule IAM-008: Wildcard Principal
        principal = stmt.get("Principal")
        if principal:
            is_wildcard_principal = False
            if principal == "*":
                is_wildcard_principal = True
            elif isinstance(principal, dict):
                for _, p_val in principal.items():
                    if p_val == "*" or (isinstance(p_val, list) and "*" in p_val):
                        is_wildcard_principal = True
                        break
            elif isinstance(principal, list) and "*" in principal:
                is_wildcard_principal = True

            if is_wildcard_principal:
                findings.append(
                    _create_finding(
                        rule_id="IAM-008",
                        title="Uso de Wildcard Global em Principal",
                        severity="CRITICAL",
                        description=f"O statement{sid_info} define 'Principal' como wildcard (*), permitindo acesso irrestrito ou não autenticado a qualquer entidade.",
                        recommendation="Restrinja o campo Principal explicitamente para ARNs de roles, usuários ou contas autorizadas.",
                    )
                )

        if not is_allow:
            continue

        # Rule IAM-007: NotAction with Allow
        if "NotAction" in stmt:
            findings.append(
                _create_finding(
                    rule_id="IAM-007",
                    title="Uso Perigoso de NotAction com Allow",
                    severity="CRITICAL",
                    description=f"O statement{sid_info} utiliza 'NotAction' com efeito 'Allow', concedendo acesso irrestrito a todas as ações não expressamente listadas.",
                    recommendation="Remova 'NotAction' com efeito Allow. Declare explicitamente as ações necessárias no campo 'Action'.",
                )
            )

        # Rule IAM-001, IAM-003, IAM-004, IAM-009: Action analysis
        raw_actions = stmt.get("Action", [])
        if isinstance(raw_actions, str):
            actions = [raw_actions]
        elif isinstance(raw_actions, list):
            actions = [str(a) for a in raw_actions]
        else:
            actions = []

        has_global_action_wildcard = False
        has_service_wildcard = False
        has_sensitive_iam = False
        has_destructive_wildcard = False
        has_passrole = False

        for act in actions:
            act_clean = act.strip()
            act_lower = act_clean.lower()

            if act_clean == "*":
                has_global_action_wildcard = True
            elif act_clean.endswith(":*"):
                has_service_wildcard = True

            if act_lower == "iam:passrole":
                has_passrole = True
            elif act_lower == "iam:*" or act_clean == "*":
                has_passrole = True

            if act_lower.startswith("iam:") and act_lower not in ["iam:get*", "iam:list*"]:
                if any(
                    act_lower.startswith(prefix)
                    for prefix in [
                        "iam:*",
                        "iam:attach",
                        "iam:put",
                        "iam:create",
                        "iam:update",
                        "iam:delete",
                        "iam:passrole",
                    ]
                ):
                    has_sensitive_iam = True

            if any(term in act_lower for term in [":delete*", ":terminate*", ":drop*"]):
                has_destructive_wildcard = True

        if has_global_action_wildcard or has_service_wildcard:
            findings.append(
                _create_finding(
                    rule_id="IAM-001",
                    title="Ação Universal com Wildcard",
                    severity="CRITICAL",
                    description=f"O statement{sid_info} permite ação wildcard (*), concedendo privilégios abrangentes ou irrestritos em serviços AWS.",
                    recommendation="Restrinja o campo Action estritamente para as operações necessárias (ex: s3:GetObject, ec2:DescribeInstances).",
                )
            )

        # Rule IAM-009: iam:PassRole without condition
        if has_passrole:
            condition = stmt.get("Condition")
            condition_valid = False
            if isinstance(condition, dict) and len(condition) > 0:
                cond_str = json.dumps(condition).lower()
                if "iam:passedtoservice" in cond_str or "stringequals" in cond_str:
                    condition_valid = True

            if not condition_valid:
                findings.append(
                    _create_finding(
                        rule_id="IAM-009",
                        title="iam:PassRole sem Restrição de Condição",
                        severity="HIGH",
                        description=f"O statement{sid_info} concede a permissão sensível 'iam:PassRole' sem restrição de condição ('iam:PassedToService'), permitindo escalação de privilégios.",
                        recommendation="Restrinja 'iam:PassRole' com a condição 'iam:PassedToService' apontando para serviços autorizados e limite os ARNs em Resource.",
                    )
                )

        # Rule IAM-003: Potential Administrative Permissions
        if has_sensitive_iam and not has_global_action_wildcard and not has_service_wildcard:
            findings.append(
                _create_finding(
                    rule_id="IAM-003",
                    title="Permissão Administrativa Potencial",
                    severity="HIGH",
                    description=f"O statement{sid_info} concede ações administrativas sensíveis de gerenciamento de identidade (IAM), ampliando a superfície de escalação.",
                    recommendation="Isole permissões de escrita/associação do IAM em roles dedicadas protegidas por MFA e aprovação prévia.",
                )
            )

        # Rule IAM-004: Unrestricted Deletion Permissions
        if has_destructive_wildcard and not has_global_action_wildcard:
            findings.append(
                _create_finding(
                    rule_id="IAM-004",
                    title="Permissões de Exclusão Irrestrita",
                    severity="HIGH",
                    description=f"O statement{sid_info} permite remoção ou destruição em lote com wildcards destrutivos (*:Delete*, *:Terminate*, *:Drop*).",
                    recommendation="Explicite individualmente as operações de exclusão estritamente necessárias e exija MFA delete quando aplicável.",
                )
            )

        # Rule IAM-002: Wildcard Resource
        raw_resources = stmt.get("Resource", [])
        if isinstance(raw_resources, str):
            resources = [raw_resources]
        elif isinstance(raw_resources, list):
            resources = [str(r) for r in raw_resources]
        else:
            resources = []

        if any(r.strip() == "*" for r in resources):
            findings.append(
                _create_finding(
                    rule_id="IAM-002",
                    title="Recurso Universal com Wildcard",
                    severity="CRITICAL",
                    description=f"O statement{sid_info} concede permissões a todos os recursos da conta ('Resource': '*').",
                    recommendation="Especifique o ARN exato do recurso ao qual as permissões se aplicam.",
                )
            )

        # Rule IAM-005: Allow Statement without Condition
        condition = stmt.get("Condition")
        if not condition or not isinstance(condition, dict) or len(condition) == 0:
            findings.append(
                _create_finding(
                    rule_id="IAM-005",
                    title="Statement Allow sem Condição",
                    severity="MEDIUM",
                    description=f"O statement{sid_info} concede efeito 'Allow' sem nenhuma cláusula de restrição 'Condition' associada.",
                    recommendation="Adicione cláusulas Condition (ex: aws:PrincipalArn, aws:SourceVpc, aws:SecureTransport) para restringir o contexto de invocação.",
                )
            )

    score, risk_level = calculate_score_and_risk(findings)
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
    }


def _strip_hcl_comments(content: str) -> str:
    """Removes single-line and multi-line comments from HCL content."""
    # Remove block comments /* ... */
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    # Remove line comments starting with // or #
    lines = []
    for line in content.splitlines():
        # Keep quotes intact while stripping comments
        clean_line = ""
        in_quote = False
        escape = False
        i = 0
        while i < len(line):
            c = line[i]
            if escape:
                clean_line += c
                escape = False
            elif c == "\\":
                clean_line += c
                escape = True
            elif c == '"':
                in_quote = not in_quote
                clean_line += c
            elif not in_quote:
                if c == "#" or (c == "/" and i + 1 < len(line) and line[i + 1] == "/"):
                    break
                clean_line += c
            else:
                clean_line += c
            i += 1
        lines.append(clean_line)
    return "\n".join(lines)


def _extract_hcl_resources(clean_content: str) -> List[Dict[str, str]]:
    """
    Extracts top-level resource blocks using brace-counting parsing.
    Returns list of dicts: {'type': str, 'name': str, 'body': str}
    """
    resources = []
    pattern = re.compile(r'resource\s+"([a-zA-Z0-9_\-]+)"\s+"([a-zA-Z0-9_\-]+)"\s*\{')

    for match in pattern.finditer(clean_content):
        res_type = match.group(1)
        res_name = match.group(2)
        start_brace = match.end() - 1

        # Match balanced braces
        depth = 0
        body_start = match.end()
        body_end = None

        for idx in range(start_brace, len(clean_content)):
            char = clean_content[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    body_end = idx
                    break

        if body_end is not None:
            body = clean_content[body_start:body_end]
            resources.append({
                "type": res_type,
                "name": res_name,
                "body": body,
            })

    return resources


def _extract_blocks(body: str, block_name: str) -> List[str]:
    """Extracts nested blocks like ingress { ... } or tags = { ... } from a resource body."""
    blocks = []
    pattern = re.compile(rf'{block_name}\s*\{{')
    for match in pattern.finditer(body):
        start_brace = match.end() - 1
        depth = 0
        block_end = None
        for idx in range(start_brace, len(body)):
            char = body[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    block_end = idx
                    break
        if block_end is not None:
            blocks.append(body[match.end():block_end])
    return blocks


def audit_terraform(content: str) -> Dict[str, Any]:
    """
    Audits a Terraform HCL code snippet.
    Detects open sensitive ports in security groups (22, 3389, 5432, 3306),
    public S3 buckets, lack of S3 public access block, lack of encryption in
    EBS, RDS, and S3, and missing governance tags.
    """
    findings: List[Dict[str, Any]] = []

    clean_content = _strip_hcl_comments(content)
    resources = _extract_hcl_resources(clean_content)

    s3_buckets: List[Dict[str, str]] = []
    s3_pab_resources: List[Dict[str, str]] = []
    s3_sse_resources: List[Dict[str, str]] = []

    for res in resources:
        res_type = res["type"]
        res_name = res["name"]
        body = res["body"]

        # Rule TF-001: Security Group Open Sensitive Ports
        if res_type == "aws_security_group":
            ingress_blocks = _extract_blocks(body, "ingress")
            for ing in ingress_blocks:
                _check_ingress_rule(ing, res_name, findings)

        elif res_type == "aws_security_group_rule":
            type_match = re.search(r'type\s*=\s*["\']ingress["\']', body)
            if type_match:
                _check_ingress_rule(body, res_name, findings)

        # Collect S3 resources
        if res_type == "aws_s3_bucket":
            s3_buckets.append(res)
            # Check inline ACL
            if re.search(r'acl\s*=\s*["\']public-(read|read-write)["\']', body):
                findings.append(
                    _create_finding(
                        rule_id="TF-002",
                        title="Bucket S3 com ACL Pública",
                        severity="HIGH",
                        description=f"O bucket S3 '{res_name}' está configurado com ACL pública ('public-read' ou 'public-read-write').",
                        recommendation="Configure a ACL como 'private' e desative ACLs com aws_s3_bucket_ownership_controls (BucketOwnerEnforced).",
                    )
                )

        elif res_type == "aws_s3_bucket_acl":
            if re.search(r'acl\s*=\s*["\']public-(read|read-write)["\']', body):
                findings.append(
                    _create_finding(
                        rule_id="TF-002",
                        title="Bucket S3 com ACL Pública",
                        severity="HIGH",
                        description=f"O recurso aws_s3_bucket_acl '{res_name}' concede leitura ou escrita pública ao bucket.",
                        recommendation="Remova ACLs públicas e adote controle de acesso baseado em IAM e Bucket Policies estritas.",
                    )
                )

        elif res_type == "aws_s3_bucket_public_access_block":
            s3_pab_resources.append(res)

        elif res_type == "aws_s3_bucket_server_side_encryption_configuration":
            s3_sse_resources.append(res)

        # Rule TF-006: EBS Volume Encryption
        if res_type == "aws_ebs_volume":
            has_encryption = re.search(r'encrypted\s*=\s*true', body, re.IGNORECASE)
            is_explicit_false = re.search(r'encrypted\s*=\s*false', body, re.IGNORECASE)
            if is_explicit_false or not has_encryption:
                findings.append(
                    _create_finding(
                        rule_id="TF-006",
                        title="Volume EBS sem Criptografia em Repouso",
                        severity="HIGH",
                        description=f"O volume EBS '{res_name}' foi provisionado sem criptografia ativada ('encrypted = true').",
                        recommendation="Adicione 'encrypted = true' e vincule uma chave AWS KMS gerenciada ou customer-managed.",
                    )
                )

        elif res_type == "aws_instance":
            block_devices = _extract_blocks(body, "root_block_device") + _extract_blocks(body, "ebs_block_device")
            for bd in block_devices:
                has_encryption = re.search(r'encrypted\s*=\s*true', bd, re.IGNORECASE)
                is_explicit_false = re.search(r'encrypted\s*=\s*false', bd, re.IGNORECASE)
                if is_explicit_false or not has_encryption:
                    findings.append(
                        _create_finding(
                            rule_id="TF-006",
                            title="Volume EBS sem Criptografia em Repouso",
                            severity="HIGH",
                            description=f"Dispositivo de bloco na instância EC2 '{res_name}' não possui criptografia ativada.",
                            recommendation="Defina 'encrypted = true' no bloco de armazenamento da instância EC2.",
                        )
                    )

        # Rule TF-007: RDS Storage Encryption
        if res_type == "aws_db_instance":
            has_storage_enc = re.search(r'storage_encrypted\s*=\s*true', body, re.IGNORECASE)
            is_explicit_false = re.search(r'storage_encrypted\s*=\s*false', body, re.IGNORECASE)
            if is_explicit_false or not has_storage_enc:
                findings.append(
                    _create_finding(
                        rule_id="TF-007",
                        title="Instância RDS sem Criptografia em Repouso",
                        severity="HIGH",
                        description=f"A instância RDS '{res_name}' está configurada sem criptografia de armazenamento em repouso ('storage_encrypted = true').",
                        recommendation="Habilite 'storage_encrypted = true' para garantir a proteção dos dados armazenados no banco de dados.",
                    )
                )

        # Rule TF-005: Governance Tags
        governed_types = ["aws_s3_bucket", "aws_security_group", "aws_ebs_volume", "aws_db_instance", "aws_instance"]
        if res_type in governed_types:
            has_tags = re.search(r'tags\s*=\s*[\{\(]', body)
            has_env_or_proj = False
            if has_tags:
                tags_str = body[has_tags.start():]
                if "environment" in tags_str.lower() or "project" in tags_str.lower():
                    has_env_or_proj = True

            if not has_tags or not has_env_or_proj:
                findings.append(
                    _create_finding(
                        rule_id="TF-005",
                        title="Ausência de Tags Padrão de Governança",
                        severity="LOW",
                        description=f"O recurso {res_type} '{res_name}' não possui tags de governança com 'Environment' ou 'Project'.",
                        recommendation="Adicione o bloco tags com pelo menos as chaves 'Environment' e 'Project' para rastreabilidade de custos.",
                    )
                )

    # Post-checks for S3 buckets (TF-003, TF-004)
    if s3_buckets:
        # Check Public Access Block
        if not s3_pab_resources:
            findings.append(
                _create_finding(
                    rule_id="TF-003",
                    title="Ausência de Bloqueio Público no S3",
                    severity="HIGH",
                    description="O código provisiona bucket S3 sem o recurso complementar aws_s3_bucket_public_access_block.",
                    recommendation="Crie o recurso aws_s3_bucket_public_access_block com todas as quatro proteções definidas como true.",
                )
            )
        else:
            for pab in s3_pab_resources:
                body = pab["body"]
                flags = [
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                ]
                has_disabled_flag = False
                for flg in flags:
                    if re.search(rf'{flg}\s*=\s*false', body, re.IGNORECASE):
                        has_disabled_flag = True
                        break
                if has_disabled_flag:
                    findings.append(
                        _create_finding(
                            rule_id="TF-003",
                            title="Ausência de Bloqueio Público no S3",
                            severity="HIGH",
                            description=f"O recurso aws_s3_bucket_public_access_block '{pab['name']}' possui flags de proteção definidas como false.",
                            recommendation="Defina block_public_acls, block_public_policy, ignore_public_acls e restrict_public_buckets como true.",
                        )
                    )

        # Check S3 Encryption (TF-004)
        has_global_sse = len(s3_sse_resources) > 0
        for bucket in s3_buckets:
            body = bucket["body"]
            has_inline_sse = "server_side_encryption_configuration" in body
            if not has_global_sse and not has_inline_sse:
                findings.append(
                    _create_finding(
                        rule_id="TF-004",
                        title="Bucket S3 sem Criptografia em Repouso",
                        severity="MEDIUM",
                        description=f"O bucket S3 '{bucket['name']}' não possui configuração de criptografia em repouso (SSE).",
                        recommendation="Configure aws_s3_bucket_server_side_encryption_configuration usando algoritmo AES256 ou AWS KMS.",
                    )
                )

    score, risk_level = calculate_score_and_risk(findings)
    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
    }


def _check_ingress_rule(rule_body: str, sg_name: str, findings: List[Dict[str, Any]]) -> None:
    """Checks an ingress rule body for 0.0.0.0/0 on sensitive ports (22, 3389, 5432, 3306)."""
    has_world_cidr = False
    cidr_match = re.search(r'cidr_blocks\s*=\s*\[(.*?)\]', rule_body, re.DOTALL)
    if cidr_match:
        cidr_content = cidr_match.group(1)
        if '"0.0.0.0/0"' in cidr_content or "'0.0.0.0/0'" in cidr_content or '"::/0"' in cidr_content:
            has_world_cidr = True

    if not has_world_cidr:
        return

    from_port_m = re.search(r'from_port\s*=\s*(\d+)', rule_body)
    to_port_m = re.search(r'to_port\s*=\s*(\d+)', rule_body)

    if from_port_m and to_port_m:
        from_port = int(from_port_m.group(1))
        to_port = int(to_port_m.group(1))
    else:
        from_port = 0
        to_port = 65535

    exposed_ports = []
    # If 0 to 0 (all traffic)
    if from_port == 0 and to_port == 0:
        exposed_ports = SENSITIVE_PORTS
    else:
        for p in SENSITIVE_PORTS:
            if from_port <= p <= to_port:
                exposed_ports.append(p)

    if exposed_ports:
        port_names = {
            22: "SSH (22)",
            3389: "RDP (3389)",
            5432: "PostgreSQL (5432)",
            3306: "MySQL (3306)",
        }
        port_labels = ", ".join(port_names.get(p, str(p)) for p in exposed_ports)
        findings.append(
            _create_finding(
                rule_id="TF-001",
                title="Porta Administrativa Aberta para a Internet",
                severity="CRITICAL",
                description=(
                    f"Security Group '{sg_name}' permite tráfego irrestrito de '0.0.0.0/0' "
                    f"nas portas sensíveis: {port_labels}."
                ),
                recommendation="Restrinja o acesso de entrada a CIDRs de VPNs, bastion hosts ou IPs administrativos autorizados.",
            )
        )
