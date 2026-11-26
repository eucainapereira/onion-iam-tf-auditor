# Plano Técnico de Hardening & Remediação de Segurança (HARDENING_PLAN.md)
**Projeto:** Onion IAM & Terraform Security Auditor (`onion-iam-tf-auditor`)  
**Branch Base:** `qa/stress-audit`  
**Branch de Correção:** `fix/hardening-v1`  
**Perfil:** Engenheiro Sênior de AppSec e Backend  
**Data:** 26 de Novembro de 2026  
**Status:** APROVADO PARA EXECUÇÃO  

---

## 1. Visão Geral e Arquitetura de Hardening

Este documento estabelece o contrato técnico prescritivo e o plano de engenharia de segurança para a remediação exaustiva de todas as 15 fragilidades, bypasses semânticos e vulnerabilidades de código identificados durante o ciclo de QA no `QA_REPORT.md`.

O hardening é estruturado em três eixos complementares:
1. **AppSec / Motor de Auditoria (`src/auditor.py` e `src/handler.py`):** Eliminação de evasões de parsing (normalização de casing), tratamento de inversão lógica (`NotResource`), restrições estritas de privilégio (`iam:PassRole`, `authenticated-read`, wildcards parciais), prevenção de falso positivo em regras `Deny`, e estabelecimento de limite de statements contra esgotamento de recursos (DoS/OOM).
2. **Frontend SPA (`web/app.js` e `web/index.html`):** Erradicação de vetor de Cross-Site Scripting (DOM XSS) através de validação estrita por whitelist e escape defensivo, ativação de Content-Security-Policy (CSP) rígida, resiliência de rede com timeout (`AbortSignal.timeout`) e validação de `response.ok`, além de modernização da UX substituindo chamadas bloqueantes `alert()` por notificações no DOM.
3. **Infraestrutura Serverless (`terraform/*.tf` e `src/handler.py`):** Configuração de throttling e burst limit no API Gateway v2 HTTP API e parametrização de CORS seguro por variável de ambiente.

---

## 2. Matriz Consolidada de Remediação (QA-001 a QA-015)

| ID | Prioridade | Severidade | Componente | Arquivo Alvo | Função / Bloco | Tipo de Remediação |
| :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| **`QA-001`** | **P0** | **CRITICAL** | Backend Engine | `src/auditor.py` | `audit_iam()` | Normalização recursiva de casing de chaves JSON |
| **`QA-002`** | **P0** | **CRITICAL** | Backend Engine | `src/auditor.py` | `audit_iam()` | Avaliação e penalização crítica de `NotResource` com `Allow` |
| **`QA-003`** | **P0** | **CRITICAL** | Backend Engine | `src/auditor.py` | `audit_iam()` | Supressão de falso positivo de `IAM-008` em `Effect: Deny` |
| **`QA-004`** | **P0** | **HIGH** | Frontend SPA | `web/app.js` | `renderFindingsList()` | Sanitização e whitelist estrita de `severity` contra DOM XSS |
| **`QA-005`** | **P1** | **HIGH** | Backend Engine | `src/auditor.py` | `audit_iam()` | Validação estrita de `iam:PassedToService` em `iam:PassRole` |
| **`QA-006`** | **P1** | **HIGH** | Backend Engine | `src/auditor.py` | `audit_terraform()` | Inclusão de `authenticated-read` na regex de ACL S3 (`TF-002`) |
| **`QA-007`** | **P1** | **HIGH** | Backend Engine | `src/auditor.py` | `audit_iam()` | Detecção ampla de wildcards em radicais de ações IAM |
| **`QA-008`** | **P1** | **MEDIUM** | Frontend SPA | `web/index.html` | `<head>` | Inclusão de meta tag Content-Security-Policy (CSP) estrita |
| **`QA-009`** | **P1** | **MEDIUM** | Frontend SPA | `web/app.js` | Listener `#btnAudit` | Implementação de `AbortSignal.timeout(15000)` no `fetch()` |
| **`QA-010`** | **P1** | **MEDIUM** | Lambda / Engine | `src/auditor.py` / `src/handler.py` | `audit_iam()` / `lambda_handler()` | Teto defensivo de quantidade máxima de statements (DoS) |
| **`QA-011`** | **P2** | **LOW** | Frontend SPA | `web/app.js` | `escapeHtml()` | Coerção de tipo defensiva `String(str)` antes de replace |
| **`QA-012`** | **P2** | **LOW** | Frontend SPA | `web/app.js` | Handlers de Erro | Substituição de `alert()` síncrono por banner inline no DOM |
| **`QA-013`** | **P2** | **LOW** | Frontend SPA | `web/app.js` | Listener `#btnAudit` | Checagem de `response.ok` e `Content-Type` antes de `.json()` |
| **`QA-014`** | **P2** | **LOW** | Frontend SPA | `web/app.js` | Listener `#btnSaveApiUrl` | Validação de protocolo (`https:`) via `new URL()` |
| **`QA-015`** | **P2** | **LOW / INFO** | Infra / Handler | `terraform/api_gateway.tf` / `src/handler.py` | Stage `$default` / `_response()` | Rate limiting / burst no API GW e parametrização CORS |

---

## 3. Especificação Detalhada das Correções de Código

---

### QA-001: IAM Casing Evasion (Normalização Recursiva de Chaves JSON)
- **ID:** `QA-001`
- **Prioridade:** P0 (Crítico)
- **CWE:** CWE-178 (Improper Handling of Case Sensitivity)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_iam(content: str)` (linhas 79-116)
- **Cenário de Teste:** `TC-EVA-IAM-LOWERCASE-KEYS-BYPASS` e `TC-EVA-IAM-MIXED-CASE-KEYS-BYPASS` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** O motor utiliza acessos diretos com case rígido em dicionários Python (`policy.get("Statement")`, `stmt.get("Action")`, `stmt.get("Resource")`). Ao receber JSON serializado com chaves em minúsculo (`"statement"`, `"action"`), as extrações retornam coleções vazias e ignoram as regras de segurança, emitindo score 95 (`LOW`) para permissões totais `*`.
- **Correção Exata a Aplicar:**
  Criar a função auxiliar `_normalize_iam_dict_keys` e aplicá-la recursivamente sobre o dicionário retornado por `json.loads`:
  ```python
  def _normalize_iam_dict_keys(d: Any) -> Any:
      """
      Normaliza recursivamente as chaves de documentos IAM para o padrão PascalCase canônico.
      Previne evasões semânticas por variação de casing (QA-001).
      """
      if isinstance(d, dict):
          key_map = {
              "version": "Version",
              "statement": "Statement",
              "sid": "Sid",
              "effect": "Effect",
              "principal": "Principal",
              "notprincipal": "NotPrincipal",
              "action": "Action",
              "notaction": "NotAction",
              "resource": "Resource",
              "notresource": "NotResource",
              "condition": "Condition",
          }
          return {
              key_map.get(k.lower(), k): _normalize_iam_dict_keys(v)
              for k, v in d.items()
          }
      elif isinstance(d, list):
          return [_normalize_iam_dict_keys(item) for item in d]
      return d
  ```
  Na função `audit_iam`:
  ```python
  policy = json.loads(content)
  if not isinstance(policy, dict):
      raise ValueError("O documento de política IAM deve ser um objeto JSON.")
  policy = _normalize_iam_dict_keys(policy)
  ```
- **Critério de Validação:** A suíte `test_eva_iam_lowercase_keys_bypass` e `test_eva_iam_mixed_case_keys_bypass` deve detectar `IAM-001`, `IAM-002` e classificar o risco como `CRITICAL` (score 0).

---

### QA-002: Inversão Lógica via `NotResource` Não Avaliada
- **ID:** `QA-002`
- **Prioridade:** P0 (Crítico)
- **CWE:** CWE-285 (Improper Authorization / Privilege Inversion)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_iam(content: str)` (seção de análise de recursos, linhas 267-286)
- **Cenário de Teste:** `TC-EVA-IAM-NOTRESOURCE-BYPASS` e `TC-EVA-IAM-NOTRESOURCE-WILDCARD-ACTION` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** A regra `IAM-002` inspeciona somente a chave `Resource`. Na semântica da AWS, usar `NotResource` em um statement com `Effect: Allow` autoriza a ação contra qualquer recurso que não pertença à lista de exceção, configurando uma concessão universal de recursos com severidade idêntica a `Resource: "*"`.
- **Correção Exata a Aplicar:**
  Adicionar a inspeção de `NotResource` no statement quando `is_allow` for verdadeiro:
  ```python
  # Rule IAM-002: Wildcard Resource or Dangerous NotResource with Allow
  raw_resources = stmt.get("Resource", [])
  if isinstance(raw_resources, str):
      resources = [raw_resources]
  elif isinstance(raw_resources, list):
      resources = [str(r) for r in raw_resources]
  else:
      resources = []

  has_wildcard_resource = any(r.strip() == "*" for r in resources)
  has_not_resource = "NotResource" in stmt

  if has_wildcard_resource:
      findings.append(
          _create_finding(
              rule_id="IAM-002",
              title="Recurso Universal com Wildcard",
              severity="CRITICAL",
              description=f"O statement{sid_info} concede permissões a todos os recursos da conta ('Resource': '*').",
              recommendation="Especifique o ARN exato do recurso ao qual as permissões se aplicam.",
          )
      )
  elif has_not_resource:
      findings.append(
          _create_finding(
              rule_id="IAM-002",
              title="Uso Perigoso de NotResource com Permissão Allow",
              severity="CRITICAL",
              description=f"O statement{sid_info} define 'NotResource' com efeito 'Allow', concedendo permissão irrestrita a todos os outros recursos da AWS.",
              recommendation="Remova 'NotResource' em statements Allow. Liste os recursos específicos autorizados no campo 'Resource'.",
          )
      )
  ```
- **Critério de Validação:** `test_eva_iam_notresource_bypass` deve identificar `IAM-002` com severidade `CRITICAL`.

---

### QA-003: Penalização Incorreta de Regras Defensivas `Deny` (Falso Positivo)
- **ID:** `QA-003`
- **Prioridade:** P0 (Crítico)
- **CWE:** CWE-398 (Indicator of Poor Code Quality / Logic Flaw)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_iam(content: str)` (linhas 125-151)
- **Cenário de Teste:** `TC-EVA-IAM-DENY-TLS-FALSE-POSITIVE` e `TC-EVA-IAM-DENY-IP-FALSE-POSITIVE` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** O bloco da regra `IAM-008` (verificação de `Principal: "*"`) é posicionado antes do comando `if not is_allow: continue`. Políticas defensivas padrão da AWS (ex: guardrails de TLS obrigatório ou listas de IP permitidos) utilizam `Effect: Deny`, `Principal: "*"` e uma `Condition` restritiva. O motor emite `IAM-008` com severidade `CRITICAL`, rebaixando o score de uma política segura para risco crítico.
- **Correção Exata a Aplicar:**
  Mover o bloco de inspeção de `IAM-008` para após a condicional `if not is_allow: continue`:
  ```python
  effect = stmt.get("Effect", "Allow")
  is_allow = str(effect).lower() == "allow"

  if not is_allow:
      continue

  # Rule IAM-008: Wildcard Principal (aplicável estritamente em statements Effect: Allow)
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
  ```
- **Critério de Validação:** As políticas com `Effect: Deny` em `test_eva_iam_deny_tls_enforcement_false_positive` e `test_eva_iam_deny_ip_restriction_false_positive` devem retornar score 100, risco `LOW` e 0 achados de `IAM-008`.

---

### QA-004: DOM XSS via Interpolação de Severidade Não Sanitizada em `innerHTML`
- **ID:** `QA-004`
- **Prioridade:** P0 (Crítico)
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation / DOM XSS)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** `renderFindingsList(findings)` (linhas 380-396)
- **Cenário de Teste:** `FE-XSS-001` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** A variável `sev` é obtida através de `(finding.severity || 'LOW').toUpperCase()` e interpolada diretamente em strings de classes CSS e texto (`card.className = "finding-card severity-${sev}"` e `<span class="finding-severity-badge severity-badge-${sev}">${sev}</span>`). Se a API retornar uma carga com injeção (ex: `<img src=x onerror=alert(1)>`), o navegador renderiza o HTML e executa scripts.
- **Correção Exata a Aplicar:**
  Validar a severidade contra uma lista permitida fechada (whitelist) e aplicar escape defensivo:
  ```javascript
  const ALLOWED_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

  function renderFindingsList(findings) {
    findingsList.innerHTML = '';

    findings.forEach(finding => {
      const card = document.createElement('div');
      const rawSev = String(finding.severity || 'LOW').toUpperCase().trim();
      const sev = ALLOWED_SEVERITIES.has(rawSev) ? rawSev : 'LOW';
      card.className = `finding-card severity-${sev}`;

      card.innerHTML = `
        <div class="finding-card-header">
          <span class="finding-id-badge">${escapeHtml(finding.id)}</span>
          <span class="finding-severity-badge severity-badge-${sev}">${escapeHtml(sev)}</span>
        </div>
        <h4 class="finding-title">${escapeHtml(finding.title)}</h4>
        <p class="finding-desc">${escapeHtml(finding.description)}</p>
        <div class="finding-rec-box">
          <span class="rec-label">💡 Recomendação de Correção:</span>
          <span class="rec-content">${escapeHtml(finding.recommendation)}</span>
        </div>
      `;

      findingsList.appendChild(card);
    });
  }
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve aprovar o controle de interpolação sem apontar `FE-XSS-001`.

---

### QA-005: Bypass em `iam:PassRole` com Condições Irrelevantes
- **ID:** `QA-005`
- **Prioridade:** P1 (Alta)
- **CWE:** CWE-284 (Improper Access Control / Privilege Escalation)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_iam(content: str)` (linhas 224-242)
- **Cenário de Teste:** `TC-EVA-IAM-PASSROLE-IRRELEVANT-COND-BYPASS` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** Na validação da regra `IAM-009`, o código executa `if "iam:passedtoservice" in cond_str or "stringequals" in cond_str: condition_valid = True`. A presença de qualquer operador genérico `StringEquals` (mesmo para chaves irrelevantes como `aws:username`) satisfaz a condição e suprime o alerta de escalação de privilégios.
- **Correção Exata a Aplicar:**
  Exigir estritamente que a restrição contenha `iam:PassedToService`:
  ```python
  # Rule IAM-009: iam:PassRole without proper service constraint condition
  if has_passrole:
      condition = stmt.get("Condition")
      condition_valid = False
      if isinstance(condition, dict) and len(condition) > 0:
          cond_str = json.dumps(condition).lower()
          if "iam:passedtoservice" in cond_str:
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
  ```
- **Critério de Validação:** O cenário `test_eva_iam_passrole_irrelevant_condition_bypass` deve emitir o achado `IAM-009`.

---

### QA-006: Bypass Semântico de ACL Pública S3 (`authenticated-read`)
- **ID:** `QA-006`
- **Prioridade:** P1 (Alta)
- **CWE:** CWE-284 (Improper Access Control / Public Data Exposure)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_terraform(content: str)` (linhas 438-461)
- **Cenário de Teste:** `TC-EVA-TF-S3-AUTH-READ-BYPASS` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** A expressão regular utilizada para verificar ACLs abertas em buckets S3 busca apenas `public-read` e `public-read-write`. A ACL pré-definida da AWS `authenticated-read` concede permissões de leitura a qualquer usuário ou conta AWS autenticada no mundo, configurando exposição pública não intencional.
- **Correção Exata a Aplicar:**
  Definir uma constante de regex unificada contemplando `authenticated-read`:
  ```python
  PUBLIC_S3_ACL_PATTERN = re.compile(
      r'acl\s*=\s*["\'](public-(?:read|read-write)|authenticated-read)["\']',
      re.IGNORECASE,
  )
  ```
  E aplicá-la em `aws_s3_bucket` e `aws_s3_bucket_acl`:
  ```python
  # Check inline ACL
  if PUBLIC_S3_ACL_PATTERN.search(body):
      findings.append(
          _create_finding(
              rule_id="TF-002",
              title="Bucket S3 com ACL Pública",
              severity="HIGH",
              description=f"O bucket S3 '{res_name}' está configurado com ACL pública ou semi-pública ('public-read', 'public-read-write' ou 'authenticated-read').",
              recommendation="Configure a ACL como 'private' e desative ACLs com aws_s3_bucket_ownership_controls (BucketOwnerEnforced).",
          )
      )
  ```
- **Critério de Validação:** `test_eva_tf_s3_authenticated_read_bypass` deve identificar `TF-002` com severidade `HIGH`.

---

### QA-007: Evasão de Wildcard em Radicais de Ações IAM
- **ID:** `QA-007`
- **Prioridade:** P1 (Alta)
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Arquivo Alvo:** `src/auditor.py`
- **Função / Seção:** `audit_iam(content: str)` (linhas 180-221)
- **Cenário de Teste:** `TC-EVA-IAM-WILDCARD-VERB-BYPASS` em `qa/test_evasion_bypass.py`
- **Diagnóstico da Causa Raiz:** A inspeção de ações wildcard só verifica igualdade com `*` ou terminação com `:*`. Wildcards parciais nos verbos ou radicais de ações (`"s3:Get*"`, `"s3:Put*"`, `"ec2:Describe*"`) não são capturados pela regra `IAM-001`.
- **Correção Exata a Aplicar:**
  Expandir a lógica para marcar `has_service_wildcard = True` sempre que o caractere `*` estiver presente na string da ação:
  ```python
  for act in actions:
      act_clean = act.strip()
      act_lower = act_clean.lower()

      if act_clean == "*":
          has_global_action_wildcard = True
      elif "*" in act_clean:
          has_service_wildcard = True
  ```
- **Critério de Validação:** `test_eva_iam_partial_wildcard_action_bypass` deve emitir o achado `IAM-001`.

---

### QA-008: Ausência de Content-Security-Policy (CSP) no Frontend
- **ID:** `QA-008`
- **Prioridade:** P1 (Média / Defesa em Profundidade)
- **CWE:** CWE-358 (Cumulative Inconsistencies / Missing CSP)
- **Arquivo Alvo:** `web/index.html`
- **Função / Seção:** Bloco `<head>` (linhas 3-12)
- **Cenário de Teste:** `FE-CSP-001` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** O HTML não define diretiva CSP via `<meta http-equiv="Content-Security-Policy">`. O navegador fica desprovido de restrições de origem para carregamento de scripts, folhas de estilo e conexões assíncronas.
- **Correção Exata a Aplicar:**
  Adicionar a seguinte tag meta no `<head>` de `web/index.html`:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; connect-src 'self' https://*.execute-api.us-east-2.amazonaws.com;">
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve aprovar `FE-CSP-001`.

---

### QA-009: Ausência de Timeout no `fetch()` do Frontend
- **ID:** `QA-009`
- **Prioridade:** P1 (Média / Resiliência de Rede)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption / Hang UI)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** Listener do botão `#btnAudit` (linhas 254-265)
- **Cenário de Teste:** `FE-NET-001` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** Chamada `fetch(targetUrl, ...)` assíncrona não define `signal: AbortSignal.timeout(15000)`. Em condições de perda de pacotes ou lentidão excessiva, a interface permanece desabilitada e travada indefinidamente com spinner.
- **Correção Exata a Aplicar:**
  Configurar timeout de 15 segundos nas opções do `fetch`:
  ```javascript
  const response = await fetch(targetUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: currentType,
      content: content,
    }),
    signal: AbortSignal.timeout(15000),
  });
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve aprovar `FE-NET-001`.

---

### QA-010: Ausência de Limite Defensivo de Statements (Risco DoS / OOM na Lambda)
- **ID:** `QA-010`
- **Prioridade:** P1 (Média / Resiliência DoS FinOps)
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Arquivo Alvo:** `src/auditor.py` e `src/handler.py`
- **Função / Seção:** `audit_iam()` em `src/auditor.py` e `lambda_handler()` em `src/handler.py`
- **Cenário de Teste:** `TC-STR-IAM-NESTING-OVERFLOW` e limites volumétricos em `qa/test_stress_local.py`
- **Diagnóstico da Causa Raiz:** Payloads de políticas IAM contendo mais de 100.000 statements alocam volumes de memória superiores a 360 MB, excedendo o limite de 128 MB alocado para a função Lambda (`terraform/lambda.tf`), provocando queda abrupta por OOM.
- **Correção Exata a Aplicar:**
  Em `src/auditor.py`:
  ```python
  MAX_ALLOWED_STATEMENTS: int = 500

  # Na extração de statements em audit_iam():
  if len(statements) > MAX_ALLOWED_STATEMENTS:
      raise ValueError(
          f"O documento excede o limite máximo permitido de {MAX_ALLOWED_STATEMENTS} statements por política."
      )
  ```
  Em `src/handler.py`:
  ```python
  MAX_PAYLOAD_CHARACTERS: int = 2_000_000  # 2 MB de caracteres

  if len(content) > MAX_PAYLOAD_CHARACTERS:
      return _response(400, {"error": "O conteúdo excede o limite máximo de 2 MB permitido."})
  ```
- **Critério de Validação:** Payloads densos que excedam 500 statements devem retornar `HTTP 400 Bad Request` controlado, sem lançar exceções 500 ou causar terminação da Lambda.

---

### QA-011: Ausência de Coerção de Tipo em `escapeHtml`
- **ID:** `QA-011`
- **Prioridade:** P2 (Baixa / Robustez)
- **CWE:** CWE-704 (Incorrect Type Conversion or Cast)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** `escapeHtml(str)` (linhas 402-410)
- **Cenário de Teste:** `FE-XSS-002` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** A função executa `str.replace()` diretamente. Caso a entrada recebida seja numérica, booleana ou um objeto, ocorre `TypeError: str.replace is not a function`, quebrando a thread de renderização da UI.
- **Correção Exata a Aplicar:**
  Garantir a conversão segura para string:
  ```javascript
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve aprovar `FE-XSS-002`.

---

### QA-012: Uso de `alert()` Síncrono Bloqueante
- **ID:** `QA-012`
- **Prioridade:** P2 (Baixa / UX e Acessibilidade)
- **CWE:** CWE-1078 (Improper UI Freezing)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** Validações de clique e tratamento de erro (linhas 236, 243, 274)
- **Cenário de Teste:** `FE-NET-002` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** O uso da função nativa `alert()` suspende a execução do motor JavaScript e bloqueia a navegação do usuário.
- **Correção Exata a Aplicar:**
  Criar uma função utilitária `showNotification(message, type = 'error')` que renderiza um banner inline na interface (usando o container de status ou criando um elemento dinâmico acessível), e substituir todas as chamadas de `alert()`:
  ```javascript
  function showNotification(message, type = 'error') {
    let notifyBanner = document.getElementById('notificationBanner');
    if (!notifyBanner) {
      notifyBanner = document.createElement('div');
      notifyBanner.id = 'notificationBanner';
      notifyBanner.className = 'notification-banner';
      const container = document.querySelector('.app-container');
      container.insertBefore(notifyBanner, container.querySelector('.main-layout'));
    }
    notifyBanner.textContent = message;
    notifyBanner.className = `notification-banner banner-${type}`;
    notifyBanner.style.display = 'block';
    setTimeout(() => {
      notifyBanner.style.display = 'none';
    }, 6000);
  }
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve registrar a ausência de chamadas `alert()`.

---

### QA-013: Desserialização JSON Precipitada sem Validação de `response.ok`
- **ID:** `QA-013`
- **Prioridade:** P2 (Baixa / Resiliência de Rede)
- **CWE:** CWE-248 (Uncaught Exception / Protocol Parsing)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** Listener do botão `#btnAudit` (linhas 266-270)
- **Cenário de Teste:** `FE-NET-004` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** Execução cega de `await response.json()` antes de inspecionar `response.ok` e o cabeçalho `Content-Type`. Respostas 502/504 retornadas por proxies intermediários em HTML provocam `SyntaxError: Unexpected token < in JSON`.
- **Correção Exata a Aplicar:**
  ```javascript
  const contentType = response.headers.get('content-type') || '';
  let data = null;

  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    const rawText = await response.text();
    if (!response.ok) {
      throw new Error(`Erro na API (${response.status}): ${rawText.slice(0, 150)}`);
    }
    throw new Error('A resposta da API não está em formato JSON válido.');
  }

  if (!response.ok) {
    throw new Error(data && data.error ? data.error : `Erro HTTP ${response.status}`);
  }
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve validar `FE-NET-004`.

---

### QA-014: Falta de Validação de Protocolo na URL Manual da API
- **ID:** `QA-014`
- **Prioridade:** P2 (Baixa / Validação de Entrada)
- **CWE:** CWE-20 (Improper Input Validation)
- **Arquivo Alvo:** `web/app.js`
- **Função / Seção:** Listener `#btnSaveApiUrl` (linhas 167-175)
- **Cenário de Teste:** `FE-INP-002` em `qa/audit_frontend.py`
- **Diagnóstico da Causa Raiz:** O input de texto aceita qualquer string sem checar se é uma URL válida com esquema `https:`, permitindo esquemas perigosos como `javascript:` ou URLs quebradas.
- **Correção Exata a Aplicar:**
  ```javascript
  if (btnSaveApiUrl) {
    btnSaveApiUrl.addEventListener('click', () => {
      const val = apiUrlInput.value.trim();
      if (!val) return;

      try {
        const parsed = new URL(val);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          showNotification('Apenas URLs HTTP ou HTTPS são permitidas.', 'error');
          return;
        }
        activeApiUrl = parsed.toString();
        window.API_URL = activeApiUrl;
        checkApiStatus();
        showNotification('Endpoint da API configurado com sucesso!', 'success');
      } catch (e) {
        showNotification('URL informada possui formato inválido.', 'error');
      }
    });
  }
  ```
- **Critério de Validação:** `qa/audit_frontend.py` deve certificar `FE-INP-002`.

---

### QA-015: Permissividade Excessiva de Origem CORS (`*`) e Rate Limiting
- **ID:** `QA-015`
- **Prioridade:** P2 (Baixa / Hardening de Infraestrutura)
- **CWE:** CWE-942 (Permissive Cross-Domain Policy) / CWE-770 (Lack of Throttling)
- **Arquivo Alvo:** `terraform/api_gateway.tf` e `src/handler.py`
- **Função / Seção:** Recurso `aws_apigatewayv2_stage.default` e dicionário `CORS_HEADERS`
- **Cenário de Teste:** Sonda `PROBE-01-CORS-OPTIONS` em `qa/probe_production.py`
- **Diagnóstico da Causa Raiz:** A API expõe `Access-Control-Allow-Origin: *` estático e o estágio padrão do API Gateway não define cotas de burst e rate limit contra abusos.
- **Correção Exata a Aplicar:**
  Em `src/handler.py`:
  ```python
  import os

  ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

  CORS_HEADERS: Dict[str, str] = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
  }
  ```
  Em `terraform/api_gateway.tf`:
  ```hcl
  resource "aws_apigatewayv2_stage" "default" {
    api_id      = aws_apigatewayv2_api.http_api.id
    name        = "$default"
    auto_deploy = true

    route_settings {
      route_key              = "POST /audit"
      throttling_burst_limit = 50
      throttling_rate_limit  = 100
    }

    tags = local.common_tags
  }
  ```
- **Critério de Validação:** Garantir compatibilidade do preflight CORS mantendo resposta 200 nas sondas de produção e protegendo contra picos de tráfego.

---

## 4. Ordem e Fases de Execução da Refatoração (Para as Próximas Camadas)

Para garantir rastreabilidade, isolamento de escopo e zero quebra de contrato, as correções devem ser executadas ordenadamente nas próximas camadas:

```
[Camada 2] Hardening do Motor de Auditoria Backend (src/auditor.py & src/handler.py)
   ├── QA-001 (Normalização de Casing JSON)
   ├── QA-002 (Inversão Lógica NotResource)
   ├── QA-003 (Eliminação de Falso Positivo Deny)
   ├── QA-005 (iam:PassRole restrito a iam:PassedToService)
   ├── QA-006 (ACL S3 'authenticated-read' em TF-002)
   ├── QA-007 (Detecção ampla de Wildcards IAM)
   └── QA-010 (Teto de Statements / Proteção DoS)

[Camada 3] Hardening do Frontend SPA (web/app.js & web/index.html)
   ├── QA-004 (Eliminação de DOM XSS via Whitelist em Severidade)
   ├── QA-008 (Meta tag Content-Security-Policy estrita)
   ├── QA-009 (Timeout defensivo de 15s via AbortSignal)
   ├── QA-011 (Coerção de tipo defensiva em escapeHtml)
   ├── QA-012 (Substituição de alert() por notificações DOM inline)
   ├── QA-013 (Validação de response.ok e Content-Type)
   └── QA-014 (Validação estrita de protocolo HTTPS no input de URL)

[Camada 4] Hardening de Infraestrutura & Deploy (terraform/*.tf)
   └── QA-015 (Throttling / Rate Limiting no API Gateway & CORS parametrizado)

[Camada 5] Validação Integral, Testes de Regressão e Homologação
   ├── Suíte de Evasão: python3 -m unittest qa/test_evasion_bypass.py (52 cenários)
   ├── Suíte de Estresse: python3 -m unittest qa/test_stress_local.py (42 cenários)
   ├── Auditoria Frontend: python3 qa/audit_frontend.py (Meta >= 90/100 SECURE)
   └── Sondas de Borda: python3 qa/probe_production.py (Se aplicável)
```

---

## 5. Critérios de Homologação Final
1. **Zero Bypasses e Zero Falsos Positivos:** Os 52 cenários de evasão semântica devem ser aprovados com todas as vulnerabilidades devidamente bloqueadas.
2. **Postura de Frontend `SECURE` (Score >= 90/100):** Eliminação integral dos achados `FE-XSS-001`, `FE-CSP-001`, `FE-NET-001`, `FE-NET-002`, `FE-NET-004`, `FE-XSS-002` e `FE-INP-002`.
3. **Resiliência e Zero Regressão:** Suíte volumétrica e de fuzzing operando com latência média inferior a 50 ms e zero estouro de memória.
4. **Contrato de API Preservado:** Manutenção estrita do schema de requisição (`{"type": "iam"|"terraform", "content": "..."}`) e resposta (`{"score": int, "risk_level": str, "findings": [...]}`).

---
*Plano Técnico de Hardening homologado para o branch `fix/hardening-v1`.*
