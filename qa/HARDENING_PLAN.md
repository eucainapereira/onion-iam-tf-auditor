# Plano Técnico de Hardening & Remediação de Segurança (HARDENING_PLAN.md)
**Projeto:** Onion IAM & Terraform Security Auditor (`onion-iam-tf-auditor`)  
**Branch Base:** `qa/stress-audit`  
**Branch de Correção:** `fix/hardening-v1`  
**Perfil:** Engenheiro Sênior de AppSec e Backend  
**Data:** 26 de Novembro de 2026  
**Status:** HOMOLOGADO E APROVADO PARA EXECUÇÃO  

---

## 1. Visão Geral e Arquitetura de Hardening

Este plano técnico estabelece o contrato prescritivo de engenharia de segurança e remediação integral para todos os **16 apontamentos de vulnerabilidade, vetores de evasão semântica e oportunidades de hardening** catalogados no [QA_REPORT.md](file:///app/workspace/github/onion-iam-tf-auditor/QA_REPORT.md).

O diagnóstico baseia-se na execução exaustiva de **112 cenários de teste automatizados** (48 de estresse volumétrico e fuzzing em `qa/results_local_stress.json`, 55 de evasão semântica e falsos positivos em `qa/results_evasion.json`, 9 sondas em produção na AWS em `qa/results_prod_probes.json` e 18 controles auditados estaticamente no frontend SPA).

A estratégia de hardening é organizada em três eixos arquiteturais interdependentes:

1. **Camada de Motor de Regras & Runtime Serverless (`src/auditor.py` e `src/handler.py`):**
   - Normalização recursiva de casing JSON contra evasões semânticas normativas (`QA-001`).
   - Avaliação e penalização rigorosa da diretiva `NotResource` sob efeito `Allow` (`QA-002`).
   - Supressão de falsos positivos em regras defensivas `Effect: Deny` (TLS e IP whitelisting) em `IAM-008` (`QA-003`).
   - Validação estrita de restrição de serviço `iam:PassedToService` em permissões `iam:PassRole` (`QA-005`).
   - Cobertura da ACL pública do S3 `authenticated-read` em regras de conformidade Terraform (`QA-006`).
   - Detecção ampla e recursiva de wildcards em radicais de verbos de ações IAM (`QA-007`).
   - Estabelecimento de tetos defensivos volumétricos de 500 statements e 512 KB de payload raw contra DoS/OOM (`QA-010`).
   - Fronteira global de exceção (`try/except Exception`) retornando HTTP 500 genérico sem vazamento de stack traces (`src/handler.py`).

2. **Camada de Frontend SPA & Resiliência de Interface (`web/app.js` e `web/index.html`):**
   - Erradicação de vetor de DOM XSS através de whitelist fechada de severidades (`ALLOWED_SEVERITIES`) e coerção de tipo na concatenação (`QA-004`).
   - Ativação de cabeçalho e meta tag de `Content-Security-Policy` (CSP) restritiva bloqueando injeções externas (`QA-008`).
   - Timeout defensivo de 15 segundos via `AbortController` nas requisições assíncronas do `fetch()` (`QA-009`).
   - Coerção defensiva de tipo primitivo na função `escapeHtml()` (`QA-011`).
   - Substituição integral de diálogos síncronos `alert()` por banner acessível e não bloqueante no DOM (`QA-012`).
   - Inspeção prévia do cabeçalho `Content-Type: application/json` antes da desserialização com `.json()` (`QA-013`).
   - Validação mandatória de esquema de protocolo (`http:` ou `https:`) no input manual de URL (`QA-014`).
   - Isolamento de dependências tipográficas remotas e preparação para hospedagem offline de fontes (`QA-016`).

3. **Camada de Infraestrutura Serverless & Borda de Rede (`terraform/*.tf` e `src/handler.py`):**
   - Configuração de rate limiting e burst limit no estágio `$default` do AWS API Gateway HTTP API v2 (`QA-015`).
   - Parametrização dinâmica da origem CORS através da variável de ambiente `ALLOWED_ORIGIN` no Lambda handler (`QA-015`).

---

## 2. Matriz Consolidada de Remediação (QA-001 a QA-016)

A tabela abaixo cruza cada apontamento do relatório de QA com o respectivo arquivo, função ou bloco de código e tipo de intervenção técnica:

| ID | Prioridade | Severidade | Componente | Arquivo Alvo | Função / Bloco | Tipo de Remediação |
| :---: | :---: | :---: | :--- | :--- | :--- | :--- |
| **`QA-001`** | **P0** | **CRITICAL** | Engine IAM | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L28-L57) | `audit_iam()` / `_normalize_iam_dict_keys()` | Normalização recursiva de casing de chaves JSON para PascalCase canônico. |
| **`QA-002`** | **P0** | **CRITICAL** | Engine IAM | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L330-L361) | `audit_iam()` / Regra `IAM-002` | Avaliação e penalização crítica da diretiva `NotResource` em statements `Allow`. |
| **`QA-003`** | **P0** | **CRITICAL** | Engine IAM | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L182-L218) | `audit_iam()` / Regra `IAM-008` | Mover verificação de `Principal: "*"` para após `if not is_allow: continue`. |
| **`QA-004`** | **P0** | **HIGH** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L498-L522) | `renderFindingsList()` | Sanitização e validação por whitelist (`ALLOWED_SEVERITIES`) contra DOM XSS. |
| **`QA-005`** | **P1** | **HIGH** | Engine IAM | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L286-L304) | `audit_iam()` / Regra `IAM-009` | Validação estrita de `iam:PassedToService` no bloco `Condition` em `iam:PassRole`. |
| **`QA-006`** | **P1** | **HIGH** | Engine Terraform | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L22-L26) | `audit_terraform()` / `PUBLIC_S3_ACL_PATTERN` | Inclusão de `authenticated-read` na regex de detecção de ACL pública em `TF-002`. |
| **`QA-007`** | **P1** | **HIGH** | Engine IAM | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L244-L284) | `audit_iam()` / Regra `IAM-001` | Detecção de asterisco `*` em qualquer posição do radical de ações IAM (`s3:Get*`). |
| **`QA-008`** | **P1** | **MEDIUM** | Frontend SPA | [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html#L6-L7) | `<head>` | Inclusão de meta tag Content-Security-Policy (CSP) restritiva no cabeçalho HTML. |
| **`QA-009`** | **P1** | **MEDIUM** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L328-L349) | Listener `#btnAudit` | Implementação de `AbortController` com timeout defensivo de 15 segundos no `fetch()`. |
| **`QA-010`** | **P1** | **MEDIUM** | Engine / Handler | [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py#L168-L173) / [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py#L25-L64) | `audit_iam()` / `_check_payload_size()` | Teto defensivo de 500 statements e guarda de 512 KB contra exaustão de memória e DoS. |
| **`QA-011`** | **P2** | **LOW** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L525-L534) | `escapeHtml()` | Coerção de tipo `String(str)` antes do encadeamento de `.replace()`. |
| **`QA-012`** | **P2** | **LOW** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L163-L201) | `showAlert()` / `#alertBanner` | Substituição de `alert()` por banner inline acessível no DOM (`#alertBanner`). |
| **`QA-013`** | **P2** | **LOW** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L353-L373) | Listener `#btnAudit` | Verificação explícita de `Content-Type: application/json` e `response.ok` antes de `.json()`. |
| **`QA-014`** | **P2** | **LOW** | Frontend SPA | [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js#L217-L239) | Listener `#btnSaveApiUrl` | Validação estrita de protocolo (`http:` ou `https:`) via construtor `new URL()`. |
| **`QA-015`** | **P2** | **LOW** | Infra / Handler | [terraform/api_gateway.tf](file:///app/workspace/github/onion-iam-tf-auditor/terraform/api_gateway.tf#L43-L54) / [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py#L28-L36) | Recurso `aws_apigatewayv2_stage` / `ALLOWED_ORIGIN` | Throttling de taxa/burst no API Gateway e CORS parametrizado por env var no Lambda. |
| **`QA-016`** | **P2** | **LOW / INFO** | Frontend SPA | [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html#L10-L13) | `<head>` / Links de Fontes | Isolamento de recursos tipográficos externos e governança de Subresource Integrity (SRI). |

---

## 3. Especificação Técnica Detalhada das Falhas e Contrato de Correção

Abaixo, cada uma das 16 falhas é detalhada no nível de código, causa raiz, reprodução e solução técnica.

---

### QA-001: IAM Casing Evasion (Sensibilidade a Maiúsculas/Minúsculas em Chaves JSON)
- **ID:** `QA-001`
- **Severidade:** CRITICAL | **Prioridade:** P0
- **CWE:** CWE-178 (Improper Handling of Case Sensitivity)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_iam(content: str)` (linhas 28-57 e 134-136)
- **Cenários de Teste:** `TC-EVA-IAM-LOWERCASE-KEYS-BYPASS` e `TC-EVA-IAM-MIXED-CASE-KEYS-BYPASS` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** O motor utilizava acessos diretos com case rígido em dicionários Python (`policy.get("Statement")`, `stmt.get("Action")`, `stmt.get("Resource")`). Ao receber políticas com chaves em minúsculas (`"statement"`, `"action"`), as extrações retornavam vazio, ignorando as regras de segurança e emitindo score 95 (`LOW`) para permissões globais `*`.
- **Payload Mínimo de Reprodução:**
  ```json
  {"version": "2012-10-17", "statement": [{"effect": "allow", "action": "*", "resource": "*"}]}
  ```
- **Correção Aplicada / Prescrita:**
  Implementar normalização recursiva de chaves de dicionário para PascalCase canônico:
  ```python
  def _normalize_iam_dict_keys(d: Any) -> Any:
      if isinstance(d, dict):
          key_map = {
              "version": "Version", "statement": "Statement", "sid": "Sid",
              "effect": "Effect", "principal": "Principal", "notprincipal": "NotPrincipal",
              "action": "Action", "notaction": "NotAction", "resource": "Resource",
              "notresource": "NotResource", "condition": "Condition",
              "aws": "AWS", "federated": "Federated", "service": "Service",
              "canonicaluser": "CanonicalUser",
          }
          return {key_map.get(k.lower(), k): _normalize_iam_dict_keys(v) for k, v in d.items()}
      elif isinstance(d, list):
          return [_normalize_iam_dict_keys(item) for item in d]
      return d

  # Em audit_iam():
  policy = _normalize_iam_dict_keys(policy)
  ```
- **Critério de Validação:** A suíte de evasão deve emitir `IAM-001`, `IAM-002` e classificar o risco como `CRITICAL` (score <= 15).

---

### QA-002: Inversão Lógica via Diretiva `NotResource` com Permissão `Allow`
- **ID:** `QA-002`
- **Severidade:** CRITICAL | **Prioridade:** P0
- **CWE:** CWE-285 (Improper Authorization / Privilege Inversion)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_iam(content: str)` (regra `IAM-002`, linhas 330-361)
- **Cenários de Teste:** `TC-EVA-IAM-NOTRESOURCE-BYPASS` e `TC-EVA-IAM-NOTRESOURCE-ACTION-WILDCARD` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** A regra `IAM-002` avaliava apenas a chave `Resource`. Declarar `NotResource` sob um statement com `Effect: Allow` autoriza a ação contra quase todos os recursos da conta AWS com exceção dos listados, constituindo um recurso universal velado.
- **Payload Mínimo de Reprodução:**
  ```json
  {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::vault-restrito/*"}]}
  ```
- **Correção Aplicada / Prescrita:**
  ```python
  raw_not_resources = stmt.get("NotResource")
  has_not_resource = False
  if raw_not_resources is not None:
      not_resources = _to_list(raw_not_resources)
      if len(not_resources) > 0:
          has_not_resource = True

  if has_wildcard_resource:
      findings.append(_create_finding(rule_id="IAM-002", title="Recurso Universal com Wildcard", severity="CRITICAL", ...))
  elif has_not_resource:
      findings.append(_create_finding(rule_id="IAM-002", title="Uso Perigoso de NotResource com Permissão Allow", severity="CRITICAL", ...))
  ```
- **Critério de Validação:** Disparo imediato de `IAM-002` com severidade `CRITICAL`.

---

### QA-003: Penalização Incorreta de Regras Defensivas `Effect: Deny` (Falso Positivo)
- **ID:** `QA-003`
- **Severidade:** CRITICAL | **Prioridade:** P0
- **CWE:** CWE-398 (Indicator of Poor Code Quality / Logic Flaw)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_iam(content: str)` (regra `IAM-008`, linhas 182-218)
- **Cenários de Teste:** `TC-EVA-IAM-DENY-TLS-FALSE-POSITIVE` e `TC-EVA-IAM-DENY-IP-FALSE-POSITIVE` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** A regra `IAM-008` (verificação de `Principal: "*"`) era executada antes do filtro `if not is_allow: continue`. Políticas defensivas mandatadas pelo CIS Benchmark (imposição de TLS e whitelist de IP corporativo) usam `Effect: Deny` e `Principal: "*"`, sendo penalizadas indevidamente como críticas.
- **Payload Mínimo de Reprodução:**
  ```json
  {"Version": "2012-10-17", "Statement": [{"Sid": "EnforceTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::meu-bucket/*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
  ```
- **Correção Aplicada / Prescrita:**
  Mover a checagem de `IAM-008` para após a validação `if not is_allow: continue`:
  ```python
  is_allow = str(stmt.get("Effect", "Allow")).strip().lower() == "allow"
  if not is_allow:
      continue

  # IAM-008 avaliado estritamente sob permissões Allow
  principal = stmt.get("Principal")
  if principal:
      # Lógica de detecção de wildcard em Principal...
  ```
- **Critério de Validação:** Guardrails defensivos de TLS e IP devem pontuar 100 com 0 apontamentos e risco `LOW`.

---

### QA-004: DOM XSS via Interpolação de Severidade Não Sanitizada em `card.innerHTML`
- **ID:** `QA-004`
- **Severidade:** HIGH | **Prioridade:** P0
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation / DOM XSS)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** `renderFindingsList(findings)` (linhas 498-522)
- **Cenários de Teste:** Controle `FE-XSS-001` em `qa/audit_frontend.py`
- **Causa Raiz:** Interpolação da variável de severidade diretamente na template string de classes e elementos (`card.innerHTML = ... severity-${sev} ...`). Se a resposta da API contiver payload malicioso no campo severity, scripts arbitrários são executados.
- **Correção Aplicada / Prescrita:**
  ```javascript
  const ALLOWED_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

  function renderFindingsList(findings) {
    findingsList.innerHTML = '';
    findings.forEach(finding => {
      const card = document.createElement('div');
      const rawSev = String(finding.severity || 'LOW').toUpperCase().trim();
      const safeSev = ALLOWED_SEVERITIES.has(rawSev) ? rawSev : 'LOW';
      card.className = `finding-card severity-${safeSev}`;
      card.innerHTML = `
        <div class="finding-card-header">
          <span class="finding-id-badge">${escapeHtml(finding.id)}</span>
          <span class="finding-severity-badge severity-badge-${safeSev}">${escapeHtml(safeSev)}</span>
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
- **Critério de Validação:** Auditor estático `qa/audit_frontend.py` aprovando sem falhas de interpolação.

---

### QA-005: Bypass em `iam:PassRole` com Condições Irrelevantes
- **ID:** `QA-005`
- **Severidade:** HIGH | **Prioridade:** P1
- **CWE:** CWE-284 (Improper Access Control / Privilege Escalation)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_iam(content: str)` (regra `IAM-009`, linhas 286-304)
- **Cenários de Teste:** `TC-EVA-IAM-PASSROLE-IRRELEVANT-COND-BYPASS` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** O código aceitava genericamente qualquer string `StringEquals` no bloco `Condition`, neutralizando a regra `IAM-009` mesmo para condições irrelevantes como `aws:username`.
- **Correção Aplicada / Prescrita:**
  Exigir explicitamente a presença mandatória de `iam:PassedToService`:
  ```python
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
- **Critério de Validação:** Detecção de `IAM-009` em permissões `iam:PassRole` desprovidas de `iam:PassedToService`.

---

### QA-006: Bypass Semântico de ACL Pública S3 (`authenticated-read`) no Terraform
- **ID:** `QA-006`
- **Severidade:** HIGH | **Prioridade:** P1
- **CWE:** CWE-284 (Improper Access Control / Public Data Exposure)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_terraform(content: str)` / `PUBLIC_S3_ACL_PATTERN` (linhas 22-26 e 513-535)
- **Cenários de Teste:** `TC-EVA-TF-S3-AUTH-READ-BYPASS` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** A regex para identificar ACL pública cobria apenas `public-read` e `public-read-write`, ignorando `authenticated-read`, que concede acesso a qualquer conta AWS no mundo.
- **Correção Aplicada / Prescrita:**
  ```python
  PUBLIC_S3_ACL_PATTERN = re.compile(
      r'acl\s*=\s*["\'](public-(?:read|read-write)|authenticated-read)["\']',
      re.IGNORECASE,
  )
  ```
- **Critério de Validação:** Disparo de `TF-002` com severidade `HIGH` para manifestos com `authenticated-read`.

---

### QA-007: Evasão de Wildcard em Radicais de Ações IAM (`s3:Get*`, `ec2:Describe*`)
- **ID:** `QA-007`
- **Severidade:** HIGH | **Prioridade:** P1
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função / Seção:** `audit_iam(content: str)` (regra `IAM-001`, linhas 244-284)
- **Cenários de Teste:** `TC-EVA-IAM-WILDCARD-VERB-BYPASS` em `qa/test_evasion_bypass.py`
- **Causa Raiz:** A regra avaliava apenas `*` isolado ou sufixos `:*`. Wildcards em radicais de verbos não eram capturados.
- **Correção Aplicada / Prescrita:**
  ```python
  for act in actions:
      act_clean = act.strip()
      if act_clean == "*":
          has_global_action_wildcard = True
      elif "*" in act_clean:
          has_service_wildcard = True
  ```
- **Critério de Validação:** Disparo de `IAM-001` (Ação Universal com Wildcard) para qualquer ação contendo `*`.

---

### QA-008: Ausência de Content-Security-Policy (CSP) Restritiva no Frontend
- **ID:** `QA-008`
- **Severidade:** MEDIUM | **Prioridade:** P1
- **CWE:** CWE-358 (Cumulative Inconsistencies / Missing CSP)
- **Arquivo Alvo:** [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html)
- **Localização:** Seção `<head>` (linhas 6-7)
- **Cenários de Teste:** Controle `FE-CSP-001` em `qa/audit_frontend.py`
- **Causa Raiz:** O documento HTML carecia de política de segurança de conteúdo, deixando o navegador sem guardrail contra execução de scripts externos.
- **Correção Aplicada / Prescrita:**
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.execute-api.us-east-2.amazonaws.com;">
  ```
- **Critério de Validação:** Meta tag detectada e aprovada pelo auditor de frontend.

---

### QA-009: Ausência de Timeout Defensivo no `fetch()` do Frontend
- **ID:** `QA-009`
- **Severidade:** MEDIUM | **Prioridade:** P1
- **CWE:** CWE-400 (Uncontrolled Resource Consumption / Hang UI)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** Listener `#btnAudit` (linhas 328-349)
- **Cenários de Teste:** Controle `FE-NET-001` em `qa/audit_frontend.py`
- **Causa Raiz:** Requisições assíncronas sem `AbortController` congelavam a interface indefinidamente caso ocorresse cold start severo ou falha de rede.
- **Correção Aplicada / Prescrita:**
  ```javascript
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: currentType, content: content }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
    btnAudit.disabled = false;
    auditSpinner.style.display = 'none';
  }
  ```
- **Critério de Validação:** Cancelamento automático após 15 segundos e desbloqueio garantido da UI.

---

### QA-010: Ausência de Limite Defensivo de Statements (Risco DoS / OOM na Lambda)
- **ID:** `QA-010`
- **Severidade:** MEDIUM | **Prioridade:** P1
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Arquivo Alvo:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py) e [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py)
- **Função / Seção:** `audit_iam()` em `src/auditor.py` e `_check_payload_size()` em `src/handler.py`
- **Cenários de Teste:** Cenários de densidade sintética em `qa/test_stress_local.py`
- **Causa Raiz:** Ausência de limitação no número de statements declarados por política IAM permitia submissões massivas que exauriam a memória de 128 MB da Lambda.
- **Correção Aplicada / Prescrita:**
  ```python
  # Em src/auditor.py:
  MAX_ALLOWED_STATEMENTS: int = 500
  if len(statements) > MAX_ALLOWED_STATEMENTS:
      raise ValueError(f"O documento excede o limite máximo permitido de {MAX_ALLOWED_STATEMENTS} statements por política.")

  # Em src/handler.py:
  MAX_PAYLOAD_BYTES: int = int(os.environ.get("MAX_PAYLOAD_BYTES", 512 * 1024))
  ```
- **Critério de Validação:** Rejeição limpa com HTTP 400 Bad Request sem queda por OOM.

---

### QA-011: Ausência de Coerção Segura de Tipo na Função `escapeHtml()`
- **ID:** `QA-011`
- **Severidade:** LOW | **Prioridade:** P2
- **CWE:** CWE-704 (Incorrect Type Conversion or Cast)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** `escapeHtml(str)` (linhas 525-534)
- **Cenários de Teste:** Controle `FE-XSS-002` em `qa/audit_frontend.py`
- **Causa Raiz:** Passagem de valores numéricos ou nulos causava `TypeError: str.replace is not a function`.
- **Correção Aplicada / Prescrita:**
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
- **Critério de Validação:** Aprovado em `FE-XSS-002` no auditor de frontend.

---

### QA-012: Uso de Diálogos Modais `alert()` Síncronos Bloqueantes
- **ID:** `QA-012`
- **Severidade:** LOW | **Prioridade:** P2
- **CWE:** CWE-1078 (Improper UI Freezing)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** `showAlert()` / `#alertBanner` (linhas 163-201)
- **Cenários de Teste:** Controle `FE-NET-002` em `qa/audit_frontend.py`
- **Causa Raiz:** Mensagens de erro disparadas via `window.alert()` travavam a thread da página.
- **Correção Aplicada / Prescrita:**
  Implementação de banner acessível `#alertBanner` com tipos `error`, `warning` e `info`.
- **Critério de Validação:** Zero invocações de `alert()` em `web/app.js`.

---

### QA-013: Desserialização JSON Precipitada sem Validação de `Content-Type`
- **ID:** `QA-013`
- **Severidade:** LOW | **Prioridade:** P2
- **CWE:** CWE-248 (Uncaught Exception / Protocol Parsing)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** Listener `#btnAudit` (linhas 353-373)
- **Cenários de Teste:** Controle `FE-NET-004` em `qa/audit_frontend.py`
- **Causa Raiz:** Invocação cega de `response.json()` diante de páginas HTML de erro 502/504 de proxy/WAF.
- **Correção Aplicada / Prescrita:**
  ```javascript
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    const rawText = await response.text();
    throw new Error(`Resposta com formato inesperado (HTTP ${response.status}): ${rawText.slice(0, 150)}`);
  }
  ```
- **Critério de Validação:** Aprovado em `FE-NET-004` no auditor de frontend.

---

### QA-014: Falta de Validação de Protocolo na URL Manual da API
- **ID:** `QA-014`
- **Severidade:** LOW | **Prioridade:** P2
- **CWE:** CWE-20 (Improper Input Validation)
- **Arquivo Alvo:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função / Seção:** Listener `#btnSaveApiUrl` (linhas 217-239)
- **Cenários de Teste:** Controle `FE-INP-002` em `qa/audit_frontend.py`
- **Causa Raiz:** O campo permitia qualquer texto, incluindo esquemas maliciosos (`javascript:`).
- **Correção Aplicada / Prescrita:**
  ```javascript
  const parsedUrl = new URL(val);
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    showAlert('Apenas URLs HTTP ou HTTPS são permitidas.', 'warning');
    return;
  }
  ```
- **Critério de Validação:** Aprovado em `FE-INP-002` no auditor de frontend.

---

### QA-015: Permissividade Excessiva de Origem CORS (`*`) e Ausência de Rate Limiting
- **ID:** `QA-015`
- **Severidade:** LOW | **Prioridade:** P2
- **CWE:** CWE-942 (Permissive Cross-Domain Policy) / CWE-770 (Lack of Throttling)
- **Arquivo Alvo:** [terraform/api_gateway.tf](file:///app/workspace/github/onion-iam-tf-auditor/terraform/api_gateway.tf) e [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py)
- **Função / Seção:** Recurso `aws_apigatewayv2_stage.default` e dicionário `CORS_HEADERS`
- **Cenários de Teste:** Sonda `PROBE-01-CORS-OPTIONS` em `qa/probe_production.py`
- **Causa Raiz:** `Access-Control-Allow-Origin: *` estático e ausência de rate limiting no API Gateway.
- **Correção Aplicada / Prescrita:**
  No Terraform:
  ```hcl
  resource "aws_apigatewayv2_stage" "default" {
    api_id      = aws_apigatewayv2_api.http_api.id
    name        = "$default"
    auto_deploy = true

    default_route_settings {
      throttling_burst_limit = var.api_throttling_burst_limit
      throttling_rate_limit  = var.api_throttling_rate_limit
    }
    tags = local.common_tags
  }
  ```
  No Lambda handler:
  ```python
  ALLOWED_ORIGIN: str = os.environ.get("ALLOWED_ORIGIN", "*")
  ```
- **Critério de Validação:** Sonda `PROBE-01-CORS-OPTIONS` aprovada e tráfego contido por throttling.

---

### QA-016: Fontes Externas do Google Fonts sem Subresource Integrity (SRI)
- **ID:** `QA-016`
- **Severidade:** LOW / INFORMATIONAL | **Prioridade:** P2
- **CWE:** CWE-353 (Missing Support for Integrity Check)
- **Arquivo Alvo:** [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html)
- **Localização:** Seção `<head>` (linhas 10-13)
- **Cenários de Teste:** Achado `FE-RES-001` em `qa/audit_frontend.py`
- **Causa Raiz:** Importação de folhas de estilo e binários `.woff2` do Google Fonts sem hashes de integridade ou fallback para ambiente air-gapped/offline.
- **Correção Aplicada / Prescrita:**
  Para ambientes com estrita restrição de rede externa, permitir o empacotamento local dos arquivos `.woff2` sob `web/fonts/` com regras `@font-face` em `styles.css` e diretiva `font-src 'self'` no CSP.
- **Critério de Validação:** Ausência de quebra de renderização mesmo quando requisições para `fonts.gstatic.com` forem bloqueadas ou offline.

---

## 4. Matriz de Priorização e Roteiro de Execução

As correções são organizadas por camadas de execução subsequentes no ciclo de hardening:

```
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P0 - BLOQUEADORES CRÍTICOS DE SEGURANÇA (Camada 2 & Camada 3)                        |
+-------------------------------------------------------------------------------------------------+
| QA-001 | Normalização recursiva de casing em IAM JSON (src/auditor.py)                          |
| QA-002 | Identificação e penalização de NotResource sob permissões Allow (src/auditor.py)         |
| QA-003 | Eliminação de falso positivo crítico em regras Deny TLS e IP (src/auditor.py)            |
| QA-004 | Sanitização e validação por whitelist de severidade contra DOM XSS (web/app.js)          |
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P1 - INTEGRIDADE SEMÂNTICA & RESILIÊNCIA OPERACIONAL (Camadas 2 e 3)                 |
+-------------------------------------------------------------------------------------------------+
| QA-005 | Validação mandatória de iam:PassedToService em iam:PassRole (src/auditor.py)             |
| QA-006 | Cobertura da ACL pública 'authenticated-read' na regra TF-002 (src/auditor.py)            |
| QA-007 | Detecção abrangente de wildcards em radicais de verbos IAM (src/auditor.py)              |
| QA-008 | Ativação da meta tag Content-Security-Policy restritiva no HTML (web/index.html)         |
| QA-009 | Timeout defensivo de 15s via AbortController no fetch (web/app.js)                       |
| QA-010 | Teto defensivo de 500 statements e guarda de 512 KB contra DoS/OOM (auditor/handler)    |
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P2 - ROBUSTEZ DE CÓDIGO, ACESSIBILIDADE & UX (Camadas 3 e 4)                         |
+-------------------------------------------------------------------------------------------------+
| QA-011 | Coerção defensiva de tipos na função escapeHtml (web/app.js)                              |
| QA-012 | Substituição de alert() por banner visual acessível inline (web/app.js)                   |
| QA-013 | Validação de response.ok e cabeçalho Content-Type prévia ao parse JSON (web/app.js)      |
| QA-014 | Validação de esquema de protocolo (HTTP/HTTPS) em URL manual (web/app.js)                |
| QA-015 | Parametrização dinâmica de CORS e rate limiting no API Gateway (Terraform / Handler)     |
| QA-016 | Governança de fontes externas e suporte a ativos locais offline (web/index.html)        |
+-------------------------------------------------------------------------------------------------+
```

---

## 5. Critérios de Homologação Final

1. **Zero Evasões e Zero Falsos Positivos:** Os 55 testes da suíte `qa/test_evasion_bypass.py` devem ser aprovados com 100% de sucesso.
2. **Resiliência e Proteção Contra DoS:** Os 48 testes de `qa/test_stress_local.py` devem passar sem exceder o teto de 30 MB de consumo de memória e sem lançar exceções HTTP 500.
3. **Auditoria Estática do Frontend SPA:** O auditor `qa/audit_frontend.py` deve certificar postura `GOOD` com score 100/100.
4. **Preservação de Contrato:** As respostas da API pública em `POST /audit` devem permanecer retrocompatíveis com o schema JSON formalizado.
5. **Zero Vazamento de Informações:** Nenhuma resposta de erro da API pode expor stack traces, caminhos internos de arquivos (`/var/task/`) ou credenciais da AWS.

---
*Plano Técnico de Hardening homologado para o branch `fix/hardening-v1` — Projeto Onion IAM & Terraform Security Auditor.*
