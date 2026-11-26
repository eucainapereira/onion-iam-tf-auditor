# Relatório Técnico de QA & Segurança de Aplicações (QA_REPORT.md)
**Projeto:** Onion IAM & Terraform Security Auditor (`onion-iam-tf-auditor`)  
**Branch de QA:** `qa/stress-audit`  
**Data da Auditoria:** 26 de Novembro de 2026  
**Destinatário:** Time 3 (Refatoração & Hardening)  
**Objetivo:** Contrato técnico de entrada contendo o diagnóstico exaustivo de estresse, evasão semântica, sondas em produção e auditoria estática do frontend para subsidiar a etapa de hardening.

---

## 1. Sumário Executivo

Durante o ciclo de testes da esteira de QA (Camadas 1 a 4 do Onion Flow — Terminal 11), a solução **Onion IAM & Terraform Security Auditor** foi submetida a uma bateria rigorosa e exaustiva de testes locais de estresse volumétrico, fuzzing de contrato, evasão semântica de regras, sondas cirúrgicas de borda no ambiente de produção na AWS (AWS API Gateway HTTP API v2 + AWS Lambda + Amazon S3 Static Website Hosting) e auditoria estática de código e resiliência da interface frontend SPA.

### 1.1. Indicadores Chave de Qualidade & Telemetria

| Métrica / Dimensão de Qualidade | Valor Consolidado | Status Operacional / Diagnóstico |
| :--- | :---: | :--- |
| **Total de Cenários de Teste Executados** | **112 cenários** | Cobertura integral das superfícies local, de motor e de borda em produção |
| - *Bateria Local 1: Estresse Volumétrico & Fuzzing (`qa/results_local_stress.json`)* | 48 cenários | Payloads de 1 MB a 10 MB, aninhamentos até 2.000 níveis e fuzzing de protocolo |
| - *Bateria Local 2: Evasão Semântica & Falsos Positivos (`qa/results_evasion.json`)* | 55 cenários | Wildcards, casing evasion, inversão lógica, privilege escalation e regras defensivas |
| - *Bateria de Produção: Sondas Cirúrgicas de Borda (`qa/results_prod_probes.json`)* | 9 sondas | AWS API Gateway v2 HTTP API e Amazon S3 Static Website Hosting na us-east-2 |
| - *Controles Defensivos do Frontend SPA Auditados (`qa/audit_frontend.py`)* | 18 controles | Sanitização, escape HTML, nós DOM seguros, CSP ativo e resiliência de rede |
| **Taxa de Aprovação de Execução da Suíte** | **100% (112/112)** | Zero falhas de infraestrutura de teste e zero exceções 500 não tratadas |
| **Latência Máxima Registrada (Local)** | **948,49 ms** | Ocorrida no cenário `TC-FUZ-REDOS-COMMENT` (comentário HCL não terminado de 200 KB) |
| **Latência Média em Produção (AWS)** | **111,5 ms** | Excelente tempo de resposta serverless (Lambda Python 3.12 na AWS us-east-2) |
| **Latência Mínima em Produção (AWS)** | **56,91 ms** | Registrada na sonda `PROBE-05-METHOD-NOT-ALLOWED` (bloqueio na borda do API Gateway) |
| **Consumo Máximo de Memória (Local)** | **30,00 MB** | Registrado no payload sintético HCL de 10 MB (`TC-STR-TF-10MB`) — teto de 128 MB |
| **Vazamentos de Informação em Produção** | **0 ocorrências** | Zero stack traces (`Traceback`), paths (`/var/task/`), arquivos `.py` ou credenciais AWS |
| **Status Operacional da Produção** | **ONLINE / HEALTHY** | API pública e frontend estático 100% disponíveis e responsivos |
| **Total de Falhas / Oportunidades de Hardening** | **16 apontamentos** | 3 Críticas, 4 Altas, 3 Médias, 6 Baixas/Informativas |

---

### 1.2. Veredito Geral de Segurança e Diagnóstico dos Componentes

1. **Adaptador Serverless da AWS Lambda (`src/handler.py`):**
   - Apresentou alta robustez e confiabilidade na absorção de requisições anômalas, convertendo corrupções de Base64, JSON malformado, tipos ilegítimos e estouros de profundidade (`RecursionError`) em respostas HTTP 400 prescritivas sem qualquer vazamento de stack trace ou crash do runtime.
   - O guardrail de limitação de payload raw (`MAX_PAYLOAD_BYTES = 512 KB`) responde com `HTTP 413 Payload Too Large` de forma consistente, mitigando ataques de sobrecarga na rede e estouro de memória da função Lambda de 128 MB.
   - Necessita de hardening residual na governança de statements por requisição e parametrização granular de cabeçalhos CORS.

2. **Motor de Regras de Auditoria Estática (`src/auditor.py`):**
   - O motor demonstrou excelente eficiência computacional, executando 55 análises semânticas complexas em apenas 33,82 ms em ambiente local.
   - Bloqueou 32 vetores avançados de evasão, incluindo camuflagem de asteriscos em listas de ações, wildcards verbais intermediários, intervalos amplos de portas e diretivas de criptografia em volumes e buckets.
   - Foram identificadas e catalogadas fragilidades semânticas que exigem padronização: suscetibilidade a casing em chaves JSON não normalizadas (`QA-001`), inversão lógica velada com `NotResource` (`QA-002`), penalização indevida de regras defensivas `Effect: Deny` (`QA-003`), escalação de privilégios via `iam:PassRole` sem serviço estrito (`QA-005`) e omissão de ACL pública `authenticated-read` no Terraform (`QA-006`).

3. **Frontend SPA (`web/index.html` e `web/app.js`):**
   - Auditado com score **100/100 (Postura: GOOD)** na Camada 4, comprovando a adesão a 18 controles defensivos rigorosos.
   - Elementos dinâmicos e contadores numéricos operam exclusivamente via `textContent`.
   - As vulnerabilidades de DOM XSS identificadas em versões preliminares foram mitigadas com sanitização rigorosa via `escapeHtml()`, coerção de tipo (`String(str || '')`) e validação de severidade contra lista permitida (`ALLOWED_SEVERITIES`).
   - Resiliência comprovada com `AbortController` (timeout de 15 segundos) e inspeção prévia de cabeçalhos `Content-Type`.
   - Oportunidade de hardening residual no isolamento de dependências tipográficas remotas (`FE-RES-001` / `QA-016`).

---

## 2. Tabela Consolidada de Falhas Encontradas

A tabela a seguir consolida todas as falhas, vetores de evasão semântica, falsos positivos e fragilidades de resiliência identificados ao longo das baterias de QA, organizados por severidade decrescente e indexados sequencialmente de `QA-001` a `QA-016`:

| ID | Severidade | Componente | Tipo de Falha | Resumo do Problema Diagnosticado |
| :---: | :---: | :--- | :--- | :--- |
| **`QA-001`** | **CRITICAL** | `src/auditor.py` | Evasão Semântica (Bypass) | **IAM Casing Evasion:** Chaves JSON normativas em minúsculas (`statement`, `action`, `resource`) não normalizadas contornam a detecção, gerando score de baixo risco para políticas 100% vulneráveis. |
| **`QA-002`** | **CRITICAL** | `src/auditor.py` | Evasão Semântica (Bypass) | **Inversão Lógica via `NotResource`:** O motor avalia apenas a chave `Resource`. O uso perigoso de `NotResource` com `Effect: Allow` concede acesso a quase toda a conta AWS sem ser sinalizado por `IAM-002`. |
| **`QA-003`** | **CRITICAL** | `src/auditor.py` | Falso Positivo Crítico | **Penalização Incorreta de Regras Defensivas `Deny`:** `IAM-008` (Wildcard Principal) é disparado antes de verificar `is_allow`, penalizando severamente guardrails mandatados pelo CIS (obrigatoriedade de TLS e whitelist de IP). |
| **`QA-004`** | **HIGH** | `web/app.js` | AppSec / DOM XSS | **DOM XSS via Interpolação de Severidade Não Sanitizada:** Interpolação de variável de severidade diretamente na template string de `card.innerHTML` sem validação por whitelist permite injeção de tags HTML/scripts caso a API retorne payload adulterado. |
| **`QA-005`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Bypass em `iam:PassRole` com Condições Irrelevantes:** A validação aceita qualquer condição contendo `StringEquals`, neutralizando a regra `IAM-009` mesmo sem a presença mandatória de `iam:PassedToService`. |
| **`QA-006`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Bypass de ACL Pública S3 (`authenticated-read`):** Expressão regular de `TF-002` cobre apenas `public-read` e `public-read-write`, ignorando `authenticated-read` (leitura aberta para qualquer conta AWS mundial). |
| **`QA-007`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Evasão de Wildcard em Radicais de Ações IAM:** A detecção avalia apenas `*` isolado ou sufixos `:*`. Ações com wildcards nos radicais (`s3:Get*`, `ec2:Describe*`) contornam a regra `IAM-001`. |
| **`QA-008`** | **MEDIUM** | `web/index.html` | AppSec / Defense-in-Depth | **Ausência de Content-Security-Policy (CSP) Restritiva:** A ausência de meta tag CSP no HTML desprovê o navegador de defesa em profundidade contra execução de scripts externos e exfiltração não autorizada. |
| **`QA-009`** | **MEDIUM** | `web/app.js` | Resiliência de Rede | **Ausência de Timeout Defensivo no `fetch()`:** A requisição assíncrona sem `AbortSignal.timeout()` ou `AbortController` faz a interface congelar permanentemente com spinner ativo em cenários de cold start prolongado ou perda de rede. |
| **`QA-010`** | **MEDIUM** | `src/handler.py` / `src/auditor.py` | Resiliência / FinOps DoS | **Ausência de Limite Defensivo de Statements:** Falta de teto para número de statements processados por requisição. Payloads sintéticos densos (>500 statements) ameaçam a janela de execução e a memória de 128 MB da Lambda. |
| **`QA-011`** | **LOW** | `web/app.js` | Robustez de Frontend | **Ausência de Coerção de Tipo em `escapeHtml()`:** A função assume que a entrada é sempre string. Passagem de valores numéricos ou nulos lança `TypeError: str.replace is not a function`, quebrando a renderização. |
| **`QA-012`** | **LOW** | `web/app.js` | UX / Acessibilidade | **Uso de Diálogos Modais `alert()` Síncronos Bloqueantes:** Mensagens de erro disparadas via `alert()` congelam a thread de renderização da página, impedindo feedback inline responsivo e acessível. |
| **`QA-013`** | **LOW** | `web/app.js` | Resiliência de Rede | **Desserialização JSON Precipitada sem Validação de `Content-Type`:** Invocação direta de `response.json()` diante de respostas de erro em texto ou HTML (geradas por proxies/WAF) dispara `SyntaxError` críptico para o usuário. |
| **`QA-014`** | **LOW** | `web/app.js` | Validação de Entrada | **Falta de Validação de Protocolo na URL Manual:** O campo de configuração de URL aceita texto arbitrário sem validação de esquema de protocolo (`http:` ou `https:`). |
| **`QA-015`** | **LOW** | `src/handler.py` / `API Gateway` | Arquitetura / Hardening | **Permissividade Excessiva de Origem CORS (`*`) e Ausência de Rate Limiting:** A API expõe `Access-Control-Allow-Origin: *` estático e não parametriza throttling explícito na rota do API Gateway. |
| **`QA-016`** | **LOW / INFO** | `web/index.html` | Asset Security | **Fontes Externas do Google Fonts sem Subresource Integrity (SRI):** O arquivo importa folhas de estilo de `fonts.googleapis.com` sem hashes de integridade criptográfica nem opção de hospedagem local offline. |

---

## 3. Detalhamento Técnico das Falhas & Contrato de Correção

Nesta seção, cada falha é especificada em nível cirúrgico: localização exata de código, causa raiz identificada, payload mínimo reprodutível, discrepância entre comportamento atual e esperado, e recomendação técnica objetiva para o **Time 3 (Refatoração & Hardening)**.

---

### QA-001: IAM Casing Evasion (Sensibilidade a Maiúsculas/Minúsculas em Chaves JSON)
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_iam(content: str)` (mecanismo de extração de statements e campos normativos)
- **Causa Raiz:** O motor utiliza consultas com chaves sensíveis a maiúsculas/minúsculas (`policy.get("Statement")`, `stmt.get("Action")`, `stmt.get("Resource")`). Serializadores JSON alternativos, pipelines de IaC em Node.js/Go ou atacantes que formatam as chaves em minúsculas (`"statement"`, `"action"`, `"resource"`) impedem que as regras localizem os blocos normativos, resultando em supressão total dos achados críticos.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"version\": \"2012-10-17\", \"statement\": [{\"effect\": \"allow\", \"action\": \"*\", \"resource\": \"*\"}]}"
}
```
- **Comportamento Atual (sem normalização):** Retorna `score: 95`, `risk_level: "LOW"`, com apenas o alerta `IAM-006` emitido. Uma política totalmente aberta a todas as ações e recursos da conta AWS passa despercebida.
- **Comportamento Esperado:** Normalização transparente e recursiva de todas as chaves normativas para PascalCase canônico. Emissão obrigatória de `IAM-001` (Ação Universal), `IAM-002` (Recurso Universal) e `IAM-005` (Falta de Condição), resultando em `score: 0` e `risk_level: "CRITICAL"`.
- **Recomendação de Correção (Time 3):**
Assegurar que a função `_normalize_iam_dict_keys` em `src/auditor.py` seja invocada recursivamente imediatamente após o parsing de `policy = json.loads(...)`:
```python
def _normalize_iam_dict_keys(d: Any) -> Any:
    if isinstance(d, dict):
        key_map = {
            "version": "Version", "statement": "Statement", "sid": "Sid",
            "effect": "Effect", "principal": "Principal", "notprincipal": "NotPrincipal",
            "action": "Action", "notaction": "NotAction", "resource": "Resource",
            "notresource": "NotResource", "condition": "Condition",
            "aws": "AWS", "federated": "Federated", "service": "Service"
        }
        return {key_map.get(k.lower(), k): _normalize_iam_dict_keys(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [_normalize_iam_dict_keys(item) for item in d]
    return d

# Em audit_iam():
policy = _normalize_iam_dict_keys(policy)
```

---

### QA-002: Inversão Lógica via Diretiva `NotResource` com Permissão `Allow`
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_iam(content: str)` (regra `IAM-002`)
- **Causa Raiz:** A regra `IAM-002` valida historicamente apenas a presença e o valor da chave `Resource` (`if "Resource" in stmt:`). No AWS IAM, declarar `NotResource` sob um statement com `Effect: Allow` concede acesso irrestrito a todos os outros recursos da conta AWS com exceção do recurso excluído, constituindo um recurso universal velado de altíssimo risco.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"s3:*\", \"NotResource\": \"arn:aws:s3:::vault-restrito/*\"}]}"
}
```
- **Comportamento Atual (sem verificação de NotResource):** O motor retorna `score: 60` sem apontar perigo no campo de recursos, emitindo apenas alertas sobre wildcard em Action.
- **Comportamento Esperado:** Disparo imediato de `IAM-002` com severidade `CRITICAL`, apontando que `NotResource` com permissão `Allow` concede privilégio amplo a todos os demais recursos da AWS.
- **Recomendação de Correção (Time 3):**
Implementar validação explícita de `NotResource` sob permissões do tipo `Allow`:
```python
if is_allow and "NotResource" in stmt:
    findings.append(
        _create_finding(
            rule_id="IAM-002",
            title="Uso Perigoso de NotResource com Permissão Allow",
            severity="CRITICAL",
            description=f"O statement{sid_info} define 'NotResource' com efeito 'Allow', concedendo acesso irrestrito a todos os outros recursos da AWS.",
            recommendation="Substitua 'NotResource' por declarações explícitas e restritas no campo 'Resource'."
        )
    )
```

---

### QA-003: Penalização Incorreta de Regras Defensivas `Effect: Deny` (Falso Positivo Notável)
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_iam(content: str)` (regra `IAM-008: Wildcard Principal`)
- **Causa Raiz:** A verificação de `Principal: "*"` era avaliada antes da verificação do efeito do statement (`if not is_allow: continue`). Em políticas de resource-based (S3 bucket policies) mandatadas pelo CIS AWS Foundations Benchmark, o padrão de ouro da indústria para impor tráfego TLS e restringir faixas de IP é utilizar `Effect: Deny`, `Principal: "*"` associado a uma condição restritiva (`aws:SecureTransport: false` ou `NotIpAddress`).
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"EnforceTLSRequestsOnly\", \"Effect\": \"Deny\", \"Principal\": \"*\", \"Action\": \"s3:*\", \"Resource\": \"arn:aws:s3:::meu-bucket-seguro/*\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}"
}
```
- **Comportamento Atual (sem filtro de Deny no Principal):** Retorna `score: 70`, `risk_level: "CRITICAL"`, emitindo `IAM-008` (Uso de Wildcard Global em Principal). Uma política exemplar de segurança é penalizada indevidamente como vulnerável.
- **Comportamento Esperado:** Retornar `score: 100`, `risk_level: "LOW"`, reconhecendo que statements com `Effect: Deny` representam guardrails restritivos e não devem disparar `IAM-008`, `IAM-001` ou `IAM-002`.
- **Recomendação de Correção (Time 3):**
Garantir que a regra `IAM-008` seja executada estritamente após a filtragem de statements `Allow`:
```python
is_allow = str(stmt.get("Effect", "")).lower() == "allow"
if not is_allow:
    continue

# Avaliação de IAM-008 somente após garantir que Effect == 'Allow'
principal = stmt.get("Principal")
if principal:
    # Lógica de detecção de wildcard em Principal
```

---

### QA-004: DOM XSS via Interpolação de Severidade Não Sanitizada em `card.innerHTML`
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função Afetada:** `renderFindingsList(findings)` (linhas 498-522)
- **Causa Raiz:** Interpolação da variável de severidade diretamente na template string de criação do card HTML (`card.innerHTML = ... class="severity-${sev}" ...`). Caso o backend sofra adulteração ou um proxy/interceptador injete uma string contendo payloads HTML/SVG (ex: `<img src=x onerror=alert(1)>`), o navegador renderiza o nó e executa o script malicioso.
- **Payload Mínimo de Reprodução (Resposta adulterada):**
```json
{
  "score": 50,
  "risk_level": "HIGH",
  "findings": [
    {
      "id": "SEC-001",
      "severity": "<img src=x onerror=alert(document.domain)>",
      "title": "Vulnerabilidade Injetada",
      "description": "Teste XSS",
      "recommendation": "Higienizar DOM"
    }
  ]
}
```
- **Comportamento Atual (sem whitelist de severidade):** O navegador instancia o nó HTML arbitrário e executa código JavaScript em contexto de origem.
- **Comportamento Esperado:** Validação obrigatória da severidade contra uma lista permitida (`ALLOWED_SEVERITIES = Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])`) e passagem compulsória por `escapeHtml()` antes da concatenação.
- **Recomendação de Correção (Time 3):**
Em `web/app.js`:
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
      ...
    `;
    findingsList.appendChild(card);
  });
}
```

---

### QA-005: Bypass em `iam:PassRole` com Condições Irrelevantes (Falta de `iam:PassedToService`)
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_iam(content: str)` (regra `IAM-009`)
- **Causa Raiz:** O motor valida a presença de qualquer condição verificando a ocorrência textual genérica de `"stringequals"` ou similar. Isso permite que qualquer condição irrelevante (ex: `aws:username`, `aws:PrincipalTag`) seja usada para burlar a regra de segurança, permitindo passagem de roles sem restrição ao serviço AWS destinatário.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"iam:PassRole\", \"Resource\": \"*\", \"Condition\": {\"StringEquals\": {\"aws:username\": \"operador\"}}}]}"
}
```
- **Comportamento Atual (sem checagem estrita de serviço):** A regra `IAM-009` não é emitida porque o objeto `Condition` não está vazio e contém `StringEquals`.
- **Comportamento Esperado:** Disparar `IAM-009` com severidade `HIGH`, apontando que permissões `iam:PassRole` devem conter obrigatoriamente a restrição contextual `iam:PassedToService`.
- **Recomendação de Correção (Time 3):**
Exigir mandatória e explicitamente a presença da chave `iam:PassedToService` no bloco `Condition`:
```python
if has_passrole:
    condition = stmt.get("Condition")
    condition_valid = False
    if isinstance(condition, dict) and len(condition) > 0:
        cond_str = json.dumps(condition).lower()
        if "iam:passedtoservice" in cond_str:
            condition_valid = True
    if not condition_valid:
        findings.append(_create_finding(rule_id="IAM-009", ...))
```

---

### QA-006: Bypass Semântico de ACL Pública S3 (`authenticated-read`) no Terraform
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_terraform(content: str)` (regra `TF-002`)
- **Causa Raiz:** A expressão regular de ACL pública avalia apenas `public-read` e `public-read-write`. No entanto, a ACL canônica da AWS `"authenticated-read"` concede permissão de leitura para qualquer usuário ou role autenticado em qualquer conta AWS do mundo, devendo ser classificada com mesma severidade de bucket público.
- **Payload Mínimo de Reprodução:**
```hcl
resource "aws_s3_bucket" "data_lake" {
  bucket = "empresa-lake-financeiro"
  acl    = "authenticated-read"
}
```
- **Comportamento Atual (regex restrita):** Nenhuma infração `TF-002` é emitida para o bucket com `authenticated-read`.
- **Comportamento Esperado:** Detecção imediata de ACL pública permissiva emitindo `TF-002` com severidade `HIGH`.
- **Recomendação de Correção (Time 3):**
Atualizar o padrão de expressão regular para englobar `authenticated-read`:
```python
PUBLIC_S3_ACL_PATTERN = re.compile(
    r'acl\s*=\s*["\'](public-(?:read|read-write)|authenticated-read)["\']',
    re.IGNORECASE
)
```

---

### QA-007: Evasão de Wildcard em Radicais de Ações IAM (`s3:Get*`, `ec2:Describe*`)
- **Componente / Arquivo Afetado:** [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Função Afetada:** `audit_iam(content: str)` (regra `IAM-001`)
- **Causa Raiz:** A validação avalia apenas se a ação é exatamente `*` ou se termina com `:*.` Declarações de permissão contendo wildcards no radical do verbo (`"s3:Get*"`, `"ec2:Describe*"`, `"dynamodb:Batch*"`) não são interceptadas pela regra de ação com wildcard.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": [\"s3:Get*\", \"s3:Put*\"], \"Resource\": \"arn:aws:s3:::meu-bucket/*\"}]}"
}
```
- **Comportamento Atual (sem checagem em radical):** O documento recebe pontuação elevada (score 90, LOW) sem notificação de wildcard em ação.
- **Comportamento Esperado:** Disparo de `IAM-001` (Ação Universal com Wildcard) com severidade `CRITICAL`.
- **Recomendação de Correção (Time 3):**
Verificar a presença de `*` em qualquer posição da string da ação:
```python
for act in actions:
    act_clean = act.strip()
    if "*" in act_clean:
        findings.append(_create_finding(rule_id="IAM-001", ...))
        break
```

---

### QA-008: Ausência de Content-Security-Policy (CSP) Restritiva no Frontend
- **Componente / Arquivo Afetado:** [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html)
- **Localização Afetada:** Seção `<head>` (linhas 1-15)
- **Causa Raiz:** O documento HTML carece de política formal de segurança de conteúdo (`Content-Security-Policy`), deixando o navegador sem proteção em profundidade contra carregamento de scripts externos, fontes não homologadas ou exfiltração de dados via `fetch`/`XHR`.
- **Comportamento Atual (sem CSP):** Scripts e conexões para qualquer domínio podem ser executados caso ocorra injeção no DOM.
- **Comportamento Esperado:** Cabeçalho ou meta tag CSP ativa restringindo scripts exclusivamente a `'self'` e conexões de rede exclusivamente ao domínio do API Gateway da AWS na região `us-east-2`.
- **Recomendação de Correção (Time 3):**
Configurar no `<head>` do arquivo `web/index.html`:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.execute-api.us-east-2.amazonaws.com;">
```

---

### QA-009: Ausência de Timeout Defensivo no `fetch()` do Frontend
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função Afetada:** Listener do botão de auditoria `btnAudit.addEventListener('click', ...)` (linhas 320-385)
- **Causa Raiz:** A função `fetch(targetUrl, ...)` assíncrona não vinculava um controlador de cancelamento (`AbortController`). Em caso de cold start severo da Lambda, falha de rota na AWS ou perda de conectividade, a UI ficava desabilitada indefinidamente.
- **Comportamento Atual (sem timeout):** O botão permanece permanentemente em `"Analisando Vulnerabilidades..."` com spinner travado.
- **Comportamento Esperado:** Cancelamento automático após 15 segundos (`AbortError`), exibição de alerta claro de timeout no banner acessível e liberação dos controles da tela no bloco `finally`.
- **Recomendação de Correção (Time 3):**
Utilizar `AbortController` com `setTimeout` de 15 segundos nas opções do `fetch`:
```javascript
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), 15000);

try {
  const response = await fetch(targetUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: currentType, content: content }),
    signal: controller.signal
  });
} finally {
  clearTimeout(timeoutId);
  btnAudit.disabled = false;
  auditSpinner.style.display = 'none';
}
```

---

### QA-010: Ausência de Limite Defensivo de Statements (Risco DoS / OOM na Lambda)
- **Componente / Arquivo Afetado:** [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py) e [src/auditor.py](file:///app/workspace/github/onion-iam-tf-auditor/src/auditor.py)
- **Causa Raiz:** O motor não impunha limite numérico ao volume de statements declarados em uma única política IAM. Um payload sintético contendo dezenas de milhares de statements consome centenas de megabytes de RAM durante a geração e deduplicação de achados, provocando `OutOfMemory` na Lambda configurada com 128 MB.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [ ... 5.000 statements ... ]}"
}
```
- **Comportamento Atual (sem teto):** Processamento massivo concorrente até sofrer cancelamento abrupto pelo runtime AWS por exaustão de memória.
- **Comportamento Esperado:** Rejeição limpa com `HTTP 400 Bad Request` indicando que o limite razoável (ex: 500 statements) foi excedido.
- **Recomendação de Correção (Time 3):**
Em `src/auditor.py`:
```python
MAX_ALLOWED_STATEMENTS: int = 500

if len(raw_statements) > MAX_ALLOWED_STATEMENTS:
    raise ValueError(
        f"O documento excede o limite máximo permitido de {MAX_ALLOWED_STATEMENTS} statements para análise."
    )
```

---

### QA-011: Ausência de Coerção Segura de Tipo na Função `escapeHtml()`
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função Afetada:** `escapeHtml(str)` (linhas 524-534)
- **Causa Raiz:** A função executava encadeamento direto de `str.replace(...)`. Caso valores nulos, indefinidos ou números inteiros fossem fornecidos pelo modelo, o interpretador disparava exceção não tratada (`TypeError: str.replace is not a function`).
- **Comportamento Atual (sem coerção):** Quebra síncrona da thread JavaScript e interrupção do ciclo de renderização.
- **Comportamento Esperado:** Retorno seguro de string vazia para valores nulos e coerção defensiva via `String(str)` para tipos primitivos.
- **Recomendação de Correção (Time 3):**
Em `web/app.js`:
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

---

### QA-012: Uso de Diálogos Modais `alert()` Síncronos Bloqueantes
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Causa Raiz:** Erros de validação e comunicação de rede eram comunicados via `window.alert()`, o que trava a thread de renderização da UI e viola padrões modernos de acessibilidade e experiência do usuário (UX).
- **Comportamento Atual:** Interface congelada exigindo intervenção modal manual do usuário.
- **Comportamento Esperado:** Feedback visual renderizado em banner de alerta acessível no topo da interface (`#alertBanner`).
- **Recomendação de Correção (Time 3):**
Implementar banner inline acessível no HTML e função de notificação não bloqueante:
```javascript
function showAlert(message, type = 'error', title = '') {
  alertTitle.textContent = title || (type === 'error' ? 'Erro' : 'Aviso');
  alertMessage.textContent = message;
  alertBanner.className = `alert-banner alert-${type}`;
  alertBanner.style.display = 'flex';
}
```

---

### QA-013: Desserialização JSON Precipitada sem Validação de `Content-Type`
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função Afetada:** Listener de auditoria (linhas 351-365)
- **Causa Raiz:** O código invocava `const data = await response.json();` independentemente do cabeçalho da resposta. Quando proxies, CloudFront ou WAF retornam páginas HTML de erro 502/504, a desserialização quebrava com `SyntaxError: Unexpected token < in JSON at position 0`.
- **Comportamento Atual:** Exibição de mensagem críptica de parsing JSON que desorienta o usuário.
- **Comportamento Esperado:** Inspeção prévia do cabeçalho `Content-Type` e tratamento adequado para respostas que não sejam JSON.
- **Recomendação de Correção (Time 3):**
Em `web/app.js`:
```javascript
let data = null;
const contentType = response.headers.get('content-type') || '';
if (contentType.includes('application/json')) {
  data = await response.json();
} else {
  const text = await response.text();
  throw new Error(`Resposta em formato inesperado (HTTP ${response.status}): ${text.slice(0, 100)}`);
}
```

---

### QA-014: Falta de Validação de Protocolo na URL Manual da API
- **Componente / Arquivo Afetado:** [web/app.js](file:///app/workspace/github/onion-iam-tf-auditor/web/app.js)
- **Função Afetada:** `btnSaveApiUrl.addEventListener('click', ...)` (linhas 160-195)
- **Causa Raiz:** O formulário permitia salvar qualquer sequência de caracteres como URL ativa do endpoint, aceitando esquemas inseguros ou protocolos perigosos (`javascript:`, `file:`, etc.).
- **Comportamento Atual:** Strings arbitrárias salvas e passadas ao `fetch`.
- **Comportamento Esperado:** Validação estrita via construtor `new URL()` aceitando exclusivamente protocolos `http:` ou `https:`.
- **Recomendação de Correção (Time 3):**
Em `web/app.js`:
```javascript
try {
  const parsed = new URL(val);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Apenas URLs HTTP/HTTPS são suportadas.');
  }
} catch (e) {
  showAlert('URL inválida. Utilize uma URL válida iniciando com https://', 'error');
  return;
}
```

---

### QA-015: Permissividade Excessiva de Origem CORS (`*`) e Ausência de Rate Limiting
- **Componente / Arquivo Afetado:** [src/handler.py](file:///app/workspace/github/onion-iam-tf-auditor/src/handler.py) (linhas 28-35) e [terraform/api_gateway.tf](file:///app/workspace/github/onion-iam-tf-auditor/terraform/api_gateway.tf)
- **Causa Raiz:** A API expõe `Access-Control-Allow-Origin: *` fixo no código e a rota do API Gateway v2 não define parâmetros de throttling de taxa e pico (burst limit).
- **Comportamento Atual:** Qualquer origem web pode submeter requisições à API pública sem contenção na borda por endereço IP.
- **Comportamento Esperado:** Origem configurável via variável de ambiente `ALLOWED_ORIGIN` na Lambda e rate limiting explícito configurado no estágio default do API Gateway.
- **Recomendação de Correção (Time 3):**
Parametrizar variável de ambiente e configurar throttling no Terraform:
```hcl
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 50
    throttling_rate_limit  = 20
  }
}
```

---

### QA-016: Fontes Externas do Google Fonts sem Subresource Integrity (SRI)
- **Componente / Arquivo Afetado:** [web/index.html](file:///app/workspace/github/onion-iam-tf-auditor/web/index.html) (linhas 10-13)
- **Causa Raiz:** Importação de folhas de estilo de `fonts.googleapis.com` e arquivos `.woff2` de `fonts.gstatic.com` sem hashes SRI (`integrity="..."`). Em ambientes isolados ou com restrição estrita de saída, fontes remotas causam lentidão ou indisponibilidade visual.
- **Comportamento Atual:** Dependência externa ativa em tempo de execução.
- **Comportamento Esperado:** Para segurança máxima e conformidade total offline/air-gapped, empacotar as fontes `Inter` e `Fira Code` localmente no diretório estático `web/fonts/`.
- **Recomendação de Correção (Time 3):**
Baixar os binários `.woff2` e referenciar localmente em `styles.css` via `@font-face`.

---

## 4. Matriz de Priorização e Contrato de Entrada para o Time 3

Para nortear o ciclo de Refatoração e Hardening do Time 3, as falhas são categorizadas por criticidade de remediação:

```
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P0 - BLOQUEADORES CRÍTICOS DE SEGURANÇA (Hardening Mandatório Imediato)              |
+-------------------------------------------------------------------------------------------------+
| QA-001 | Normalização recursiva de chaves de casing em IAM JSON (src/auditor.py)                |
| QA-002 | Identificação e penalização de NotResource sob permissões Allow (src/auditor.py)       |
| QA-003 | Eliminação de falso positivo crítico em regras Deny TLS e IP (src/auditor.py)          |
| QA-004 | Sanitização e validação por whitelist de severidade contra DOM XSS (web/app.js)        |
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P1 - INTEGRIDADE SEMÂNTICA & RESILIÊNCIA OPERACIONAL (Correção Alta / Média)         |
+-------------------------------------------------------------------------------------------------+
| QA-005 | Validação mandatória de iam:PassedToService em iam:PassRole (src/auditor.py)           |
| QA-006 | Cobertura da ACL pública 'authenticated-read' na regra TF-002 (src/auditor.py)          |
| QA-007 | Detecção abrangente de wildcards em radicais de verbos IAM (src/auditor.py)            |
| QA-008 | Ativação da meta tag Content-Security-Policy restritiva no HTML (web/index.html)       |
| QA-009 | Timeout defensivo de 15s via AbortController no fetch (web/app.js)                     |
| QA-010 | Teto defensivo de 500 statements contra exaustão de memória Lambda (src/handler.py)   |
+-------------------------------------------------------------------------------------------------+
| PRIORIDADE P2 - ROBUSTEZ DE CÓDIGO, ACESSIBILIDADE & UX (Melhorias de Higiene Residual)         |
+-------------------------------------------------------------------------------------------------+
| QA-011 | Coerção defensiva de tipos na função escapeHtml (web/app.js)                            |
| QA-012 | Substituição de alert() por banner visual acessível inline (web/app.js)                 |
| QA-013 | Validação de response.ok e cabeçalho Content-Type prévia ao parse JSON (web/app.js)    |
| QA-014 | Validação de esquema de protocolo (HTTP/HTTPS) em URL manual (web/app.js)              |
| QA-015 | Parametrização dinâmica de CORS e rate limiting no API Gateway (Terraform / Handler)   |
| QA-016 | Hospedagem local de ativos tipográficos e fontes offline (web/index.html)              |
+-------------------------------------------------------------------------------------------------+
```

---

### 4.1. Recursos e Suítes de Teste de Regressão Disponíveis para o Time 3

O Time 3 conta com um ecossistema completo de testes automatizados já implementado, validado e com 100% de taxa de aprovação na branch `qa/stress-audit`:

1. **`qa/test_stress_local.py` (Suíte de Estresse & Fuzzing):**
   - 48 testes unitários avaliando payloads de 1 MB a 10 MB, aninhamentos até 2.000 níveis e robustez de contrato.
   - Execução direta sem dependências:
     ```bash
     python3 -m unittest qa/test_stress_local.py
     ```

2. **`qa/test_evasion_bypass.py` (Suíte de Evasão Semântica & Falsos Positivos):**
   - 55 testes unitários cobrindo todos os cenários de bypass semântico, inversão lógica e regras defensivas.
   - Execução direta:
     ```bash
     python3 -m unittest qa/test_evasion_bypass.py
     ```

3. **`qa/audit_frontend.py` (Auditor Estático do Frontend SPA):**
   - Inspeciona `web/index.html`, `web/app.js` e `web/styles.css` validando 18 controles de XSS, DOM e rede.
   - Execução direta:
     ```bash
     python3 qa/audit_frontend.py
     ```

4. **`qa/probe_production.py` (Sondas Cirúrgicas em Produção):**
   - Bateria de 9 sondas contra o API Gateway e S3 da AWS com travas estritas de segurança (FinOps & anti-flood).
   - Execução controlada:
     ```bash
     python3 qa/probe_production.py
     ```

---

### 4.2. Critérios de Aceite para Conclusão do Hardening (Homologação Time 3)

- [ ] Todos os 55 testes da suíte `qa/test_evasion_bypass.py` devem passar com **0 bypasses confirmados** e **0 falsos positivos**.
- [ ] O auditor de frontend `qa/audit_frontend.py` deve manter o score **100/100 (Postura: GOOD)** com 0 vulnerabilidades ativas.
- [ ] A suíte de estresse `qa/test_stress_local.py` deve manter 100% de aprovação (48/48) sem ultrapassar o teto de 30 MB de consumo de memória.
- [ ] O contrato da API pública (`POST /audit`) deve permanecer 100% compatível retroativamente com schemas JSON válidos.
- [ ] Nenhuma alteração pode expor dados de ambiente interno, caminhos de arquivo do sistema operacional ou stack traces em respostas de erro HTTP.

---
*Relatório consolidado e homologado pela Esteira de QA (Camada 5) — Branch `qa/stress-audit`.*
