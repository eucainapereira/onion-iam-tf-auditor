# Relatório Técnico de QA & Segurança de Aplicações (QA_REPORT.md)
**Projeto:** Onion IAM & Terraform Security Auditor (`onion-iam-tf-auditor`)  
**Branch de QA:** `qa/stress-audit`  
**Data da Auditoria:** 26 de Novembro de 2026  
**Destinatário:** Time 3 (Refatoração & Hardening)  
**Objetivo:** Contrato técnico de entrada contendo o diagnóstico exaustivo de estresse, evasão semântica, sondas em produção e auditoria estática do frontend para subsidiar a etapa de hardening.

---

## 1. Sumário Executivo

Durante o ciclo de testes da esteira de QA (Camadas 1 a 4 do Onion Flow), o sistema **Onion IAM & Terraform Auditor** foi submetido a baterias rigorosas de testes locais de estresse volumétrico, fuzzing de contrato, evasão semântica de regras, sondas cirúrgicas no ambiente de produção (AWS API Gateway + Lambda + S3) e auditoria estática de código do frontend.

### 1.1. Indicadores Chave de Qualidade & Telemetria

| Métrica | Valor Consolidado | Status / Diagnóstico |
| :--- | :---: | :--- |
| **Total de Cenários de Teste Executados** | **103 cenários** | Cobertura integral das superfícies local e de borda |
| - *Bateria Local 1: Estresse Volumétrico & Fuzzing* | 42 cenários | Payloads de 1 MB a 10 MB, aninhamentos até 2.000 níveis e fuzzing de protocolo |
| - *Bateria Local 2: Evasão Semântica & Regras* | 52 cenários | Wildcards, casing evasion, inversão lógica e falsos positivos |
| - *Bateria de Produção: Sondas Cirúrgicas de Borda* | 9 sondas | API Gateway v2 HTTP API e S3 Static Website Hosting |
| - *Controles Defensivos de Frontend Auditados* | 15 controles | Sanitização, escape HTML, nós DOM e segurança CSS |
| **Taxa de Aprovação de Execução da Suíte** | **100% (103/103)** | Zero falhas de infraestrutura de teste e zero exceções 500 não tratadas |
| **Latência Máxima Registrada (Local)** | **954,63 ms** | Ocorrida no cenário `TC-FUZ-REDOS-COMMENT` (comentário HCL não fechado de 200 KB) |
| **Latência Média em Produção (AWS)** | **~68,3 ms** | Excelente tempo de resposta serverless (Lambda Python 3.12 na us-east-2) |
| **Consumo Máximo de Memória (Local)** | **20,07 MB** | Registrado no payload sintético de 10 MB (`TC-STR-IAM-10MB`) |
| **Vazamentos de Informação em Produção** | **0 ocorrências** | Zero stack traces, paths internos (`/var/task`) ou chaves AWS expostas |
| **Status Operacional da Produção** | **ONLINE / HEALTHY** | API pública e frontend estático 100% disponíveis |
| **Total de Falhas / Vulnerabilidades Mapeadas** | **15 apontamentos** | 3 Críticas, 4 Altas, 3 Médias, 5 Baixas/Informativas |

### 1.2. Veredito Geral de Segurança
- **Motor de Execução e Parsing (`src/handler.py`):** O adaptador da AWS Lambda mostrou alta maturidade no tratamento de requisições malformadas, retornando respostas controladas `HTTP 400 Bad Request` sem nenhum crash ou vazamento de depuração. No entanto, há ausência de limites explícitos de quantidade de statements, criando um risco potencial de esgotamento de memória em payloads densos.
- **Motor de Regras (`src/auditor.py`):** Apresentou fragilidades semânticas críticas decorrentes de acesso estrito a chaves de dicionário sensíveis a maiúsculas/minúsculas, omissão de diretivas como `NotResource`, wildcards verbais intermediários não mapeados e emissão indevida de penalidade crítica (`IAM-008`) contra políticas defensivas com `Effect: Deny`.
- **Frontend SPA (`web/app.js` / `web/index.html`):** Contém boa base de segurança (uso exclusivo de `textContent` para scores e contadores), mas possui vulnerabilidade de **Severidade Alta de Cross-Site Scripting (XSS)** por interpolação não escapada da severidade em `card.innerHTML`, além de ausência de **Content-Security-Policy (CSP)** e timeout no `fetch()`.

---

## 2. Tabela Consolidada de Falhas Encontradas

A tabela a seguir consolida todas as falhas, bypasses, falsos positivos e fragilidades de resiliência identificados ao longo das baterias de QA, organizados por severidade decrescente e numerados sequencialmente de `QA-001` a `QA-015`:

| ID | Severidade | Componente | Tipo de Falha | Resumo do Problema |
| :---: | :---: | :--- | :--- | :--- |
| **`QA-001`** | **CRITICAL** | `src/auditor.py` | Evasão Semântica (Bypass) | **IAM Casing Evasion:** Chaves JSON normativas em minúsculo (`"statement"`, `"action"`, `"resource"`) contornam totalmente a análise, resultando em score 95 (LOW) para políticas 100% abertas. |
| **`QA-002`** | **CRITICAL** | `src/auditor.py` | Evasão Semântica (Bypass) | **Inversão Lógica via `NotResource`:** O motor avalia apenas a chave `Resource`. O uso de `NotResource` com `Effect: Allow` concede acesso a quase toda a conta AWS sem ser detectado por `IAM-002`. |
| **`QA-003`** | **CRITICAL** | `src/auditor.py` | Falso Positivo Crítico | **Penalização Incorreta de Regras Defensivas `Deny`:** `IAM-008` (Wildcard Principal) é disparado antes de verificar `is_allow`, penalizando severamente políticas modelo da AWS (ex: obrigatoriedade de TLS e whitelist de IP). |
| **`QA-004`** | **HIGH** | `web/app.js` | AppSec / DOM XSS | **DOM XSS via Interpolação de Severidade:** A variável `sev` é colocada em `card.innerHTML` sem sanitização ou validação por whitelist; tags como `<IMG SRC=X ONERROR=ALERT(1)>` são interpretadas pelo navegador. |
| **`QA-005`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Bypass em `iam:PassRole` com Condições Irrelevantes:** A validação aceita qualquer condição que contenha `"stringequals"`, contornando `IAM-009` mesmo sem a presença obrigatória de `iam:PassedToService`. |
| **`QA-006`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Bypass de ACL Pública S3 (`authenticated-read`):** Expressão regular de `TF-002` cobre apenas `public-read` e `public-read-write`, ignorando `authenticated-read` (acesso público para qualquer usuário AWS do mundo). |
| **`QA-007`** | **HIGH** | `src/auditor.py` | Evasão Semântica (Bypass) | **Evasão de Wildcard em Radicais de Ações IAM:** O motor só detecta `*` puro ou `:*` ao final. Ações como `"s3:Get*"` e `"s3:Put*"` não são sinalizadas por `IAM-001`. |
| **`QA-008`** | **MEDIUM** | `web/index.html` | AppSec / Defense-in-Depth | **Ausência de Content-Security-Policy (CSP):** O frontend não possui meta tag ou cabeçalho CSP, desprovendo o navegador de Defesa em Profundidade contra exfiltração de dados e injeções de script. |
| **`QA-009`** | **MEDIUM** | `web/app.js` | Resiliência de Rede | **Ausência de Timeout no `fetch()`:** A requisição assíncrona não possui `AbortSignal.timeout()`. Se a API travar ou a rede perder pacotes, a interface permanece desabilitada com spinner infinito. |
| **`QA-010`** | **MEDIUM** | `src/handler.py` | Resiliência / FinOps DoS | **Ausência de Limite Defensivo de Statements:** Falta de teto para número de statements processados. Payloads sintéticos densos (100k statements) alocam >360 MB de memória, excedendo os 128 MB da Lambda. |
| **`QA-011`** | **LOW** | `web/app.js` | Robustez de Frontend | **Ausência de Coerção de Tipo em `escapeHtml`:** A função assume que a entrada é sempre string. Passagem de valores numéricos ou booleanos lança `TypeError: str.replace is not a function`, quebrando a UI. |
| **`QA-012`** | **LOW** | `web/app.js` | UX / Acessibilidade | **Uso de `alert()` Síncrono Bloqueante:** Notificações de erro utilizam `alert()` nativo, congelando a thread principal do navegador e impedindo tratamento assíncrono acessível. |
| **`QA-013`** | **LOW** | `web/app.js` | Resiliência de Rede | **Desserialização JSON Precipitada:** Chamada de `response.json()` antes de testar `response.ok`. Erros de proxies/CDNs em formato HTML resultam em `SyntaxError` confuso para o usuário. |
| **`QA-014`** | **LOW** | `web/app.js` | Validação de Entrada | **Falta de Validação de Protocolo na URL Manual:** O campo manual de URL aceita qualquer texto arbitrário sem checar se o esquema é `https://` via `new URL()`. |
| **`QA-015`** | **LOW / INFO** | `API Gateway / Handler` | Arquitetura / Hardening | **CORS com Wildcard Global (`*`) e Falta de Rate Limiting:** A API expõe `Access-Control-Allow-Origin: *` irrestrito e não define throttling/burst explícito por IP no estágio do API Gateway. |

---

## 3. Detalhamento Técnico das Falhas & Contrato de Correção

Nesta seção, cada falha é descrita com sua localização exata, causa raiz, carga útil mínima necessária para reprodução imediata, discrepância de comportamento e recomendação prescritiva de código para o **Time 3**.

---

### QA-001: IAM Casing Evasion (Sensibilidade a Maiúsculas/Minúsculas em Chaves JSON)
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_iam(content: str)` (linhas 105, 122, 126, 164, 185, 203)
- **Causa Raiz:** O motor utiliza acessos estritos `policy.get("Statement")`, `stmt.get("Action")` e `stmt.get("Resource")` diretamente em dicionários Python nativos. Como o AWS IAM aceita políticas com variações de caixa de chaves ou serializadores JSON alternativos geram chaves minúsculas, os statements deixam de ser extraídos.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"version\": \"2012-10-17\", \"statement\": [{\"effect\": \"allow\", \"action\": \"*\", \"resource\": \"*\"}]}"
}
```
- **Comportamento Atual:** O motor retorna `score: 95`, `risk_level: "LOW"`, com apenas o achado `IAM-006` emitido. A política aberta a todas as ações e recursos da AWS não gera nenhum alerta crítico.
- **Comportamento Esperado:** O motor deve identificar os statements independentemente do case das chaves e emitir `IAM-001`, `IAM-002` e `IAM-005`, resultando em `score: 0` e `risk_level: "CRITICAL"`.
- **Recomendação de Correção (Time 3):**
Implementar uma normalização recursiva das chaves de dicionário logo após o parse JSON em `audit_iam`:
```python
def _normalize_dict_keys(d: Any) -> Any:
    if isinstance(d, dict):
        key_map = {
            "version": "Version", "statement": "Statement", "sid": "Sid",
            "effect": "Effect", "principal": "Principal", "notprincipal": "NotPrincipal",
            "action": "Action", "notaction": "NotAction", "resource": "Resource",
            "notresource": "NotResource", "condition": "Condition"
        }
        return {key_map.get(k.lower(), k): _normalize_dict_keys(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [_normalize_dict_keys(item) for item in d]
    return d

# No início de audit_iam():
policy = _normalize_dict_keys(policy)
```

---

### QA-002: Inversão Lógica via `NotResource` Não Avaliada
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_iam(content: str)` (linhas 203-222)
- **Causa Raiz:** A regra `IAM-002` verifica exclusivamente a presença da chave `Resource` (`if "Resource" in stmt:`). No IAM da AWS, a diretiva `NotResource` combinada com `Effect: Allow` concede acesso a todos os recursos da conta com exceção daqueles listados, constituindo uma permissão universal velada.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"s3:*\", \"NotResource\": \"arn:aws:s3:::backup-vault/*\"}]}"
}
```
- **Comportamento Atual:** Retorna `score: 90`, `risk_level: "LOW"` (apenas `IAM-005` por falta de Condition). O motor ignora a concessão universal sobre o restante dos recursos.
- **Comportamento Esperado:** Emitir achado `IAM-002` (ou nova regra `IAM-010`) com severidade `CRITICAL` e rebaixar o score para nível crítico.
- **Recomendação de Correção (Time 3):**
Adicionar avaliação específica para `NotResource` quando o efeito for `Allow`:
```python
if is_allow and "NotResource" in stmt:
    findings.append(
        _create_finding(
            rule_id="IAM-002",
            title="Uso Perigoso de NotResource com Permissão Allow",
            severity="CRITICAL",
            description=f"O statement{sid_info} define 'NotResource' com efeito 'Allow', concedendo acesso irrestrito a todos os outros recursos da AWS.",
            recommendation="Remova 'NotResource' com efeito Allow. Liste os recursos específicos autorizados no campo 'Resource'."
        )
    )
```

---

### QA-003: Penalização Incorreta de Regras Defensivas `Deny` (Falso Positivo Notável)
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_iam(content: str)` (linhas 126-151)
- **Causa Raiz:** A inspeção de `Principal: "*"` (`IAM-008`) é executada no código **antes** da checagem `if not is_allow: continue` (linha 150). Em políticas defensivas de S3 recomendadas pela AWS (guardrails de TLS ou whitelist de IP), o padrão arquitetural é usar `Effect: Deny` com `Principal: "*"` associado a uma condição restritiva.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"EnforceTLS\", \"Effect\": \"Deny\", \"Principal\": \"*\", \"Action\": \"s3:*\", \"Resource\": \"arn:aws:s3:::meu-bucket/*\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}"
}
```
- **Comportamento Atual:** Retorna `score: 70`, `risk_level: "CRITICAL"`, emitindo `IAM-008` com severidade `CRITICAL`. Uma política recomendada pelo AWS Well-Architected Framework é classificada incorretamente como vulnerável.
- **Comportamento Esperado:** Retorna `score: 100`, `risk_level: "LOW"`, sem achados de segurança contra políticas de negação defensiva.
- **Recomendação de Correção (Time 3):**
Mover a verificação da regra `IAM-008` para após o filtro `if not is_allow: continue`:
```python
# Mover linhas 126-149 para depois da linha 151:
if not is_allow:
    continue

# Rule IAM-008: Wildcard Principal (aplicável somente em Effect: Allow)
principal = stmt.get("Principal")
if principal:
    # ... lógica de verificação de wildcard em principal ...
```

---

### QA-004: DOM XSS via Interpolação de Severidade Não Sanitizada em `innerHTML`
- **Componente / Arquivo:** `web/app.js`
- **Função Afetada:** `renderFindingsList(findings)` (linhas 382-396)
- **Causa Raiz:** O código extrai a severidade com `const sev = (finding.severity || 'LOW').toUpperCase();` e interpola a variável diretamente na template string de `card.innerHTML` (`class="...-${sev}"` e `>${sev}</span>`) sem passar por `escapeHtml()`. Como atributos e tags HTML não diferenciam maiúsculas de minúsculas, uma string injetada contendo tags HTML é executada pelo navegador.
- **Payload Mínimo de Reprodução (Resposta de API injetada ou interceptada):**
```json
{
  "score": 50,
  "risk_level": "HIGH",
  "findings": [
    {
      "id": "SEC-001",
      "severity": "<img src=x onerror=alert(document.domain)>",
      "title": "Vulnerabilidade Simulada",
      "description": "Teste",
      "recommendation": "Teste"
    }
  ]
}
```
- **Comportamento Atual:** O navegador cria o nó `<img src=x onerror=alert(document.domain)>` no DOM e executa o código JavaScript síncrono.
- **Comportamento Esperado:** O valor de `severity` deve ser validado contra uma lista fechada (whitelist) de valores válidos e escapado antes de ser inserido no DOM.
- **Recomendação de Correção (Time 3):**
Em `web/app.js`, implementar validação estrita por lista permitida:
```javascript
const ALLOWED_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const rawSev = String(finding.severity || 'LOW').toUpperCase().trim();
const sev = ALLOWED_SEVERITIES.has(rawSev) ? rawSev : 'LOW';
```

---

### QA-005: Bypass em `iam:PassRole` com Condições Irrelevantes
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_iam(content: str)` (linhas 224-242)
- **Causa Raiz:** A linha 229 valida se a condição é segura usando:
  `if "iam:passedtoservice" in cond_str or "stringequals" in cond_str: condition_valid = True`.
  Isso permite que qualquer política contendo `StringEquals` (mesmo para `aws:username` ou tags arbitrárias) neutralize a regra `IAM-009`, abrindo vetor de escalação de privilégios.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"iam:PassRole\", \"Resource\": \"*\", \"Condition\": {\"StringEquals\": {\"aws:username\": \"operador\"}}}]}"
}
```
- **Comportamento Atual:** A regra `IAM-009` não é emitida. A política é aceita sem a obrigatoriedade da restrição de serviço `iam:PassedToService`.
- **Comportamento Esperado:** Emitir `IAM-009` (Severidade `HIGH`) porque `iam:PassRole` não restringe o serviço destinatário.
- **Recomendação de Correção (Time 3):**
Exigir estritamente a presença da chave `iam:PassedToService`:
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

### QA-006: Bypass Semântico de ACL Pública S3 (`authenticated-read`)
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_terraform(content: str)` (linhas 439, 451)
- **Causa Raiz:** A expressão regular utilizada busca `acl\s*=\s*["\']public-(read|read-write)["\']`. A ACL canônica da AWS `"authenticated-read"` concede permissão de leitura para qualquer entidade autenticada na AWS globalmente, sendo equivalente a um bucket público para fins de segurança corporativa.
- **Payload Mínimo de Reprodução:**
```hcl
resource "aws_s3_bucket" "lake" {
  bucket = "lake-financeiro"
  acl    = "authenticated-read"
}
```
- **Comportamento Atual:** Nenhuma violação `TF-002` é reportada.
- **Comportamento Esperado:** Disparar `TF-002` com severidade `HIGH`.
- **Recomendação de Correção (Time 3):**
Expandir a regex para contemplar `authenticated-read`:
```python
PUBLIC_ACL_REGEX = re.compile(r'acl\s*=\s*["\'](public-(read|read-write)|authenticated-read)["\']', re.IGNORECASE)
if PUBLIC_ACL_REGEX.search(body):
    findings.append(_create_finding(rule_id="TF-002", ...))
```

---

### QA-007: Evasão de Wildcard em Radicais de Ações IAM
- **Componente / Arquivo:** `src/auditor.py`
- **Função Afetada:** `audit_iam(content: str)` (linhas 168-181)
- **Causa Raiz:** A lógica de detecção de wildcard em ações valida apenas `act_clean == "*"` ou `act_clean.endswith(":*")`. Ações com wildcards nos radicais (`"s3:Get*"`, `"s3:Put*"`, `"ec2:Describe*"`) contornam a regra `IAM-001`.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": [\"s3:Get*\", \"s3:Put*\"], \"Resource\": \"arn:aws:s3:::dados/*\"}]}"
}
```
- **Comportamento Atual:** Retorna `score: 90`, `risk_level: "LOW"`, sem alertar sobre wildcards em ações.
- **Comportamento Esperado:** Sinalizar `IAM-001` (Ação com Wildcard) ou criar regra específica para wildcards no radical.
- **Recomendação de Correção (Time 3):**
Verificar se o caractere `*` está presente em qualquer posição da ação:
```python
if "*" in act_clean:
    if act_clean == "*":
        has_global_action_wildcard = True
    else:
        has_service_wildcard = True
```

---

### QA-008: Ausência de Content-Security-Policy (CSP) no Frontend
- **Componente / Arquivo:** `web/index.html`
- **Localização Afetada:** `<head>` (linhas 1-15)
- **Causa Raiz:** O arquivo HTML não define diretivas CSP via `<meta http-equiv="Content-Security-Policy">`. Em caso de DOM Injection, scripts arbitrários podem ser carregados de origens externas ou exfiltrar dados.
- **Comportamento Atual:** Navegador sem política CSP restritiva ativa.
- **Comportamento Esperado:** CSP rígida restringindo scripts a `'self'` e conexões exclusivas à API Gateway da aplicação.
- **Recomendação de Correção (Time 3):**
Inserir no `<head>` de `web/index.html`:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; connect-src 'self' https://*.execute-api.us-east-2.amazonaws.com;">
```

---

### QA-009: Ausência de Timeout no `fetch()` do Frontend
- **Componente / Arquivo:** `web/app.js`
- **Função Afetada:** Listener do botão de auditoria (linha 255)
- **Causa Raiz:** A chamada `fetch(targetUrl, ...)` não associa um sinal de abortamento por tempo (`AbortSignal.timeout(15000)`). Em cenários de lentidão severa ou perda de pacotes, a UI permanece congelada.
- **Comportamento Atual:** Botão permanece permanentemente em `'Analisando Vulnerabilidades...'` sem retorno ao usuário.
- **Comportamento Esperado:** Abortar a chamada após 15 segundos com mensagem de erro clara e restaurar os controles.
- **Recomendação de Correção (Time 3):**
Adicionar `signal: AbortSignal.timeout(15000)` nas opções do `fetch`:
```javascript
const response = await fetch(targetUrl, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ type: currentType, content: content }),
  signal: AbortSignal.timeout(15000)
});
```

---

### QA-010: Ausência de Limite Defensivo de Statements (Risco DoS / OOM na Lambda)
- **Componente / Arquivo:** `src/handler.py` e `src/auditor.py`
- **Causa Raiz:** Ausência de validação quanto ao número máximo de statements processados por requisição. Payloads com mais de 100.000 statements provocam estouro da memória padrão de 128 MB alocada no `terraform/lambda.tf`.
- **Payload Mínimo de Reprodução:**
```json
{
  "type": "iam",
  "content": "{\"Version\": \"2012-10-17\", \"Statement\": [ ... 10.000 blocos ... ]}"
}
```
- **Comportamento Atual:** O interpretador tenta processar todos os blocos até sofrer terminação por `OutOfMemory` na AWS.
- **Comportamento Esperado:** Rejeição limpa com `HTTP 400 Bad Request` indicando que o limite de statements foi excedido.
- **Recomendação de Correção (Time 3):**
Em `src/auditor.py`:
```python
MAX_ALLOWED_STATEMENTS = 500
if len(statements) > MAX_ALLOWED_STATEMENTS:
    raise ValueError(f"O documento excede o limite máximo permitido de {MAX_ALLOWED_STATEMENTS} statements.")
```

---

### QA-011: Ausência de Coerção de Tipo em `escapeHtml`
- **Componente / Arquivo:** `web/app.js`
- **Função Afetada:** `escapeHtml(str)` (linhas 402-410)
- **Causa Raiz:** Execução direta de `str.replace()` assumindo tipo string. Se o backend retornar valores numéricos (`id: 101`), ocorre exceção não capturada.
- **Comportamento Atual:** Dispara `TypeError: str.replace is not a function` e interrompe a renderização.
- **Comportamento Esperado:** Retornar string vazia ou converter defensivamente o valor para string.
- **Recomendação de Correção (Time 3):**
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

### QA-012: Uso de `alert()` Síncrono Bloqueante
- **Componente / Arquivo:** `web/app.js` (linhas 236, 243, 274)
- **Causa Raiz:** Erros de rede e validação são disparados via `alert()`.
- **Comportamento Atual:** Congela a execução do thread JavaScript e a interface até o clique do usuário.
- **Comportamento Esperado:** Feedback visual renderizado inline ou através de banner de erro acessível.
- **Recomendação de Correção (Time 3):**
Substituir as chamadas `alert()` pela exibição de uma mensagem de erro em elemento dedicado na DOM (ex: `apiConfigBanner` ou container de notificações).

---

### QA-013: Desserialização JSON Precipitada sem Validação de `response.ok`
- **Componente / Arquivo:** `web/app.js` (linhas 266-270)
- **Causa Raiz:** O código invoca `const data = await response.json();` antes de testar `response.ok`. Se a infraestrutura intermediária (WAF/CloudFront) retornar uma página 502/504 em HTML, o parser falha com `SyntaxError`.
- **Comportamento Atual:** Exibe mensagem críptica de JSON ao usuário em vez do código HTTP real.
- **Comportamento Esperado:** Inspecionar `response.ok` e o cabeçalho `Content-Type` antes da desserialização.
- **Recomendação de Correção (Time 3):**
```javascript
let data = null;
const contentType = response.headers.get('content-type') || '';
if (contentType.includes('application/json')) {
  data = await response.json();
} else {
  const text = await response.text();
  throw new Error(`Erro HTTP ${response.status}: ${text.slice(0, 100)}`);
}
```

---

### QA-014: Falta de Validação de Protocolo na URL Manual da API
- **Componente / Arquivo:** `web/app.js` (linhas 168-180)
- **Causa Raiz:** O campo de URL aceita qualquer sequência de caracteres sem validação com a API `URL()`.
- **Comportamento Atual:** URLs malformadas ou esquemas arbitrários (`javascript:`, `ftp:`) são salvos e passados ao `fetch`.
- **Comportamento Esperado:** Rejeitar strings que não representem URLs `https://` válidas.
- **Recomendação de Correção (Time 3):**
```javascript
try {
  const parsed = new URL(val);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Apenas URLs HTTP/HTTPS são permitidas.');
  }
} catch (e) {
  // Exibir feedback de URL inválida
  return;
}
```

---

### QA-015: Permissividade Excessiva de Origem CORS (`*`) e Ausência de Rate Limiting
- **Componente / Arquivo:** `src/handler.py` (linha 19) e `terraform/api_gateway.tf`
- **Causa Raiz:** O header `Access-Control-Allow-Origin: *` permite chamadas a partir de qualquer domínio de navegador. Ademais, o estágio do API Gateway v2 não define restrições de burst/taxa de chamadas.
- **Comportamento Atual:** A API aceita preflights e requisições de origens indiscriminadas.
- **Comportamento Esperado:** Em ambiente corporativo fechado, restringir a origem autorizada ao bucket S3/CloudFront e parametrizar o throttling da rota.
- **Recomendação de Correção (Time 3):**
Tornar o header de CORS configurável via variável de ambiente `ALLOWED_ORIGIN` no Lambda e adicionar parâmetros `throttling_burst_limit` e `throttling_rate_limit` no recurso `aws_apigatewayv2_stage.default`.

---

## 4. Matriz de Priorização e Contrato de Entrada para o Time 3

Para guiar a execução dos trabalhos de Refatoração e Hardening do Time 3, as falhas são categorizadas por prioridade de remediação:

```
+-----------------------------------------------------------------------------------------+
| PRIORIDADE P0 - BLOQUEADORES CRÍTICOS DE SEGURANÇA (Hardening Mandatório Imediato)      |
+-----------------------------------------------------------------------------------------+
| QA-001 | Normalização de case de chaves JSON em IAM (src/auditor.py)                   |
| QA-002 | Avaliação e penalização de NotResource com Allow (src/auditor.py)              |
| QA-003 | Eliminação de falso positivo crítico em regras Deny TLS/IP (src/auditor.py)    |
| QA-004 | Sanitização e validação por whitelist de severidade em innerHTML (web/app.js)  |
+-----------------------------------------------------------------------------------------+
| PRIORIDADE P1 - INTEGRIDADE SEMÂNTICA & RESILIÊNCIA OPERACIONAL (Correção Alta/Média)   |
+-----------------------------------------------------------------------------------------+
| QA-005 | Validação estrita de iam:PassedToService em iam:PassRole (src/auditor.py)      |
| QA-006 | Inclusão da ACL S3 'authenticated-read' na regra TF-002 (src/auditor.py)       |
| QA-007 | Detecção de wildcards em radicais verbais de ações IAM (src/auditor.py)         |
| QA-008 | Implementação de Content-Security-Policy restritiva (web/index.html)           |
| QA-009 | Timeout defensivo de 15s via AbortSignal no fetch (web/app.js)                 |
| QA-010 | Teto defensivo de statements contra estouro de memória Lambda (src/handler.py) |
+-----------------------------------------------------------------------------------------+
| PRIORIDADE P2 - ROBUSTEZ DE CÓDIGO, ACESSIBILIDADE & UX (Melhorias de Higiene)          |
+-----------------------------------------------------------------------------------------+
| QA-011 | Coerção de tipo defensiva na função escapeHtml (web/app.js)                    |
| QA-012 | Substituição de alert() por notificações DOM inline acessíveis (web/app.js)     |
| QA-013 | Validação de response.ok e Content-Type antes de parse JSON (web/app.js)       |
| QA-014 | Validação de esquema HTTPS em input de URL da API (web/app.js)                 |
| QA-015 | Parametrização de CORS e configuração de rate limiting (Terraform / Handler)   |
+-----------------------------------------------------------------------------------------+
```

### 4.1. Recursos de Teste de Regressão Disponíveis para o Time 3
O Time 3 dispõe de quatro artefatos de teste já implementados e validados na branch `qa/stress-audit` para validar suas refatorações:

1. **`qa/test_stress_local.py`:** Suíte com 42 testes cobrindo limites de memória, payloads de até 10 MB e fuzzing. Execução direta com:
   ```bash
   python3 -m unittest qa/test_stress_local.py
   ```
2. **`qa/test_evasion_bypass.py`:** Suíte com 52 testes cobrindo todos os cenários de bypass e falsos positivos. Execução direta com:
   ```bash
   python3 -m unittest qa/test_evasion_bypass.py
   ```
3. **`qa/audit_frontend.py`:** Auditor estático de segurança do frontend validando XSS, CSP e resiliência de rede:
   ```bash
   python3 qa/audit_frontend.py
   ```
4. **`qa/probe_production.py`:** Sondas de borda com travas de segurança ativas (máximo de 12 requisições com 1s de intervalo):
   ```bash
   python3 qa/probe_production.py
   ```

### 4.2. Critérios de Aceite para Conclusão do Hardening
- [ ] Todos os 52 testes de `qa/test_evasion_bypass.py` devem passar com **0 bypasses confirmados** e **0 falsos positivos**.
- [ ] O score do frontend auditado por `qa/audit_frontend.py` deve evoluir de **40/100** para **>= 90/100** (`SECURE`).
- [ ] A suíte de testes de estresse `qa/test_stress_local.py` deve manter 100% de aprovação sem regressão de latência ou estouro de memória.
- [ ] Nenhuma alteração pode quebrar o contrato da API pública (`POST /audit`).

---
*Relatório consolidado e homologado pela Esteira de QA (Camada 5) — Branch `qa/stress-audit`.*
