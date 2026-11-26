# Release Notes — Onion Auditor v1.0.0

**Projeto:** Onion IAM & Terraform Security Auditor (`onion-iam-tf-auditor`)  
**Versão Oficial de Release:** `v1.0.0`  
**Data de Publicação:** 26 de Novembro de 2026  
**Ambiente:** AWS Cloud (`us-east-2`) — Produção Homologada & Estabilizada  
**Status do Ciclo:** 100% Aprovado em Produção — Zero Vulnerabilidades Remanescentes  

---

## 📌 Sumário
1. [Visão Geral & Destaques da Release](#1-visão-geral--destaques-da-release)
2. [Ciclo 1: Arquitetura Serverless & Menor Privilégio](#2-ciclo-1-arquitetura-serverless--menor-privilégio)
3. [Ciclo 2: Diagnóstico de QA, Estresse & Evasão Semântica](#3-ciclo-2-diagnóstico-de-qa-estresse--evasão-semântica)
4. [Ciclo 3: Correções de Hardening AppSec, Regressão & Resiliência](#4-ciclo-3-correções-de-hardening-appsec-regressão--resiliência)
5. [Ciclo 4: Validação em Produção & Re-teste Pós-Hardening](#5-ciclo-4-validação-em-produção--re-teste-pós-hardening)
6. [Métricas de Desempenho e Latência em Produção](#6-métricas-de-desempenho-e-latência-em-produção)
7. [Catálogo Oficial de Regras de Auditoria (v1.0.0)](#7-catálogo-oficial-de-regras-de-auditoria-v100)
8. [Matriz de Resolução de Apontamentos de QA (QA-001 a QA-015)](#8-matriz-de-resolução-de-apontamentos-de-qa-qa-001-a-qa-015)
9. [Guia de Operação e Verificação da Release](#9-guia-de-operação-e-verificação-da-release)

---

## 1. Visão Geral & Destaques da Release

A versão **`v1.0.0`** consolida o ciclo de engenharia autônoma do **Onion Auditor**, um auditor visual de segurança para políticas AWS IAM e manifestos de Infraestrutura como Código Terraform (HCL). A solução foi projetada sob os mais altos padrões de DevSecOps, AppSec e FinOps (Scale-to-Zero), garantindo auditoria estática instantânea, pontuação de risco automatizada e conformidade estrita com o princípio de menor privilégio (*Least Privilege*).

### Destaques Principais:
- **Arquitetura 100% Serverless & Scale-to-Zero:** Custo zero em ociosidade na AWS (S3 Website + API Gateway HTTP API v2 + AWS Lambda).
- **Zero Dependências Externas (Pure Stdlib):** Runtime Python 3.12 utilizando apenas a biblioteca padrão, eliminando riscos de supply chain e alcançando inicialização sub-50ms.
- **Proteções de Hardening Ativas:** Limite estrito de 512 KB por requisição, proteção anti-recursão contra DoS, blindagem anti-evasão sintática/semântica e sanitização defensiva anti-XSS no frontend.
- **Homologação Completa em Produção:** 100% de aprovação nos testes em produção diretamente contra a infraestrutura ativa na AWS (`us-east-2`), com latência média de ~64.6 ms e zero vazamento de informações internas.

---

## 2. Ciclo 1: Arquitetura Serverless & Menor Privilégio

O **Ciclo 1** estabeleceu o alicerce arquitetural e a infraestrutura como código (IaC) do projeto, parametrizada para custo mínimo, alta escalabilidade e segurança por padrão.

### Componentes Arquiteturais:
- **Frontend SPA Estático:** Interface web desenvolvida em HTML5, CSS3 moderno e Vanilla JavaScript, hospedada em bucket Amazon S3 configurado com Static Website Hosting (`onion-auditor-frontend-*`).
- **Ponto de Entrada REST (API Gateway HTTP API v2):** Rota única e otimizada `POST /audit` com integração `AWS_PROXY` e suporte nativo a CORS (`OPTIONS`, `POST`), oferecendo latência inferior e custo até 70% menor em relação a APIs REST tradicionais.
- **Motor de Auditoria (AWS Lambda):** Função `onion-auditor-engine` executada em runtime Python 3.12. Construída sem pacotes externos (`pip`), eliminando camadas (*layers*) e mitigando vulnerabilidades em pacotes de terceiros.
- **Observabilidade Otimizada:** Grupo de logs Amazon CloudWatch (`/aws/lambda/onion-auditor-engine`) com retenção fixa de 7 dias, eliminando custos de retenção prolongada desnecessária.
- **Menor Privilégio IAM (Least Privilege):** Perfil de execução restrito exclusivamente à criação e publicação de streams no CloudWatch Logs (`AWSLambdaBasicExecutionRole`), sem permissões amplas ou desnecessárias na conta AWS.

### Contrato de Dados & Regras Fundamentais:
- Contrato padronizado de requisição (`type`: `"iam"` | `"terraform"`, `content`: string).
- Resposta estruturada com `score` (0-100), `risk_level` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) e lista de `findings` detalhando identificador, título, severidade, descrição e recomendação corretiva.

---

## 3. Ciclo 2: Diagnóstico de QA, Estresse & Evasão Semântica

No **Ciclo 2** (executado na branch `qa/stress-audit`), uma equipe especializada de QA e Red Team conduziu uma bateria abrangente de testes adversariais locais e sondas controladas em produção para identificar vulnerabilidades, limites de exaustão e fragilidades semânticas nos parsers:

### Frentes de Testes Adversariais:
1. **Bateria de Estresse Local e Fuzzing (`qa/test_stress_local.py`):**
   - Payloads gigantescos (de 1 MB a 10 MB) para forçar esgotamento de memória (OOM).
   - Explosão de statements JSON (mais de 500 statements em uma única política).
   - Aninhamento recursivo profundo (estruturas com até 2.000 níveis) para induzir estouro de pilha (*stack overflow*) no runtime Python.
   - Payloads com alta complexidade de regex para testar ataques de ReDoS (*Regular Expression Denial of Service*).
2. **Bateria de Evasão Semântica (`qa/test_evasion_bypass.py`):**
   - Evasão de casing em chaves IAM: uso de minúsculas (`statement`, `action`, `resource`) ou casing misto para contornar checagens baseadas em PascalCase.
   - Inversão lógica via `NotResource`: concessão de `Effect: Allow` com `NotResource`, concedendo privilégios universais velados.
   - Wildcards em listas de ações (`["s3:GetObject", "*"]`) e em radicais de verbos (`s3:Get*`, `ec2:Describe*`).
   - Evasão de regras de Security Group em Terraform: abertura para a internet (`0.0.0.0/0`) usando intervalos amplos (`from_port = 0, to_port = 65535`) em vez de portas exatas (22, 3389).
   - Uso de ACLs semi-públicas do Amazon S3 (`authenticated-read`) que concedem acesso de leitura para qualquer conta AWS no mundo.
3. **Auditoria Estática de Segurança no Frontend (`qa/audit_frontend.py`):**
   - Ausência de cabeçalho ou meta tag `Content-Security-Policy` (CSP).
   - Risco de XSS caso parâmetros de severidade ou textos de achados não fossem rigorosamente tratados antes da injeção no DOM.
   - Ausência de controle de timeout nas chamadas `fetch()`, permitindo congelamento indefinido da interface em falhas de rede.
   - Uso de chamadas síncronas bloqueantes `alert()`.
4. **Relatório Gerado:** Consolidação formal no documento `QA_REPORT.md` contendo 15 vulnerabilidades catalogadas (`QA-001` a `QA-015`).

---

## 4. Ciclo 3: Correções de Hardening AppSec, Regressão & Resiliência

No **Ciclo 3** (executado na branch `fix/hardening-v1`), foi implementado um pacote completo de remediações de AppSec cobrindo 100% das 15 vulnerabilidades documentadas:

### 4.1. Blindagem do Handler Serverless (`src/app.py` / `src/handler.py`):
- **Teto Rígido de Payload (512 KB):** Implementada checagem prévia `len(body) > 524288`, retornando imediatamente `HTTP 413 Payload Too Large` e impedindo consumo abusivo de memória.
- **Prevenção contra Recursão Profunda:** Trava de profundidade máxima de 20 níveis em estruturas aninhadas (`MAX_JSON_DEPTH = 20`), eliminando vetores de DoS por estouro de pilha no Python 3.12.
- **Limite de Statements IAM:** Teto de no máximo 500 statements por política (`MAX_ALLOWED_STATEMENTS = 500`), retornando `HTTP 400 Bad Request` antes do parsing iterativo.
- **Sanitização de Exceções & Fuga de Informações:** Captura de exceções genéricas sanitizada, retornando mensagens limpas sem stack traces, linhas de código fonte ou caminhos internos (`/var/task/`).

### 4.2. Fortalecimento dos Motores de Auditoria (`src/auditor.py`):
- **Normalização Recursiva de Casing (`QA-001`):** Função `_normalize_iam_dict_keys` converte dinamicamente variantes minúsculas e mistas para a especificação canônica PascalCase da AWS.
- **Detecção de Inversão Lógica `NotResource` (`QA-002`):** Regra `IAM-002` aprimorada para capturar `NotResource` com `Effect: Allow`, emitindo penalidade `CRITICAL`.
- **Eliminação de Falsos Positivos em Regras `Deny` Defensivas (`QA-003`):** Guardrails recomendados pela AWS (ex: rejeição de conexões sem TLS via `Deny`) são ignorados pelas regras restritivas a `Allow`, preservando o score 100 (LOW).
- **Validação Estrita de `iam:PassRole` (`QA-005`):** Exigência obrigatória de restrição `iam:PassedToService` no bloco `Condition`, bloqueando vetores de escalação de privilégios.
- **Detecção de ACL Semi-Pública S3 (`QA-006`):** Expressão regular `PUBLIC_S3_ACL_PATTERN` expandida para incluir a ACL `authenticated-read` em recursos inline e separados.
- **Captura de Wildcards em Radicais IAM (`QA-007`):** Regex e parsing atualizados para interceptar curingas `*` em prefixos, sufixos ou radicais de verbos IAM (`IAM-001`).
- **Detecção de Portas Sensíveis em Faixas de SG (`TF-001`):** Algoritmo de intersecção de intervalos numéricos para validar se faixas amplas (ex: 0-65535) expõem portas administrativas (22, 3389, 5432, 3306).

### 4.3. Hardening do Frontend SPA (`web/app.js` e `web/index.html`):
- **Diretiva CSP Restritiva (`QA-008`):** Adicionada meta tag `Content-Security-Policy` no `<head>` de `index.html`, restringindo origens autorizadas para scripts, estilos e conexões.
- **Whitelist Estrita de Severidades (`QA-004`):** O frontend rejeita quaisquer tokens fora de `['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']`, prevenindo injeções de classes CSS ou seletores arbitrários.
- **Coerção de Tipo Segura em `escapeHtml` (`QA-011`):** Tratamento robusto para valores nulos/indefinidos e conversão obrigatória para `String` antes da substituição de entidades HTML (`&`, `<`, `>`, `"`, `'`, `/`).
- **Cancelamento de Timeout com `AbortController` (`QA-009`):** Temporizador defensivo de 15 segundos (`15.000 ms`) para abortar chamadas HTTP pendentes e restaurar a UI.
- **Descongelamento de UI sem `alert()` (`QA-012`):** Erradicação de diálogos síncronos, substituídos por banner acessível no DOM (`role="alert"`).
- **Validação Segura de Protocolo e Desserialização (`QA-013`, `QA-014`):** Validação estrita de URLs com o construtor `new URL()` (esquemas `http:` e `https:`) e verificação de `Content-Type: application/json` antes de chamar `.json()`.

### 4.4. Infraestrutura Defensiva & Suíte de Regressão:
- **Throttling e Burst no API Gateway (`QA-015`):** Configurado `throttling_rate_limit = 50` req/s e `throttling_burst_limit = 100` reqs no estágio `$default` do HTTP API v2.
- **Suíte Oficial de Regressão 1-para-1 (`src/test_hardening_regression.py`):** 15 testes dedicados cobrindo cada apontamento de QA, atingindo 100% de aprovação (56 testes no backend, 94 testes nas baterias de QA e 18 controles de frontend = 168 verificações com zero falhas).
- **Relatório e Merge:** Formalização do documento `HARDENING_REPORT.md`, merge para a branch `main` (`f01d0aa`) e reconciliação idempotente de estado Terraform (`284bdcb`).

---

## 5. Ciclo 4: Validação em Produção & Re-teste Pós-Hardening

No **Ciclo 4** (Camada 3), a release candidate `v1.0.0` foi submetida à homologação oficial diretamente contra a infraestrutura em produção na AWS (`us-east-2`).

### 5.1. Mecanismo do Validador de Release (`qa/verify_release_v1.py`):
- Desenvolvido exclusivamente com bibliotecas padrão do Python 3 (`urllib.request`, `json`, `time`, `re`, `pathlib`).
- **Trava de Orçamento HTTP Rígida:** Limite máximo de 15 requisições HTTP (`MAX_ALLOWED_HTTP_REQUESTS = 15`) com interrupção imediata por exceção em caso de estouro.
- **Intervalo Defensivo:** Delay de 1,0 segundo entre chamadas sucessivas para garantir estabilidade operacional e evitar alarmes de saturação.
- **Verificador Ativo de Fuga de Dados:** Varredura em cada payload de resposta contra strings sensíveis (`Traceback`, `File "*.py"`, `/var/task/`, chaves e segredos AWS).

### 5.2. Resultados dos Cenários de Teste em Produção:

| ID | Cenário Homologado em Produção | Método / Alvo | Status HTTP | Latência (ms) | Parecer Técnico |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **V1-01** | **Preflight CORS OPTIONS /audit** | `OPTIONS` / API Gateway | `204` | 59.52 ms | **APROVADO** — Headers RFC válidos (`Origin: *`, `Methods: OPTIONS,POST`). |
| **V1-02** | **Auditoria IAM Legítima** | `POST` / API Gateway | `200` | 90.58 ms | **APROVADO** — Score `100` (LOW), zero achados de segurança, conformidade de schema. |
| **V1-03** | **Auditoria Terraform Legítima** | `POST` / API Gateway | `200` | 58.54 ms | **APROVADO** — Score `100` (LOW), zero achados de segurança, HCL seguro processado. |
| **V1-04** | **Detecção de Evasão IAM (Wildcard em Lista)** | `POST` / API Gateway | `200` | 59.76 ms | **APROVADO** — Disparou `IAM-001` (`CRITICAL`), Score `45`, mitigando evasão `["s3:GetObject", "*"]`. |
| **V1-05** | **Detecção de Evasão TF (SG Faixa 0-65535)** | `POST` / API Gateway | `200` | 61.86 ms | **APROVADO** — Disparou `TF-001` (`CRITICAL`), Score `65`, portas 22, 3389, 5432, 3306 identificadas. |
| **V1-06** | **Teto de Payload (>512 KB)** | `POST` / API Gateway | `413` | 113.69 ms | **APROVADO** — Payload de ~600 KB rejeitado limpo com HTTP 413 (`Payload Too Large`), sem crash. |
| **V1-07** | **JSON Malformado no Corpo** | `POST` / API Gateway | `400` | 61.86 ms | **APROVADO** — Erro controlado com HTTP 400 sem stack trace nem caminhos `/var/task`. |
| **V1-08** | **Disponibilidade do Frontend S3** | `GET` / S3 Static Web | `200` | 31.57 ms | **APROVADO** — HTML integro (9.272 bytes), assets `app.js` e `config.js` referenciados corretamente. |
| **V1-09** | **Controle Anti-XSS no Frontend** | `GET` / `app.js` (S3) | `200` | 44.17 ms | **APROVADO** — Função `escapeHtml` com coerção defensiva e escape de entidades confirmado. |

- **Requisições Utilizadas:** 9 de 15 permitidas (60% do orçamento consumido).
- **Taxa de Sucesso em Produção:** 100,0% (9 de 9 testes aprovados).
- **Vazamentos Detectados:** Zero vazamentos.
- **Arquivo de Evidência Gerado:** `qa/results_release_v1.json` (Commit `37cc4bf`).

---

## 6. Métricas de Desempenho e Latência em Produção

O comportamento de tempo de resposta da infraestrutura em produção na região `us-east-2` foi medido durante a execução da suíte de release:

```
+--------------------------------------------------------------------------------+
| Distribuição de Latência das Requisições em Produção (AWS us-east-2)           |
+--------------------------------------------------------------------------------+
| V1-08 (Frontend S3 HTML)             | 31.57 ms                                |
| V1-09 (Frontend S3 app.js)           | 44.17 ms                                |
| V1-03 (Auditoria Terraform HCL)      | 58.54 ms                                |
| V1-01 (Preflight CORS OPTIONS)       | 59.52 ms                                |
| V1-04 (Evasão IAM Wildcard)          | 59.76 ms                                |
| V1-05 (Evasão TF Security Group)     | 61.86 ms                                |
| V1-07 (Erro 400 JSON Malformado)     | 61.86 ms                                |
| V1-02 (Auditoria IAM Legítima)       | 90.58 ms                                |
| V1-06 (Rejeição 413 Payload >512 KB) | 113.69 ms                               |
+--------------------------------------------------------------------------------+
```

- **Latência Mínima:** 31.57 ms (S3 Static Website Hosting)
- **Latência Máxima:** 113.69 ms (Validação e rejeição de payload grande no API Gateway / Lambda)
- **Latência Média Global:** ~64.62 ms
- **Latência Média do Backend API Gateway + Lambda:** ~72.26 ms
- **Consistência de Resposta:** Todas as requisições normais de auditoria completadas em menos de 100 ms.

---

## 7. Catálogo Oficial de Regras de Auditoria (v1.0.0)

### 7.1. Regras para Políticas AWS IAM:

| ID Regra | Severidade | Penalidade | Título | Descrição Resumida |
| :---: | :---: | :---: | :--- | :--- |
| **`IAM-001`** | `CRITICAL` | -40 pts | Ação Universal com Wildcard | Permissão de ação `*` ou radicais como `s3:Get*` em statement com `Effect: Allow`. |
| **`IAM-002`** | `CRITICAL` | -30 pts | Recurso Universal com Wildcard | Statement com `Resource: "*"` ou uso perigoso de `NotResource` com `Effect: Allow`. |
| **`IAM-003`** | `CRITICAL` | -35 pts | Administração Total de IAM | Concessões amplas de `iam:*` com recursos universais, abrindo risco de privilégio de root. |
| **`IAM-004`** | `HIGH` | -20 pts | Operações Destrutivas Sem Restrição | Ações de exclusão/deleção de infraestrutura (`*:Delete*`, `*:Drop*`) sem condições. |
| **`IAM-005`** | `MEDIUM` | -10 pts | Statement Allow sem Condição | Ausência de restrições contextuais (`Condition`) em statements permissivos. |
| **`IAM-006`** | `HIGH` | -20 pts | Acesso Amplo a Dados em Repositórios | Permissões genéricas de leitura de dados (`s3:*`, `dynamodb:*`) em toda a conta. |
| **`IAM-007`** | `MEDIUM` | -10 pts | Permissões de Decodificação / KMS | Ações de uso de chaves criptográficas (`kms:Decrypt`) sem amarração de recursos. |
| **`IAM-008`** | `CRITICAL` | -35 pts | Principal Aberto / Wildcard | Uso de `Principal: "*"` em políticas baseadas em recursos (Trust Policies) com `Allow`. |
| **`IAM-009`** | `HIGH` | -25 pts | `iam:PassRole` sem Condição de Serviço | Permissão `iam:PassRole` sem a cláusula estrita `iam:PassedToService`. |
| **`IAM-010`** | `MEDIUM` | -10 pts | Modificação de Políticas IAM | Ações permissivas de alteração de políticas (`iam:AttachRolePolicy`, `iam:PutUserPolicy`). |

### 7.2. Regras para Terraform HCL:

| ID Regra | Severidade | Penalidade | Título | Descrição Resumida |
| :---: | :---: | :---: | :--- | :--- |
| **`TF-001`** | `CRITICAL` | -35 pts | Security Group com Porta Sensível Aberta | Exposição de portas de gerência (22, 3389, 5432, 3306) para `0.0.0.0/0` (inclusive faixas amplas). |
| **`TF-002`** | `HIGH` | -25 pts | Bucket S3 com ACL Pública | Uso de ACLs públicas ou semi-públicas (`public-read`, `authenticated-read`, etc.). |
| **`TF-003`** | `HIGH` | -20 pts | Bucket S3 sem Encriptação Ativa | Ausência do bloco `server_side_encryption_configuration` com AES256 ou KMS. |
| **`TF-004`** | `HIGH` | -20 pts | Volume EBS sem Encriptação | Definição de `aws_ebs_volume` com `encrypted = false` ou bloco de encriptação ausente. |
| **`TF-005`** | `CRITICAL` | -30 pts | Security Group Aberto para Toda a Internet | Regras de entrada com `0.0.0.0/0` cobrindo todas as portas (`from_port = 0, to_port = 0`). |
| **`TF-006`** | `HIGH` | -20 pts | Instância de Banco RDS sem Encriptação | Instância `aws_db_instance` configurada com `storage_encrypted = false`. |

---

## 8. Matriz de Resolução de Apontamentos de QA (QA-001 a QA-015)

Todos os apontamentos originados no Ciclo de QA foram corrigidos e auditados 1-para-1:

| ID QA | Severidade | Componente | Descrição da Remediação | Teste Automatizado | Status |
| :---: | :---: | :--- | :--- | :--- | :---: |
| **`QA-001`** | **CRITICAL** | `src/auditor.py` | Normalização recursiva de chaves de dicionário para PascalCase (`Statement`, `Action`, `Resource`). | `test_qa_001_iam_casing_evasion_*` | **RESOLVIDO** |
| **`QA-002`** | **CRITICAL** | `src/auditor.py` | Inspeção e penalização de `NotResource` em statements com `Effect: Allow` (`IAM-002`). | `test_qa_002_notresource_logical_inversion_with_allow` | **RESOLVIDO** |
| **`QA-003`** | **CRITICAL** | `src/auditor.py` | Supressão de falso positivo em guardrails defensivos com `Effect: Deny` (TLS e IP). | `test_qa_003_defensive_deny_rules_no_false_positive_iam008` | **RESOLVIDO** |
| **`QA-004`** | **HIGH** | `web/app.js` | Whitelist estrita de severidades (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) e escape no DOM. | `test_qa_004_frontend_anti_xss_severity_whitelist` | **RESOLVIDO** |
| **`QA-005`** | **HIGH** | `src/auditor.py` | Exigência da chave de condição `iam:PassedToService` para `iam:PassRole`. | `test_qa_005_passrole_condition_strict_enforcement` | **RESOLVIDO** |
| **`QA-006`** | **HIGH** | `src/auditor.py` | Cobertura da ACL `authenticated-read` na regex de buckets públicos S3 (`TF-002`). | `test_qa_006_s3_authenticated_read_acl_detection` | **RESOLVIDO** |
| **`QA-007`** | **HIGH** | `src/auditor.py` | Captura de caracteres curinga `*` em radicais verbais de ações (`s3:Get*`). | `test_qa_007_iam_wildcard_in_action_radicals` | **RESOLVIDO** |
| **`QA-008`** | **MEDIUM** | `web/index.html` | Meta tag `Content-Security-Policy` restritiva no cabeçalho do documento HTML. | `test_qa_008_frontend_content_security_policy_configured` | **RESOLVIDO** |
| **`QA-009`** | **MEDIUM** | `web/app.js` | Implementação de `AbortController` com temporizador defensivo de 15 segundos. | `test_qa_009_frontend_fetch_timeout_control` | **RESOLVIDO** |
| **`QA-010`** | **MEDIUM** | `src/auditor.py` | Teto de 500 statements por política para contenção de DoS de memória. | `test_qa_010_statement_explosion_rejection` | **RESOLVIDO** |
| **`QA-011`** | **LOW** | `web/app.js` | Coerção defensiva `String(str)` e tratamento de nulo em `escapeHtml()`. | `test_qa_011_frontend_escape_html_defensive_type_coercion` | **RESOLVIDO** |
| **`QA-012`** | **LOW** | `web/app.js` | Substituição de `alert()` síncrono por banner DOM acessível (`role="alert"`). | `test_qa_012_frontend_no_synchronous_blocking_alert` | **RESOLVIDO** |
| **`QA-013`** | **LOW** | `web/app.js` | Checagem de cabeçalho `Content-Type: application/json` antes do parse JSON. | `test_qa_013_frontend_safe_json_deserialization` | **RESOLVIDO** |
| **`QA-014`** | **LOW** | `web/app.js` | Validação estrita de protocolo de API URL utilizando o construtor `new URL()`. | `test_qa_014_frontend_api_url_protocol_validation` | **RESOLVIDO** |
| **`QA-015`** | **LOW / INFO** | `terraform/` | Throttling defensivo no API Gateway (rate: 50, burst: 100) e CORS parametrizado. | `test_qa_015_cors_and_rate_limiting_infrastructure` | **RESOLVIDO** |

---

## 9. Guia de Operação e Verificação da Release

### 9.1. URLs da Aplicação em Produção:
- **Frontend SPA (S3 Website):**  
  [http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com](http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com)
- **API Gateway Endpoint (Rota POST /audit):**  
  `https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit`

### 9.2. Como Executar a Verificação Automatizada da Release:
Para re-executar a homologação contra os endpoints em produção a qualquer momento:
```bash
python3 qa/verify_release_v1.py
```
O script consumirá no máximo 9 requisições HTTP (abaixo do teto de 15) e atualizará `qa/results_release_v1.json`.

### 9.3. Como Executar as Suítes de Testes Unitários e Regressão Localmente:
```bash
# 1. Suíte unitária do backend e regressão 1-para-1 (56 testes)
python3 -m unittest discover -s src -v

# 2. Baterias de evasão semântica e estresse local (94 testes)
python3 -m unittest qa/test_stress_local.py qa/test_evasion_bypass.py -v

# 3. Auditoria estática de controles de frontend (18 verificações)
python3 qa/audit_frontend.py
```

---

## 10. Conclusão & Próximos Passos

A versão **`v1.0.0`** representa a conclusão com sucesso do ciclo de desenvolvimento autônomo do Onion Auditor. A aplicação encontra-se em produção, plenamente funcional, estabilizada, protegida contra evasões e ataques adversariais, e em total conformidade com os princípios de segurança, menor privilégio e eficiência FinOps.
