# 🧅 Onion Auditor — Plano Estratégico de Testes QA, Estresse, Evasão e Borda

[![QA & AppSec Engineering](https://img.shields.io/badge/QA%20%26%20AppSec-Security%20Testing-red)](README.md)
[![Branch: qa/stress-audit](https://img.shields.io/badge/Branch-qa%2Fstress--audit-blueviolet)](https://github.com/eucainapereira/onion-iam-tf-auditor/tree/qa/stress-audit)
[![Python 3.12](https://img.shields.io/badge/Python-3.12%20Stdlib-blue?logo=python)](https://www.python.org/)
[![Target: Zero Vulnerabilities](https://img.shields.io/badge/Target-Zero%20Vulnerabilities-brightgreen)](README.md)

---

## 📌 Sumário
- [1. Visão Geral e Objetivos do Plano de QA & AppSec](#1-visão-geral-e-objetivos-do-plano-de-qa--appsec)
- [2. Mapeamento da Superfície de Ataque e Infraestrutura](#2-mapeamento-da-superfície-de-ataque-e-infraestrutura)
  - [2.1. Endpoints Públicos de Produção (AWS)](#21-endpoints-públicos-de-produção-aws)
  - [2.2. Contrato de API (HTTP API v2 + AWS Lambda)](#22-contrato-de-api-http-api-v2--aws-lambda)
  - [2.3. Matriz de Severidade e Cálculo de Score](#23-matriz-de-severidade-e-cálculo-de-score)
  - [2.4. Catálogo Canônico de Regras de Auditoria (IAM & Terraform)](#24-catálogo-canônico-de-regras-de-auditoria-iam--terraform)
- [3. Plano de Testes de Estresse & Resiliência Operacional (Stress & Load Testing)](#3-plano-de-testes-de-estresse--resiliência-operacional-stress--load-testing)
  - [3.1. Volumetria de Dados e Limites de Payload (512 KB)](#31-volumetria-de-dados-e-limites-de-payload-512-kb)
  - [3.2. Carga Sintética de Statements e Recursos (DoS Prevention)](#32-carga-sintética-de-statements-e-recursos-dos-prevention)
  - [3.3. Profundidade de Aninhamento JSON (Anti-Recursion DoS)](#33-profundidade-de-aninhamento-json-anti-recursion-dos)
  - [3.4. Avaliação de ReDoS (Regex Denial of Service)](#34-avaliação-de-redos-regex-denial-of-service)
  - [3.5. Limites Operacionais de Memória e Timeout (FinOps Scale-to-Zero)](#35-limites-operacionais-de-memória-e-timeout-finops-scale-to-zero)
- [4. Plano de Testes de Evasão & Bypasses de Análise Estática](#4-plano-de-testes-de-evasão--bypasses-de-análise-estática)
  - [4.1. Evasões Semânticas em Políticas IAM](#41-evasões-semânticas-em-políticas-iam)
  - [4.2. Evasões em Regras Terraform HCL (Regex vs Sintaxe Real)](#42-evasões-em-regras-terraform-hcl-regex-vs-sintaxe-real)
  - [4.3. Bypasses de Portas, Faixas Contíguas e Notação CIDR/IPv6](#43-bypasses-de-portas-faixas-contíguas-e-notação-cidripv6)
  - [4.4. Mitigação e Supressão de Falsos Positivos](#44-mitigação-e-supressão-de-falsos-positivos)
- [5. Sondas de Borda da API & Protocolo (Edge Probing)](#5-sondas-de-borda-da-api--protocolo-edge-probing)
  - [5.1. Fuzzing de Métodos HTTP e Cabeçalhos](#51-fuzzing-de-métodos-http-e-cabeçalhos)
  - [5.2. Manipulação de Base64 e Codificação de Caracteres](#52-manipulação-de-base64-e-codificação-de-caracteres)
  - [5.3. Validação de Políticas de CORS e Preflight](#53-validação-de-políticas-de-cors-e-preflight)
  - [5.4. Sanitização Anti-XSS e Content Security Policy (CSP) do Frontend](#54-sanitização-anti-xss-e-content-security-policy-csp-do-frontend)
- [6. Matriz de Cenários de Teste Executáveis](#6-matriz-de-cenários-de-teste-executáveis)
- [7. Diretrizes de Execução e Automação](#7-diretrizes-de-execução-e-automação)

---

## 1. Visão Geral e Objetivos do Plano de QA & AppSec

O presente documento formaliza a estratégia e o plano executivo de **Garantia de Qualidade (QA)** e **Segurança de Aplicações (AppSec)** para o projeto **Onion Auditor**.

### Objetivos Primários:
1. **Conformidade Estrita com o Contrato Arquitetural:** Garantir que o endpoint Serverless (`POST /audit`), o motor de auditoria (`src/auditor.py`, `src/handler.py`) e a SPA estática (`web/`) operem em perfeita sintonia com as especificações da arquitetura.
2. **Resiliência Extrema contra DoS & Estresse:** Submeter a função AWS Lambda (Python 3.12, 128 MB, timeout 10s) a cargas anômalas, payloads gigantescos e estruturas altamente aninhadas, prevenindo *Out-Of-Memory* (OOM), saturação de tempo de execução e travamentos de CPU.
3. **Imunidade contra Evasões Semânticas:** Mapear e testar vetores avançados de bypass de regras IAM e Terraform HCL (case variations, inversões lógicas com `NotAction`/`NotResource`, ofuscação de portas e manipulação de CIDRs).
4. **Proteção da Superfície de Borda e Defesa em Profundidade:** Validar a blindagem contra chamadas maliciosas de protocolo, injeção de parâmetros, corrupção de Base64, brechas de CORS e vetores de Cross-Site Scripting (XSS) no frontend.

> [!IMPORTANT]
> **Regra Crítica de Isolamento:** Todas as atividades, experimentos, scripts de teste de carga e sondas de borda são mantidos **estritamente na branch isolada `qa/stress-audit`**. É expressamente proibido fazer alterações ou commits diretos na branch `main` ou acionar pipelines produtivos (`.github/workflows/deploy.yml`).

---

## 2. Mapeamento da Superfície de Ataque e Infraestrutura

### 2.1. Endpoints Públicos de Produção (AWS)

Com base nas saídas oficiais declaradas em `terraform/outputs.tf` e na documentação arquitetural em `README.md`, os seguintes ativos públicos encontram-se mapeados e operacionais na AWS:

| Ativo | Tipo de Recurso AWS | URL Pública / Identificador | Observações de Segurança |
| :--- | :--- | :--- | :--- |
| **API Backend** | AWS API Gateway HTTP API (v2) | `https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit` | Rota única `POST /audit`, CORS ativo, Throttling defensivo |
| **Frontend SPA** | AWS S3 Static Website Hosting | `http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com` | Hospedagem estática pura, CSP ativo, sem frameworks |
| **Bucket S3** | Amazon S3 Storage | `onion-auditor-frontend-654341980060-us-east-2` | PublicRead apenas para assets estáticos, BucketOwnerEnforced |
| **Motor Lambda**| AWS Lambda (Python 3.12) | `onion-auditor-engine` | 128 MB RAM, 10s timeout, Graviton2/x86_64, zero dependências |
| **Telemetria** | Amazon CloudWatch Logs | `/aws/lambda/onion-auditor-engine` | Retenção de 7 dias, logging estruturado sem vazamento de traces |

---

### 2.2. Contrato de API (HTTP API v2 + AWS Lambda)

#### 2.2.1. Rota Principal: `POST /audit`
- **Método HTTP:** `POST`
- **Cabeçalhos Requeridos:**
  - `Content-Type: application/json`
- **CORS:**
  - `Access-Control-Allow-Origin: *` (ou configurado via variável `ALLOWED_ORIGIN`)
  - `Access-Control-Allow-Methods: POST, OPTIONS`
  - `Access-Control-Allow-Headers: Content-Type, Authorization`
  - `Access-Control-Max-Age: 300`

#### 2.2.2. Contrato de Entrada (Request JSON):
```json
{
  "type": "iam" | "terraform",
  "content": "<string não vazia contendo política IAM ou código HCL>"
}
```

*Critérios de Validação:*
- `type`: obrigatório, string estrita (`"iam"` ou `"terraform"`, insensível a maiúsculas/espaços nas pontas).
- `content`: obrigatório, string não nula e não vazia (após strip).
- `tamanho máximo`: `512 KB` (524.288 bytes). Payloads maiores são rejeitados imediatamente com HTTP 413.

#### 2.2.3. Contrato de Saída de Sucesso (HTTP 200 OK):
```json
{
  "score": 40,
  "risk_level": "CRITICAL",
  "findings": [
    {
      "id": "IAM-001",
      "title": "Ação Universal com Wildcard",
      "severity": "CRITICAL",
      "description": "O statement permite a ação wildcard (*), concedendo controle irrestrito a serviços AWS.",
      "recommendation": "Restrinja o campo Action estritamente para as operações necessárias (ex: s3:GetObject, ec2:DescribeInstances)."
    }
  ]
}
```

#### 2.2.4. Respostas de Erro Padronizadas:
- **HTTP 400 Bad Request:**
  ```json
  { "error": "<mensagem prescritiva de validação>" }
  ```
  *(Ocorre em: JSON inválido, campos ausentes, tipos incorretos, recursão excessiva > 20/800 níveis, mais de 500 statements em IAM, ou Base64 inválido).*
- **HTTP 413 Payload Too Large:**
  ```json
  { "error": "Corpo da requisição excede o limite máximo permitido de 512 KB." }
  ```
- **HTTP 500 Internal Server Error:**
  ```json
  { "error": "Erro interno do servidor durante o processamento da requisição." }
  ```
  *(Resposta defensiva opaca; jamais deve expor stack trace, caminhos `/var/task/` ou versões de pacotes).*

---

### 2.3. Matriz de Severidade e Cálculo de Score

O score de segurança é calculado dinamicamente pelo motor (`calculate_score_and_risk`), partindo de **100 pontos** com penalidades cumulativas por achado:

| Severidade | Dedução por Ocorrência | Impacto e Regra de Enquadramento |
| :--- | :---: | :--- |
| **`CRITICAL`** | **-30** pontos | Força `risk_level = CRITICAL` mesmo que o score resultante seja $\ge 40$. |
| **`HIGH`** | **-15** pontos | Redução severa da pontuação. |
| **`MEDIUM`** | **-10** pontos | Redução moderada de boas práticas. |
| **`LOW`** | **-5** pontos | Desvio menor de conformidade/governança. |

**Regras Normativas de Nível de Risco (`risk_level`):**
- **`CRITICAL`:** `score < 40` OU presença de **pelo menos 1 achado de severidade `CRITICAL`**.
- **`HIGH`:** `40 <= score < 70` (sem achados CRITICAL).
- **`MEDIUM`:** `70 <= score < 90`.
- **`LOW`:** `90 <= score <= 100`.

---

### 2.4. Catálogo Canônico de Regras de Auditoria (IAM & Terraform)

#### 2.4.1. Regras para Políticas IAM (`type: "iam"`):

| Código | Severidade | Título | Gatilho Técnico de Detecção |
| :--- | :---: | :--- | :--- |
| `IAM-001` | `CRITICAL` | Ação Universal com Wildcard | Statement com `Effect: Allow` contendo `Action = "*"` ou wildcard genérico de serviço (`s3:*`, `ec2:*`). |
| `IAM-002` | `CRITICAL` | Recurso Universal com Wildcard | Statement com `Effect: Allow` contendo `Resource = "*"` ou presença de `NotResource` com `Allow`. |
| `IAM-003` | `HIGH` | Permissão Administrativa Potencial | Statement com `Effect: Allow` com ações sensíveis de gerenciamento de identidade (`iam:*`, `iam:attach*`, `iam:put*`, `iam:create*`, `iam:update*`, `iam:delete*`, `iam:passrole`). |
| `IAM-004` | `HIGH` | Permissões de Exclusão Irrestrita | Statement com `Effect: Allow` contendo verbos destrutivos curingas (`*:Delete*`, `*:Terminate*`, `*:Drop*`). |
| `IAM-005` | `MEDIUM` | Statement Allow sem Condição | Statement com `Effect: Allow` sem bloco `Condition` ou com bloco `Condition` vazio `{}`. |
| `IAM-006` | `LOW` | Versão de Política Incorreta ou Ausente | Cabeçalho `Version` ausente ou divergente da especificação normativa `"2012-10-17"`. |
| `IAM-007` | `CRITICAL` | Uso Perigoso de NotAction com Allow | Declaração do bloco `NotAction` em statement com efeito `Allow`. |
| `IAM-008` | `CRITICAL` | Uso de Wildcard Global em Principal | Campo `Principal` definido como `*` (string, lista `["*"]` ou objeto `{"AWS": "*"}`). |
| `IAM-009` | `HIGH` | iam:PassRole sem Restrição de Condição | Ação `iam:PassRole` sem cláusula `Condition` contendo `iam:PassedToService`. |

#### 2.4.2. Regras para Terraform HCL (`type: "terraform"`):

| Código | Severidade | Título | Gatilho Técnico de Detecção |
| :--- | :---: | :--- | :--- |
| `TF-001` | `CRITICAL` | Porta Administrativa Aberta para a Internet | `ingress` em `aws_security_group` ou `aws_security_group_rule` com CIDR `0.0.0.0/0` ou `::/0` expondo portas sensíveis (22 SSH, 3389 RDP, 5432 Postgres, 3306 MySQL) ou faixas amplas (ex: 0 a 65535). |
| `TF-002` | `HIGH` | Bucket S3 com ACL Pública | Atributo `acl` em `aws_s3_bucket` ou `aws_s3_bucket_acl` configurado como `public-read`, `public-read-write` ou `authenticated-read`. |
| `TF-003` | `HIGH` | Ausência de Bloqueio Público no S3 | Ausência de `aws_s3_bucket_public_access_block` para o bucket ou flags de bloqueio explicitamente configuradas como `false`. |
| `TF-004` | `MEDIUM` | Bucket S3 sem Criptografia em Repouso | Ausência de bloco inline ou recurso complementar `aws_s3_bucket_server_side_encryption_configuration`. |
| `TF-005` | `LOW` | Ausência de Tags Padrão de Governança | Recursos governados (`aws_s3_bucket`, `aws_security_group`, `aws_ebs_volume`, `aws_db_instance`, `aws_instance`) sem bloco `tags` contendo `Environment` ou `Project`. |
| `TF-006` | `HIGH` | Volume EBS sem Criptografia em Repouso | `aws_ebs_volume` ou blocos de disco em `aws_instance` sem `encrypted = true` ou com `encrypted = false`. |
| `TF-007` | `HIGH` | Instância RDS sem Criptografia em Repouso | `aws_db_instance` sem `storage_encrypted = true` ou com `storage_encrypted = false`. |

---

## 3. Plano de Testes de Estresse & Resiliência Operacional (Stress & Load Testing)

### 3.1. Volumetria de Dados e Limites de Payload (512 KB)
- **Risco:** Payloads excessivamente grandes podem esgotar a memória da função Lambda (128 MB), provocar timeouts faturados no API Gateway e gerar custos não planejados.
- **Cenários de Teste:**
  1. *Payload Baseline (1 KB a 10 KB):* Documento IAM e manifesto HCL típicos para medição de latência baseline (alvo: < 50ms).
  2. *Payload Médio (100 KB a 250 KB):* Políticas corporativas com dezenas de statements e comentários extensos.
  3. *Payload no Limite Superior (500 KB):* Documento ligeiramente abaixo do limiar `MAX_PAYLOAD_BYTES = 524.288` (deve ser processado com sucesso).
  4. *Payload Excedido (513 KB a 2 MB):* Submissão de volumes superiores a 512 KB. Deve disparar retorno imediato de **HTTP 413 Payload Too Large** sem carregar o parser JSON ou executar auditoria.
  5. *Ataque de Padding Nulo / Espaços em Branco:* Envio de 600 KB constituídos por 1 statement válido seguido de 599 KB de espaços em branco (deve ser barrado no pre-check de tamanho).

---

### 3.2. Carga Sintética de Statements e Recursos (DoS Prevention)
- **Risco:** Loops de iteração não limitados podem degradar o tempo de resposta em $\mathcal{O}(N^2)$ ou travar a CPU da Lambda.
- **Cenários de Teste:**
  1. *Políticas com 100, 250 e 500 statements:* Validação de desempenho linear $\mathcal{O}(N)$ e tempo de resposta < 500ms.
  2. *Defesa contra Explosão de Statements (501 a 2.000 statements):* A Lambda impõe `MAX_ALLOWED_STATEMENTS = 500`. Deve retornar **HTTP 400 Bad Request** de forma controlada: `"O documento excede o limite máximo permitido de 500 statements por política."`
  3. *Carga HCL de 500 Security Groups:* Validação do contador de chaves e regex do analisador HCL sob alta densidade de blocos.

---

### 3.3. Profundidade de Aninhamento JSON (Anti-Recursion DoS)
- **Risco:** Estruturas JSON profundamente aninhadas podem causar `RecursionError` / estouro de pilha no interpretador Python 3.12 (`sys.getrecursionlimit()`).
- **Mecanismo Defensivo:** Algoritmo iterativo `_check_nesting_depth` limitando o aninhamento a no máximo 20 níveis para validações defensivas (ou teto configurável de 800).
- **Cenários de Teste:**
  1. *Aninhamento Normal (1 a 5 níveis):* Execução transparente.
  2. *Aninhamento Patológico (30 a 100 níveis de dicionários/listas aninhadas):* Interrupção com **HTTP 400 Bad Request** informando `"Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError)."`.
  3. *Garantia Anti-Crash:* A aplicação nunca deve lançar exceção não capturada ou retornar HTTP 500 com dump de erro interno.

---

### 3.4. Avaliação de ReDoS (Regex Denial of Service)
- **Risco:** Expressões regulares vulneráveis a *catastrophic backtracking* podem reter a CPU em 100% até o timeout da Lambda.
- **Expressões Auditadas:**
  - `re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)`: Bloco de comentário não fechado `/*` seguido de 200.000 caracteres de texto sem `*/`.
  - `re.compile(r'resource\s+"([a-zA-Z0-9_\-]+)"\s+"([a-zA-Z0-9_\-]+)"\s*\{')`: Milhares de espaços em branco e tabulações intercaladas entre palavras-chave.
  - `re.search(r'cidr_blocks\s*=\s*\[(.*?)\]', rule_body, re.DOTALL)`: Listas com milhares de quebras de linha e vírgulas órfãs.
- **Validação:** Tempo de execução sob strings patológicas deve permanecer < 100ms.

---

### 3.5. Limites Operacionais de Memória e Timeout (FinOps Scale-to-Zero)
- **Configuração da Lambda em Terraform:**
  - `memory_size = 128` (MB)
  - `timeout = 10` (segundos)
- **Critérios de Homologação:**
  - Consumo de memória real não deve ultrapassar 70 MB sob carga máxima autorizada.
  - Duração típica das requisições deve permanecer sub-100ms.
  - Zero ocorrências de timeouts faturados de 10 segundos no CloudWatch.

---

## 4. Plano de Testes de Evasão & Bypasses de Análise Estática

### 4.1. Evasões Semânticas em Políticas IAM

| ID | Técnica de Evasão | Vetor de Teste | Comportamento Esperado do Motor |
| :--- | :--- | :--- | :--- |
| **EVA-IAM-01** | Casing Inversion | `"action": "s3:*"` ou `"ACTION": "*"` | Normalização recursiva de chaves via `_normalize_iam_dict_keys`; detectado como `IAM-001`. |
| **EVA-IAM-02** | Efeito em Minúsculas | `"effect": "allow"` | Normalizado com `.strip().lower() == "allow"`; auditado sem bypass. |
| **EVA-IAM-03** | Inversão Lógica `NotAction` | `"NotAction": "iam:Delete*"` com `Effect: Allow` | Capturado pela regra `IAM-007` (`CRITICAL`), impedindo concessão irrestrita velada. |
| **EVA-IAM-04** | Inversão Lógica `NotResource` | `"NotResource": "arn:aws:s3:::safe-bucket"` com `Allow` | Capturado pela regra `IAM-002` (`CRITICAL`), acusando permissão irrestrita a todos os outros recursos. |
| **EVA-IAM-05** | Wildcard Oculto em Array | `"Action": ["s3:GetObject", " * "]` | Remoção de espaços com `.strip()`; detectado como `IAM-001`. |
| **EVA-IAM-06** | PassRole sem Condição Válida | `"Condition": {"StringEquals": {"dummy": "val"}}` | Validação semântica exige a chave `iam:PassedToService`; detectado como `IAM-009`. |
| **EVA-IAM-07** | Wildcard Complexo em Principal | `"Principal": {"AWS": ["arn:...", "*"]}` | Inspeção recursiva em listas de dicionários; detectado como `IAM-008`. |

---

### 4.2. Evasões em Regras Terraform HCL (Regex vs Sintaxe Real)

| ID | Técnica de Evasão | Vetor de Teste | Comportamento Esperado do Motor |
| :--- | :--- | :--- | :--- |
| **EVA-TF-01** | Quebras de Linha em Tokens | `resource\n "aws_security_group"\n "web" {` | A regex `resource\s+...` com suporte a `\s` captura a declaração integralmente. |
| **EVA-TF-02** | Chaves Dentro de Strings Literais | `description = "Porta liberada { teste }"` | O algoritmo `depth` brace counter não se corrompe ao contar blocos externos. |
| **EVA-TF-03** | Comentários Mistos na Mesma Linha | `from_port = 22 # inline\n to_port = 22 // inline` | Sanitização prévia via `_strip_hcl_comments` remove comentários preservando tokens. |
| **EVA-TF-04** | ACL Semi-Pública | `acl = "authenticated-read"` | O regex `PUBLIC_S3_ACL_PATTERN` detecta `authenticated-read` como achado `TF-002`. |
| **EVA-TF-05** | Public Access Block Desativado | `block_public_acls = false` | O motor inspeciona flags booleanas desativadas e acusa `TF-003`. |

---

### 4.3. Bypasses de Portas, Faixas Contíguas e Notação CIDR/IPv6

1. **Faixas de Portas Abrangentes:**
   - Em vez de especificar `from_port = 22` e `to_port = 22`, submeter `from_port = 20` e `to_port = 80`.
   - O algoritmo `_check_ingress_rule` calcula `from_port <= 22 <= to_port` e detecta a abertura de SSH (`TF-001`).
   - Faixas extremas: `from_port = 0, to_port = 65535` ou `from_port = 0, to_port = 0` (todo o tráfego) detectam todas as 4 portas sensíveis (22, 3389, 5432, 3306).
2. **Notação IPv6 Wildcard:**
   - Submissão de `cidr_blocks = ["::/0"]` aberta na porta 3389.
   - O motor reconhece `"::/0"` com a mesma severidade `CRITICAL` de `0.0.0.0/0`.

---

### 4.4. Mitigação e Supressão de Falsos Positivos

- **Políticas com `Effect: Deny` Defensivo:**
  - Declarações mandatadas pelo CIS AWS (como bloqueio explícito de transporte inseguro `aws:SecureTransport: false` ou negação universal de exclusão `Effect: Deny, Action: *`) **não devem deduzir pontos do score**.
  - O motor ignora declarações que não possuam `Effect: Allow`, garantindo **Score 100 (LOW)** para controles puramente defensivos.

---

## 5. Sondas de Borda da API & Protocolo (Edge Probing)

### 5.1. Fuzzing de Métodos HTTP e Cabeçalhos
- **Sonda PRB-01 (Métodos HTTP Inválidos):**
  - Chamadas com `GET`, `PUT`, `DELETE`, `PATCH`, `HEAD` para o endpoint `/audit`.
  - Resposta esperada: `HTTP 400 Bad Request` ou `HTTP 405 Method Not Allowed` retornado pelo API Gateway/Lambda sem vazar traces internos.
- **Sonda PRB-02 (Content-Type Anômalo ou Ausente):**
  - Submissão com `Content-Type: text/plain`, `application/xml` ou sem header.
  - O handler Lambda deve realizar parse resiliente do payload JSON ou responder com erro 400 amigável.
- **Sonda PRB-03 (Parameter Pollution / Injeção de Propriedades):**
  - Envio de campos extras como `{"type": "iam", "content": "...", "admin": true, "__proto__": {"polluted": true}}`.
  - A API deve processar estritamente `type` e `content`, descartando atributos espúrios de forma segura.

---

### 5.2. Manipulação de Base64 e Codificação de Caracteres
- **Sonda PRB-04 (Base64 Corrompido):**
  - Evento com `isBase64Encoded: true` e corpo contendo lixo binário ou strings com padding inválido.
  - Tratamento com bloco `except (binascii.Error, ValueError)` retornando **HTTP 400 Bad Request** (`"Erro na decodificação Base64"`).
- **Sonda PRB-05 (Caracteres de Controle Não-Imprimíveis):**
  - Submissão de bytes nulos `\x00` ou caracteres de controle ASCII (`\x01` a `\x1f`).
  - No motor HCL, sanitização automática via `CONTROL_CHARS_PATTERN`; no motor IAM, rejeição pelo parser JSON restrito.

---

### 5.3. Validação de Políticas de CORS e Preflight
- **Sonda PRB-06 (Preflight OPTIONS):**
  - Envio de requisição `OPTIONS /audit` simulando origens arbitrárias (`Origin: https://sec-eval.internal`).
  - Validação do retorno imediato de **HTTP 200 OK** contendo os cabeçalhos:
    - `Access-Control-Allow-Origin: *` (ou configurado)
    - `Access-Control-Allow-Methods: POST, OPTIONS`
    - `Access-Control-Allow-Headers: Content-Type, Authorization`

---

### 5.4. Sanitização Anti-XSS e Content Security Policy (CSP) do Frontend
- **Sonda PRB-07 (Injeção de Script em Findings):**
  - Resposta simulada da API contendo tags `<script>alert('xss')</script>` ou `<img src=x onerror=alert(1)>` nos campos `title`, `description` ou `recommendation`.
  - A função `escapeHtml()` no `app.js` deve neutralizar todos os caracteres (`<`, `>`, `&`, `"`, `'`, `/`), renderizando o texto seguro como texto puro no DOM.
- **Sonda PRB-08 (Whitelist de Severidades):**
  - Submissão de severidade injetada `CRITICAL'; injection--`.
  - O frontend valida contra a whitelist `ALLOWED_SEVERITIES = Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])`, rejeitando valores adulterados.
- **Sonda PRB-09 (Validação da Meta Tag CSP em `index.html`):**
  - Verificar a diretiva `connect-src 'self' https://*.execute-api.us-east-2.amazonaws.com;` impedindo exfiltração de dados para origens terceiras não autorizadas.
- **Sonda PRB-10 (Timeout com AbortController):**
  - Simulação de latência de 20 segundos na API.
  - O frontend deve abortar a conexão após 15 segundos (`15000 ms`), restaurar o estado da interface e exibir banner visual amigável sem chamadas bloqueantes a `alert()`.

---

## 6. Matriz de Cenários de Teste Executáveis

| ID do Caso | Categoria | Descrição Técnica do Teste | Entrada / Vetor | Resultado Esperado | Prioridade |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-STR-01** | Estresse | Payload IAM volumetricamente elevado | 500 statements `Allow` | HTTP 200, score calculado, tempo < 500ms | P1 |
| **TC-STR-02** | Estresse | Tentativa de DoS por explosão de statements | 501 statements `Allow` | HTTP 400 com mensagem de limite excedido | P0 |
| **TC-STR-03** | Estresse | Payload excedendo o teto de 512 KB | String com 525 KB de caracteres | HTTP 413 Payload Too Large imediato | P0 |
| **TC-STR-04** | Estresse | ReDoS com comentário de bloco sem fechamento | `/*` seguido de 250k caracteres | Retorno normal sem consumo de CPU | P0 |
| **TC-STR-05** | Estresse | Recursão profunda em JSON (> 20 níveis) | JSON aninhado com 35 níveis | HTTP 400 RecursionError tratado | P1 |
| **TC-EVA-01** | Evasão | Casing em chaves IAM (`action`, `resource`) | JSON com chaves minúsculas | Detectado normalmente (`IAM-001`, `IAM-002`) | P0 |
| **TC-EVA-02** | Evasão | Inversão lógica perigosa com `NotAction` | `Effect: Allow, NotAction: iam:Delete*` | Detectado como `IAM-007` (CRITICAL) | P0 |
| **TC-EVA-03** | Evasão | Inversão lógica perigosa com `NotResource`| `Effect: Allow, NotResource: arn:...` | Detectado como `IAM-002` (CRITICAL) | P0 |
| **TC-EVA-04** | Evasão | Wildcard com espaços (`" * "`) | `"Action": " * "` | Detectado como `IAM-001` (CRITICAL) | P0 |
| **TC-EVA-05** | Falso Positivo| Política defensiva com `Effect: Deny` | CIS deny statement com `Action: *` | Score 100 (LOW), sem achados espúrios | P1 |
| **TC-EVA-06** | Evasão | Security Group com faixa cobrindo porta 22 | `from_port = 20, to_port = 25` | Detectado como `TF-001` (SSH 22) | P0 |
| **TC-EVA-07** | Evasão | Security Group expondo todas as portas | `from_port = 0, to_port = 0` | Detectado como `TF-001` (22, 3389, 5432, 3306) | P0 |
| **TC-EVA-08** | Evasão | Regra Ingress com CIDR IPv6 global | `cidr_blocks = ["::/0"]` (porta 3389) | Detectado como `TF-001` (RDP 3389) | P0 |
| **TC-EVA-09** | Evasão | Chaves literais `{}` dentro de string HCL | `description = "SG com chave { teste }"` | Parse íntegro de blocos subsequentes | P1 |
| **TC-PRB-01** | Borda | Método HTTP GET na rota de auditoria | `GET /audit` | HTTP 400 ou 405 sem stack trace | P1 |
| **TC-PRB-02** | Borda | Tipo de auditoria inválido no JSON | `{"type": "azure_arm", "content": "..."}`| HTTP 400 ("Tipo de auditoria inválido") | P1 |
| **TC-PRB-03** | Borda | Conteúdo vazio ou composto por espaços | `{"type": "iam", "content": "   "}` | HTTP 400 ("campo content é obrigatório") | P1 |
| **TC-PRB-04** | Borda | Payload Base64 com dados corrompidos | `isBase64Encoded: true` com lixo | HTTP 400 ("Erro decodificação Base64") | P1 |
| **TC-PRB-05** | Borda | Requisição de Preflight CORS | `OPTIONS /audit` | HTTP 200 (`status: ok`) com headers CORS | P1 |
| **TC-PRB-06** | Borda/XSS | Tentativa de injeção de script via findings | Payload simulado com `<script>` | Entidades escapadas via `escapeHtml()` | P0 |

---

## 7. Diretrizes de Execução e Automação

O pipeline de testes da branch `qa/stress-audit` é estruturado em suítes modulares utilizando estritamente a biblioteca padrão do Python (`unittest`):

1. **`qa/test_stress_local.py`:** Suíte de estresse sintético local (payloads volumosos, limites de tamanho, saturação de statements, profundidade JSON e vetores ReDoS).
2. **`qa/test_evasion_bypass.py`:** Bateria de testes de evasão semântica (casing, arrays, NotAction/NotResource, range de portas, IPv6 e supressão de falsos positivos).
3. **`qa/probe_production.py`:** Sondas de borda executadas diretamente contra a API pública em produção (`https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit`), validando CORS, preflight, métodos e comportamento de borda.
4. **`qa/audit_frontend.py`:** Verificação estática do código da SPA (`web/`), assegurando proteção anti-XSS, integridade de CSP, timeouts determinísticos e ausência de bloqueios síncronos na interface.

---
*Documento de Referência Técnica mantido pela Engenharia de QA & AppSec — Branch `qa/stress-audit`.*
