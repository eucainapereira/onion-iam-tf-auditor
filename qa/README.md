# 🧅 Onion Auditor — Plano Estratégico de Testes QA, Estresse, Evasão e Borda

[![QA & AppSec Engineering](https://img.shields.io/badge/QA%20%26%20AppSec-Security%20Testing-red)](qa/README.md)
[![Branch: qa/stress-audit](https://img.shields.io/badge/Branch-qa%2Fstress--audit-blueviolet)](https://github.com/eucainapereira/onion-iam-tf-auditor/tree/qa/stress-audit)
[![Coverage Target: 100%](https://img.shields.io/badge/Coverage%20Target-Resilience%20%26%20Evasion-brightgreen)](qa/README.md)

---

## 📌 Sumário
- [1. Visão Geral e Objetivos do Plano de QA](#1-visão-geral-e-objetivos-do-plano-de-qa)
- [2. Mapeamento da Superfície de Ataque e Infraestrutura](#2-mapeamento-da-superfície-de-ataque-e-infraestrutura)
  - [2.1. Endpoints Públicos de Produção](#21-endpoints-públicos-de-produção)
  - [2.2. Contrato de API (HTTP API v2 + Lambda)](#22-contrato-de-api-http-api-v2--lambda)
  - [2.3. Matriz de Severidade e Cálculo de Risco](#23-matriz-de-severidade-e-cálculo-de-risco)
  - [2.4. Catálogo Canônico de Regras de Auditoria](#24-catálogo-canônico-de-regras-de-auditoria)
- [3. Plano de Testes de Estresse & Resiliência (Stress & Load Testing)](#3-plano-de-testes-de-estresse--resiliência-stress--load-testing)
  - [3.1. Limites de Payload e Volumetria de Dados](#31-limites-de-payload-e-volumetria-de-dados)
  - [3.2. Carga Sintética de Statements e Recursos](#32-carga-sintética-de-statements-e-recursos)
  - [3.3. Avaliação de ReDoS (Regex Denial of Service)](#33-avaliação-de-redos-regex-denial-of-service)
  - [3.4. Limites Operacionais de Memória e Timeout (FinOps Scale-to-Zero)](#34-limites-operacionais-de-memória-e-timeout-finops-scale-to-zero)
- [4. Plano de Testes de Evasão & Bypasses de Análise Estática](#4-plano-de-testes-de-evasão--bypasses-de-análise-estática)
  - [4.1. Evasão em Regras IAM (Case Sensitivity, Arrays e Lógica de Efeito)](#41-evasão-em-regras-iam-case-sensitivity-arrays-e-lógica-de-efeito)
  - [4.2. Evasão em Regras Terraform HCL (Regex vs Sintaxe Real)](#42-evasão-em-regras-terraform-hcl-regex-vs-sintaxe-real)
  - [4.3. Bypasses de Portas, Notação CIDR e IPv6](#43-bypasses-de-portas-notação-cidr-e-ipv6)
- [5. Sondas de Borda da API & Protocolo (Edge Probing)](#5-sondas-de-borda-da-api--protocolo-edge-probing)
  - [5.1. Fuzzing de Métodos HTTP e Cabeçalhos](#51-fuzzing-de-métodos-http-e-cabeçalhos)
  - [5.2. Manipulação de Base64 e Codificação de Caracteres](#52-manipulação-de-base64-e-codificação-de-caracteres)
  - [5.3. Validação de Políticas de CORS e Preflight](#53-validação-de-políticas-de-cors-e-preflight)
- [6. Matriz de Cenários de Teste Executáveis](#6-matriz-de-cenários-de-teste-executáveis)
- [7. Cronograma e Automação de Execução](#7-cronograma-e-automação-de-execução)

---

## 1. Visão Geral e Objetivos do Plano de QA

O presente documento estabelece o plano formal de **Garantia de Qualidade (QA)** e **Segurança de Aplicações (AppSec)** para o projeto **Onion Auditor**.

O objetivo primário deste plano é submeter a arquitetura Serverless (API Gateway v2 + AWS Lambda Python 3.12 + S3 Frontend) e o motor de análise estática (`src/auditor.py` e `src/handler.py`) a testes rigorosos em quatro frentes principais:
1. **Conformidade Contratual:** Assegurar que todas as entradas e saídas cumpram milimetricamente os contratos da API e os tipos de dados definidos.
2. **Resiliência e Estresse:** Determinar os limites de ruptura do motor estático contra payloads volumosos, estouro de memória e saturação de tempo de execução.
3. **Resistência à Evasão:** Identificar vetores onde regras de segurança IAM ou Terraform HCL possam ser contornadas por formatações não-canônicas, ofuscação, variações de case ou manipulações estruturais.
4. **Defesa em Borda:** Validar a resposta do API Gateway e do handler Lambda contra tráfego malicioso, métodos HTTP não permitidos e cabeçalhos forjados.

> [!IMPORTANT]
> **Isolamento de Branch:** Todas as atividades, automações e scripts de teste de estresse são mantidos estritamente na branch isolada `qa/stress-audit`. Nunca deve ser feito push de testes na branch `main` ou disparado o workflow `.github/workflows/deploy.yml`.

---

## 2. Mapeamento da Superfície de Ataque e Infraestrutura

### 2.1. Endpoints Públicos de Produção

Com base no manifesto Terraform (`terraform/outputs.tf`) e na documentação arquitetural (`README.md`), os ativos públicos em ambiente de produção estão mapeados:

| Ativo | Tipo de Recurso | URL Pública Mapeada |
| :--- | :--- | :--- |
| **API Backend** | AWS API Gateway HTTP API (v2) | `https://p73sp8ai87.execute-api.us-east-2.amazonaws.com/audit` |
| **Frontend SPA** | AWS S3 Static Website Hosting | `http://onion-auditor-frontend-654341980060-us-east-2.s3-website.us-east-2.amazonaws.com` |
| **Storage S3** | S3 Bucket Físico | `onion-auditor-frontend-654341980060-us-east-2` |
| **Telemetria** | Amazon CloudWatch Logs | `/aws/lambda/onion-auditor-engine` (Retenção: 7 dias) |

---

### 2.2. Contrato de API (HTTP API v2 + Lambda)

#### Requisição: `POST /audit`
- **Cabeçalhos Exigidos:**
  - `Content-Type: application/json`
- **CORS Habilitado:**
  - `Access-Control-Allow-Origin: *`
  - `Access-Control-Allow-Methods: POST, OPTIONS`
  - `Access-Control-Allow-Headers: Content-Type, Authorization` (ou `content-type, authorization`)

#### Esquema de Entrada (JSON Request Body):
```json
{
  "type": "iam" | "terraform",
  "content": "<string não vazia>"
}
```

#### Esquema de Saída com Sucesso (HTTP 200 OK):
```json
{
  "score": 0,
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "findings": [
    {
      "id": "IAM-001",
      "title": "Ação Universal com Wildcard",
      "severity": "CRITICAL",
      "description": "...",
      "recommendation": "..."
    }
  ]
}
```

#### Esquema de Erro de Validação (HTTP 400 Bad Request):
```json
{
  "error": "<descrição prescritiva do erro de validação>"
}
```

#### Esquema de Erro Interno (HTTP 500 Internal Server Error):
```json
{
  "error": "Erro interno durante a execução da auditoria: <detalhes>"
}
```

---

### 2.3. Matriz de Severidade e Cálculo de Risco

O motor calcula o score a partir de **100**, deduzindo pontos por severidade e aplicando piso em **0**:

| Severidade | Dedução por Achado | Impacto no Score |
| :--- | :---: | :--- |
| `CRITICAL` | **-30** pontos | Força `risk_level = CRITICAL` independentemente do score final. |
| `HIGH` | **-15** pontos | Reduz o score gradualmente. |
| `MEDIUM` | **-10** pontos | Risco moderado. |
| `LOW` | **-5** pontos | Baixo risco / boas práticas. |

**Regras de Enquadramento do `risk_level`:**
- `CRITICAL`: `Score < 40` OU presença de $\ge 1$ achado `CRITICAL`.
- `HIGH`: $40 \le \text{Score} < 70$.
- `MEDIUM`: $70 \le \text{Score} < 90$.
- `LOW`: $90 \le \text{Score} \le 100$.

---

### 2.4. Catálogo Canônico de Regras de Auditoria

#### Regras para Políticas IAM (`type: "iam"`):
| ID | Severidade | Título | Condição de Detecção Implementada |
| :--- | :---: | :--- | :--- |
| `IAM-001` | `CRITICAL` | Ação Universal com Wildcard | Statement com `Effect: Allow` contendo `Action = "*"` ou terminando com `:*` (ex: `s3:*`). |
| `IAM-002` | `CRITICAL` | Recurso Universal com Wildcard | Statement com `Effect: Allow` contendo `Resource = "*"`. |
| `IAM-003` | `HIGH` | Permissão Administrativa Potencial | Statement com `Effect: Allow` com ações IAM sensíveis (`iam:*`, `iam:attach*`, `iam:put*`, `iam:create*`, `iam:update*`, `iam:delete*`, `iam:passrole`) sem wildcards globais. |
| `IAM-004` | `HIGH` | Permissões de Exclusão Irrestrita | Statement com `Effect: Allow` contendo `:delete*`, `:terminate*`, `:drop*` sem wildcard universal. |
| `IAM-005` | `MEDIUM` | Statement Allow sem Condição | Statement com `Effect: Allow` sem bloco `Condition` ou com bloco `Condition` vazio. |
| `IAM-006` | `LOW` | Versão de Política Incorreta ou Ausente | Cabeçalho `Version` ausente ou diferente do padrão normativo `"2012-10-17"`. |
| `IAM-007` | `CRITICAL` | Uso Perigoso de NotAction com Allow | Presença do campo `NotAction` em statements com `Effect: Allow`. |
| `IAM-008` | `CRITICAL` | Uso de Wildcard Global em Principal | `Principal` definido como `*` (string, lista ou em dicionários). |
| `IAM-009` | `HIGH` | iam:PassRole sem Restrição de Condição | Ação `iam:passrole` sem condição válida (`iam:passedtoservice` ou `stringequals`). |

#### Regras para Terraform HCL (`type: "terraform"`):
| ID | Severidade | Título | Condição de Detecção Implementada |
| :--- | :---: | :--- | :--- |
| `TF-001` | `CRITICAL` | Porta Administrativa Aberta para a Internet | `ingress` em `aws_security_group` ou `aws_security_group_rule` com `0.0.0.0/0` ou `::/0` nas portas 22 (SSH), 3389 (RDP), 5432 (Postgres), 3306 (MySQL) ou `0-0` (all traffic). |
| `TF-002` | `HIGH` | Bucket S3 com ACL Pública | `aws_s3_bucket` ou `aws_s3_bucket_acl` com `acl = "public-read"` ou `"public-read-write"`. |
| `TF-003` | `HIGH` | Ausência de Bloqueio Público no S3 | `aws_s3_bucket` sem `aws_s3_bucket_public_access_block` ou com flags de bloqueio como `false`. |
| `TF-004` | `MEDIUM` | Bucket S3 sem Criptografia em Repouso | `aws_s3_bucket` sem configuração inline ou externa de SSE. |
| `TF-005` | `LOW` | Ausência de Tags Padrão de Governança | Recursos governados sem bloco `tags` contendo `Environment` ou `Project`. |
| `TF-006` | `HIGH` | Volume EBS sem Criptografia em Repouso | `aws_ebs_volume` ou `aws_instance` com `encrypted = false` ou sem a diretiva `encrypted = true`. |
| `TF-007` | `HIGH` | Instância RDS sem Criptografia em Repouso | `aws_db_instance` com `storage_encrypted = false` ou sem `storage_encrypted = true`. |

---

## 3. Plano de Testes de Estresse & Resiliência (Stress & Load Testing)

### 3.1. Limites de Payload e Volumetria de Dados
- **Objetivo:** Avaliar a capacidade do parser e do runtime AWS Lambda de processar payloads de tamanhos progressivos sem estourar tempo ou memória.
- **Cenários a Executar:**
  1. **Payload Tiny (1 KB):** Política IAM padrão com 1 statement. (Baseline de latência).
  2. **Payload Médio (100 KB):** Política com dezenas de statements e comentários HCL extensos.
  3. **Payload Grande (1 MB a 5 MB):** Manifesto HCL gigante contendo centenas de definições de Security Groups e volumes EBS.
  4. **Payload Limite API Gateway (10 MB):** Teste de borda contra o limite do AWS API Gateway (Payload Too Large - 413).
  5. **Análise de Profundidade JSON (Nesting Stress):** JSON com 100 níveis de aninhamento para validar se `json.loads` atinge o limite de recursão do Python.

---

### 3.2. Carga Sintética de Statements e Recursos
- **Objetivo:** Verificar se o tempo de execução do motor cresce de forma linear $\mathcal{O}(N)$ ou quadrática $\mathcal{O}(N^2)$ ao analisar grandes volumes de entidades.
- **Cenários a Executar:**
  1. Gerar documento IAM com 500 statements individuais.
  2. Gerar documento IAM com 2.500 statements com mix de conformidade e não conformidade.
  3. Gerar código HCL com 1.000 blocos de `resource "aws_security_group"`.
  4. Medir o consumo de CPU e tempo de execução na Lambda (limite de 10 segundos).

---

### 3.3. Avaliação de ReDoS (Regex Denial of Service)
- **Objetivo:** Testar as expressões regulares do analisador de HCL contra strings patológicas desenhadas para provocar *catastrophic backtracking*.
- **Alvos de Expressões Regulares em Análise:**
  - `re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)`: Comentários de bloco sem fechamento (`/*` seguido de 100.000 caracteres sem `*/`).
  - `re.compile(r'resource\s+"([a-zA-Z0-9_\-]+)"\s+"([a-zA-Z0-9_\-]+)"\s*\{')`: Espaços em branco repetidos excessivamente entre tokens.
  - `re.compile(rf'{block_name}\s*\{{')`: Verificação de aninhamento de chaves desbalanceadas.
  - `re.search(r'cidr_blocks\s*=\s*\[(.*?)\]', rule_body, re.DOTALL)`: Listas com milhares de vírgulas, quebras de linha e strings incompletas.

---

### 3.4. Limites Operacionais de Memória e Timeout (FinOps Scale-to-Zero)
- **Configuração da Lambda em Terraform:**
  - `memory_size = 128` (MB)
  - `timeout = 10` (segundos)
- **Métricas a Monitorar via CloudWatch:**
  - `Duration` vs `Billed Duration`
  - `Max Memory Used` (Verificar se atinge margem de segurança < 80 MB)
  - Ocorrência de eventos `Task timed out after 10.00 seconds`

---

## 4. Plano de Testes de Evasão & Bypasses de Análise Estática

### 4.1. Evasão em Regras IAM (Case Sensitivity, Arrays e Lógica de Efeito)

Como o parser IAM avalia propriedades JSON e strings em Python, devem ser testados os seguintes vetores de bypass:

1. **Variações de Case nas Chaves e Valores:**
   - Testar `"effect": "allow"` vs `"Effect": "Allow"`.
   - Testar `"action": "*"` vs `"Action": "*"`.
   - Testar `"resource": "*"` vs `"Resource": "*"`.
   - Testar `"IAM:PassRole"` ou `"Iam:PassRole"` em vez de `"iam:PassRole"`.
2. **Normalização de Espaços e Caracteres Especiais:**
   - Inserção de espaços em branco ou tabs dentro das strings de ação (`" s3:* "`, `"iam:PassRole "`).
   - Caracteres Unicode ou zero-width space antes de wildcards.
3. **Representação Mista de Tipos em `Action` e `Resource`:**
   - `Action` como string única vs lista de strings vs array com valores vazios `["", "*"]`.
4. **Statement de Negação (`Effect: Deny`) com Wildcards:**
   - Verificar se um statement legítimo de negação (`Effect: Deny`, `Action: *`, `Resource: *`) é incorretamente penalizado pelo motor como `IAM-001` ou `IAM-002`.
5. **Bypass da Regra `IAM-009` (`iam:PassRole`):**
   - Criação de bloco `Condition` espúrio (ex: `{"Null": {"dummy": "true"}}`) sem a restrição real `iam:PassedToService`, verificando se o motor valida adequadamente a semântica da condição.
6. **Bypass da Regra `IAM-008` (Principal):**
   - Inserção de wildcard em chaves complexas como `{"AWS": ["arn:aws:iam::123456789012:root", "*"]}`.

---

### 4.2. Evasão em Regras Terraform HCL (Regex vs Sintaxe Real)

O parser de HCL é baseado em contagem de chaves e expressões regulares. Isso abre possíveis brechas que precisam ser estressadas:

1. **Quebras de Linha e Espaçamentos Não Canônicos:**
   - Declaração de recursos com quebras de linha entre palavras-chave:
     ```hcl
     resource
       "aws_security_group"
       "evasion_sg" {
     ```
   - Verificar se a regex `resource\s+"([a-zA-Z0-9_\-]+)"\s+"([a-zA-Z0-9_\-]+)"\s*\{` reconhece adequadamente a declaração.
2. **Chaves `{}` Dentro de Strings Literais:**
   - Inclusão de chaves `{` ou `}` dentro de descrições ou strings:
     ```hcl
     description = "Regra contendo chave { desbalanceadora"
     ```
   - Testar se o algoritmo `depth` brace counter é corrompido ao encontrar chaves literais dentro de aspas.
3. **Uso de Comentários Aninhados e Comentários de Linha Especial:**
   - Comentários no padrão `#`, `//` e `/* */` misturados na mesma linha de declarações sensíveis.
4. **Variáveis e Valores Computados:**
   - `encrypted = var.encryption_enabled`
   - `storage_encrypted = local.enable_rds_encryption`
   - O auditor deve tratar variáveis desconhecidas de forma determinística (conforme especificação, ausência de `true` literal é considerada achado).

---

### 4.3. Bypasses de Portas, Notação CIDR e IPv6

1. **Faixas de Portas Abrangentes:**
   - Em vez de especificar a porta exata 22, configurar `from_port = 20` e `to_port = 80`.
   - O motor deve detectar que 22 está contido na faixa.
   - Testar faixas com `from_port = 0` e `to_port = 65535`.
2. **Variações de CIDR Wildcard:**
   - `["0.0.0.0/0"]` vs `["0.0.0.0/0", "10.0.0.0/8"]`
   - Notação IPv6 `["::/0"]`
   - CIDRs adjacentes: `["0.0.0.0/1", "128.0.0.0/1"]` (que cobrem 100% da internet sem usar `0.0.0.0/0`).

---

## 5. Sondas de Borda da API & Protocolo (Edge Probing)

### 5.1. Fuzzing de Métodos HTTP e Cabeçalhos
- **Sonda 1 (Métodos HTTP Inválidos):**
  - Submissão de requisições `GET`, `PUT`, `DELETE`, `PATCH`, `HEAD` para `/audit`.
  - Verificação se o API Gateway ou a Lambda retornam HTTP 400 ou 405 sem vazar stack trace.
- **Sonda 2 (Content-Type Malformado ou Ausente):**
  - Envio de payload com `Content-Type: text/plain`.
  - Envio com `Content-Type: application/x-www-form-urlencoded`.
  - Envio sem nenhum cabeçalho `Content-Type`.
- **Sonda 3 (Injeção de Campos Desconhecidos / Parameter Pollution):**
  - Payload com chaves não previstas:
    ```json
    {
      "type": "iam",
      "content": "...",
      "admin": true,
      "bypass_rules": ["IAM-001"],
      "__proto__": { "polluted": true }
    }
    ```
  - Garantir que parâmetros espúrios sejam ignorados sem afetar a lógica.

---

### 5.2. Manipulação de Base64 e Codificação de Caracteres
- **Sonda 4 (Flags de Base64 Malformadas):**
  - Envio de evento simulando `isBase64Encoded: true` com corpo contendo string que não é Base64 válida.
  - Verificação da resposta de erro HTTP 400 (`Erro na decodificação Base64`).
- **Sonda 5 (Codificações Especiais UTF-8 / Caracteres Nulos):**
  - Envio de caracteres nulos `\u0000` embutidos no JSON.
  - Caracteres multilíngues (cirílico, kanji, emojis) no corpo do conteúdo.

---

### 5.3. Validação de Políticas de CORS e Preflight
- **Sonda 6 (OPTIONS Preflight Completo):**
  - Envio de `OPTIONS /audit` com cabeçalhos:
    - `Origin: https://malicious-site.example.com`
    - `Access-Control-Request-Method: POST`
    - `Access-Control-Request-Headers: Content-Type`
  - Validar se o status é `200 OK` e se os cabeçalhos CORS são retornados com segurança.

---

## 6. Matriz de Cenários de Teste Executáveis

| ID do Caso | Categoria | Descrição do Teste | Entrada / Vetor | Resultado Esperado | Prioridade |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-STR-01** | Estresse | Payload IAM volumoso | 1.000 statements `Allow` | HTTP 200, tempo < 2s, sem OOM | P1 |
| **TC-STR-02** | Estresse | Payload HCL volumoso | 500 Security Groups | HTTP 200, tempo < 3s, sem OOM | P1 |
| **TC-STR-03** | Estresse / ReDoS | Comentário HCL não terminado | `/*` seguido de 200k chars | Resposta sem travamento de CPU | P0 |
| **TC-STR-04** | Estresse | Profundidade JSON extrema | 150 níveis de objetos aninhados | HTTP 400 ou 200 sem crash | P2 |
| **TC-EVA-01** | Evasão IAM | Case variation em Action | `"Action": "iam:passrole"` | Detectado por `IAM-009` | P0 |
| **TC-EVA-02** | Evasão IAM | Espaço antes do Wildcard | `"Action": " * "` | Detectado por `IAM-001` | P0 |
| **TC-EVA-03** | Evasão IAM | Deny com Wildcard | `Effect: Deny, Action: *` | NÃO deve gerar `IAM-001` | P1 |
| **TC-EVA-04** | Evasão IAM | Array em Principal | `Principal: { AWS: ["*"] }` | Detectado por `IAM-008` | P0 |
| **TC-EVA-05** | Evasão HCL | Chave dentro de String | `description = "SG { teste }"` | Contagem de blocos íntegra | P0 |
| **TC-EVA-06** | Evasão HCL | Range amplo de portas | `from_port = 1, to_port = 100` | Detectado por `TF-001` (SSH 22) | P0 |
| **TC-EVA-07** | Evasão HCL | IPv6 Wildcard | `cidr_blocks = ["::/0"]` | Detectado por `TF-001` | P0 |
| **TC-EVA-08** | Evasão HCL | Quebras de linha em declaração | `resource\n"aws_s3_bucket"` | Detectado normalmente | P1 |
| **TC-PRB-01** | Sonda Borda | Método HTTP GET | `GET /audit` | HTTP 400 ou 405 | P1 |
| **TC-PRB-02** | Sonda Borda | Tipo de auditoria inválido | `type: "azure_arm"` | HTTP 400 ("Tipo de auditoria inválido") | P1 |
| **TC-PRB-03** | Sonda Borda | Payload Base64 corrompido | `isBase64Encoded: true` com lixo | HTTP 400 (Erro decodificação) | P1 |
| **TC-PRB-04** | Sonda Borda | Requisição OPTIONS Preflight | `OPTIONS /audit` | HTTP 200 (`status: ok`) | P1 |

---

## 7. Cronograma e Automação de Execução

As baterias de testes desenhadas neste plano serão implementadas utilizando:
1. **Testes Unitários Automatizados (Python `unittest`):** Implementação na pasta `qa/` de suíte executável sem dependências externas.
2. **Scripts de Teste de Carga e Sondas de Borda (`qa/probes/`):** Chamadas HTTP contra a API ao vivo documentada em `api_url`.
3. **Relatório de Conformidade:** Geração de sumário de achados de QA e validação de cobertura.

---
*Documento mantido pela equipe de QA & AppSec — Branch `qa/stress-audit`.*
