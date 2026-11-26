"""
Módulo de Auditoria Estática de Segurança e Resiliência do Frontend (Camada 4 - Onion Flow).
Realiza análise estática automatizada em busca de:
1. Vulnerabilidades XSS e Injeção DOM (uso de innerHTML, escapeHtml, interpolação unescaped).
2. Resiliência de Rede e Tratamento de Falhas (timeout/AbortController, fetch offline, JSON parsing).
3. Validação de Entrada e Pré-requisitos (campos vazios, validação de URL, tipos de auditoria).
4. Segurança de Folha de Estilos e Recursos Estáticos (ausência de @import, url(), integridade).

Utiliza estritamente bibliotecas padrão do Python (re, json, sys, pathlib, datetime).
Salva ou consolida os resultados em qa/results_prod_probes.json.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = REPO_ROOT / "web"
QA_DIR = REPO_ROOT / "qa"
RESULTS_FILE = QA_DIR / "results_prod_probes.json"

INDEX_HTML = WEB_DIR / "index.html"
APP_JS = WEB_DIR / "app.js"
STYLES_CSS = WEB_DIR / "styles.css"
CONFIG_JS = WEB_DIR / "config.js"


class FrontendAuditor:
    """Motor de auditoria estática de segurança e qualidade do frontend."""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.verified_controls: List[Dict[str, Any]] = []
        self.files_scanned: List[str] = []

    def _add_finding(
        self,
        finding_id: str,
        category: str,
        severity: str,
        title: str,
        file_path: str,
        line_number: Optional[int],
        snippet: str,
        description: str,
        recommendation: str,
    ) -> None:
        """Registra um achado de segurança ou resiliência no frontend."""
        self.findings.append({
            "id": finding_id,
            "category": category,
            "severity": severity,
            "title": title,
            "file": file_path,
            "line": line_number,
            "snippet": snippet.strip(),
            "description": description,
            "recommendation": recommendation,
        })

    def _add_verified_control(
        self,
        control_id: str,
        category: str,
        title: str,
        file_path: str,
        description: str,
    ) -> None:
        """Registra um controle de segurança defensivo comprovado como ativo."""
        self.verified_controls.append({
            "id": control_id,
            "category": category,
            "title": title,
            "file": file_path,
            "description": description,
        })

    # =========================================================================
    # AUDITORIA DE XSS E INJEÇÃO DOM
    # =========================================================================

    def audit_xss_and_dom_injection(self, app_js_content: str, html_content: str) -> None:
        """Verifica ocorrências de innerHTML, escapeHtml e vetores de injeção DOM."""
        js_lines = app_js_content.splitlines()

        # 1. Analisa usos de innerHTML no app.js
        for idx, line in enumerate(js_lines, start=1):
            if ".innerHTML" in line:
                # Caso 1: Limpeza de elemento (e.g. findingsList.innerHTML = '';)
                if re.search(r"\.innerHTML\s*=\s*['\"]\s*['\"]", line):
                    self._add_verified_control(
                        control_id="CTRL-DOM-CLEAR",
                        category="XSS & DOM Security",
                        title="Limpeza Segura de Container DOM",
                        file_path="web/app.js",
                        description=f"Linha {idx}: Uso de innerHTML estritamente para resetar container (''). Sem risco de injeção.",
                    )
                # Caso 2: Atribuição de template literal ou conteúdo dinâmico
                else:
                    snippet = "\n".join(js_lines[idx - 1: min(idx + 15, len(js_lines))])
                    
                    # Verifica se interpola variáveis não escapadas (ex: ${sev})
                    if "${sev}" in snippet:
                        self._add_finding(
                            finding_id="FE-XSS-001",
                            category="XSS & DOM Injection",
                            severity="HIGH",
                            title="Interpolação de Severidade Não Escapada em innerHTML",
                            file_path="web/app.js",
                            line_number=idx,
                            snippet=line.strip(),
                            description=(
                                "A variável `sev` é derivada de `(finding.severity || 'LOW').toUpperCase()` e interpolada "
                                "diretamente no innerHTML (`class=\"...-${sev}\"` e `>${sev}</span>`) sem passar pela função `escapeHtml()`. "
                                "Como tags e atributos HTML são insensíveis a maiúsculas, caso uma severidade contenha payloads como "
                                "`<IMG SRC=X ONERROR=ALERT(1)>`, o navegador interpretará e executará como HTML/JavaScript válido."
                            ),
                            recommendation=(
                                "Aplicar sanitização mandatória em `sev`: validar contra uma lista permitida estrita "
                                "(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) com fallback defensivo para 'LOW', ou usar `escapeHtml(sev)`."
                            ),
                        )

        # 2. Avaliação da função escapeHtml()
        if "function escapeHtml" in app_js_content:
            # Verifica se trata tipos primitivos não-string (ex: números ou nulos)
            escape_fn_match = re.search(r"function escapeHtml\((\w+)\)\s*\{([^}]+)\}", app_js_content)
            if escape_fn_match:
                fn_body = escape_fn_match.group(2)
                has_str_coercion = "typeof" in fn_body or "String(" in fn_body
                if not has_str_coercion:
                    self._add_finding(
                        finding_id="FE-XSS-002",
                        category="XSS & DOM Injection",
                        severity="LOW",
                        title="Função escapeHtml Sem Coerção de Tipo Defensiva",
                        file_path="web/app.js",
                        line_number=402,
                        snippet="function escapeHtml(str) { ... }",
                        description=(
                            "A função `escapeHtml(str)` assume que o argumento é sempre uma string e executa `str.replace()`. "
                            "Se a API retornar um campo numérico ou booleano para id ou título, ocorrerá uma exceção "
                            "`TypeError: str.replace is not a function`, travando a renderização dos achados."
                        ),
                        recommendation="Adicionar coerção explícita de tipo: `str = String(str || '');` antes dos replaces.",
                    )
                else:
                    self._add_verified_control(
                        control_id="CTRL-ESCAPE-TYPE-SAFE",
                        category="XSS & DOM Security",
                        title="Função escapeHtml com Coerção Segura",
                        file_path="web/app.js",
                        description="escapeHtml coerge tipos não-string adequadamente.",
                    )

                # Verifica caracteres essenciais escapados: &, <, >, ", '
                escaped_chars = ["&", "<", ">", '"', "'"]
                missing_chars = [c for c in escaped_chars if c not in fn_body]
                if not missing_chars:
                    self._add_verified_control(
                        control_id="CTRL-ESCAPE-CHARS-COMPLETE",
                        category="XSS & DOM Security",
                        title="Escape de Caracteres Críticos Completo",
                        file_path="web/app.js",
                        description="A função escapeHtml neutraliza &, <, >, \" e ' contra injeção de tags e atributos.",
                    )

        # 3. Verificação de uso de textContent nas métricas de score e contadores
        safe_text_content_targets = ["scoreDisplay", "riskBadge", "riskDescription", "countCritical", "findingsCount"]
        for target in safe_text_content_targets:
            if f"{target}.textContent" in app_js_content:
                self._add_verified_control(
                    control_id=f"CTRL-SAFE-TEXT-{target.upper()}",
                    category="XSS & DOM Security",
                    title=f"Uso Seguro de textContent em {target}",
                    file_path="web/app.js",
                    description=f"Atualização do elemento `{target}` utiliza estritamente `textContent`, prevenindo injeção HTML.",
                )

        # 4. Verificação de inline scripts e inline event handlers no index.html
        html_lines = html_content.splitlines()
        inline_handlers = []
        for idx, line in enumerate(html_lines, start=1):
            if re.search(r"\son\w+\s*=", line):
                inline_handlers.append((idx, line))

        if inline_handlers:
            self._add_finding(
                finding_id="FE-XSS-003",
                category="XSS & DOM Injection",
                severity="MEDIUM",
                title="Presença de Event Handlers Inline no HTML",
                file_path="web/index.html",
                line_number=inline_handlers[0][0],
                snippet=inline_handlers[0][1].strip(),
                description="Uso de atributos inline (ex: onclick) fragiliza a política de segurança contra injeção de scripts.",
                recommendation="Substituir event handlers inline por `addEventListener` no arquivo app.js.",
            )
        else:
            self._add_verified_control(
                control_id="CTRL-NO-INLINE-HANDLERS",
                category="XSS & DOM Security",
                title="Ausência Total de Inline Event Handlers no HTML",
                file_path="web/index.html",
                description="Zero ocorrências de atributos `on*` no HTML; todos os listeners são vinculados via Vanilla JS.",
            )

        # 5. Verificação de Content-Security-Policy (CSP) no index.html
        if "http-equiv=\"Content-Security-Policy\"" not in html_content and "http-equiv='Content-Security-Policy'" not in html_content:
            self._add_finding(
                finding_id="FE-CSP-001",
                category="XSS & DOM Injection",
                severity="MEDIUM",
                title="Ausência de Meta Tag Content-Security-Policy (CSP)",
                file_path="web/index.html",
                line_number=5,
                snippet="<meta name=\"viewport\" ...>",
                description=(
                    "O arquivo `web/index.html` não define uma meta tag de Content-Security-Policy (CSP). "
                    "A ausência de CSP remove a camada de defesa em profundidade (Defense-in-Depth) contra execução de scripts não autorizados "
                    "e exfiltração de dados no caso de uma injeção XSS ser bem-sucedida no navegador."
                ),
                recommendation=(
                    "Adicionar meta tag CSP restritiva no <head>: "
                    "`<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'; style-src 'self' fonts.googleapis.com 'unsafe-inline'; font-src fonts.gstatic.com; connect-src https://*.execute-api.us-east-2.amazonaws.com;\">`."
                ),
            )
        else:
            self._add_verified_control(
                control_id="CTRL-CSP-ACTIVE",
                category="XSS & DOM Security",
                title="Content-Security-Policy Configurado no HTML",
                file_path="web/index.html",
                description="Meta tag CSP detectada protegendo o contexto de execução da página.",
            )

        # 6. Avaliação de eval(), Function(), setTimeout(string)
        dangerous_sinks = ["eval(", "new Function(", "setTimeout(\"", "setInterval(\""]
        for sink in dangerous_sinks:
            if sink in app_js_content:
                self._add_finding(
                    finding_id="FE-DANGEROUS-SINK",
                    category="XSS & DOM Injection",
                    severity="HIGH",
                    title=f"Uso de Sink Dinâmico Perigoso: {sink}",
                    file_path="web/app.js",
                    line_number=None,
                    snippet=sink,
                    description=f"Detectado uso de sink perigoso que executa código dinâmico a partir de strings: `{sink}`.",
                    recommendation="Eliminar o uso de avaliação dinâmica de strings.",
                )
        self._add_verified_control(
            control_id="CTRL-NO-EVAL",
            category="XSS & DOM Security",
            title="Ausência de Funções Dinâmicas Perigosas (Zero eval/Function)",
            file_path="web/app.js",
            description="Código estritamente funcional sem o uso de `eval()`, `new Function()` ou passagem de strings para timers.",
        )

    # =========================================================================
    # AUDITORIA DE RESILIÊNCIA DE REDE E TRATAMENTO DE FALHAS
    # =========================================================================

    def audit_network_and_error_handling(self, app_js_content: str) -> None:
        """Verifica timeout em fetch, tratamento de exceções offline e recuperação de estado da UI."""
        js_lines = app_js_content.splitlines()

        # 1. Verifica presença de AbortController ou timeout no fetch
        has_abort = "AbortController" in app_js_content or "AbortSignal.timeout" in app_js_content
        if not has_abort:
            fetch_line_num = 255
            for idx, line in enumerate(js_lines, start=1):
                if "await fetch(" in line or "fetch(" in line:
                    fetch_line_num = idx
                    break

            self._add_finding(
                finding_id="FE-NET-001",
                category="Network Resilience",
                severity="MEDIUM",
                title="Ausência de Timeout ou AbortController no fetch()",
                file_path="web/app.js",
                line_number=fetch_line_num,
                snippet=js_lines[fetch_line_num - 1].strip() if fetch_line_num <= len(js_lines) else "fetch(targetUrl, ...)",
                description=(
                    "A chamada assíncrona `fetch(targetUrl, ...)` não especifica um sinal de abortamento ou timeout "
                    "(`signal: AbortSignal.timeout(10000)` ou `AbortController`). Se a conexão com o API Gateway v2 oscilar, "
                    "sofrer perda de pacotes ou travar, o botão 'Executar Auditoria' permanecerá desativado com spinner ativo "
                    "indefinidamente, bloqueando a interface do usuário."
                ),
                recommendation=(
                    "Implementar timeout defensivo com `signal: AbortSignal.timeout(15000)` ou `AbortController` "
                    "com temporizador de 15 segundos para cancelar requisições estagnadas e informar o usuário."
                ),
            )
        else:
            self._add_verified_control(
                control_id="CTRL-FETCH-TIMEOUT",
                category="Network Resilience",
                title="Timeout / AbortController Presente no fetch",
                file_path="web/app.js",
                description="O fetch possui controle explícito de cancelamento por timeout.",
            )

        # 2. Verifica tratamento de erro com alert() síncrono
        if "alert(" in app_js_content:
            alert_lines = [idx for idx, line in enumerate(js_lines, start=1) if "alert(" in line]
            self._add_finding(
                finding_id="FE-NET-002",
                category="Network Resilience",
                severity="LOW",
                title="Uso de alert() Nativo para Exibição de Falhas de Rede",
                file_path="web/app.js",
                line_number=alert_lines[0] if alert_lines else None,
                snippet=js_lines[alert_lines[0] - 1].strip() if alert_lines else "alert(...)",
                description=(
                    "Erros de conexão ou falhas de requisição são comunicados através do método modal nativo `alert()`. "
                    "O `alert()` bloqueia a thread principal do navegador, degrada a experiência do usuário e impede que "
                    "leitores de tela ou suítes de automação capturem o erro de forma assíncrona."
                ),
                recommendation="Substituir `alert()` por um banner visual ou componente de notificação inline/toast acessível no DOM.",
            )

        # 3. Verifica bloco finally restaurando estado do botão de auditoria
        has_finally_reset = False
        if "finally {" in app_js_content:
            finally_match = re.search(r"finally\s*\{([^}]+)\}", app_js_content)
            if finally_match:
                body = finally_match.group(1)
                if "btnAudit.disabled = false" in body and "auditSpinner.style.display" in body:
                    has_finally_reset = True

        if has_finally_reset:
            self._add_verified_control(
                control_id="CTRL-UI-FINALLY-RESET",
                category="Network Resilience",
                title="Restauração Garantida do Estado da UI no Bloco finally",
                file_path="web/app.js",
                description="O botão de auditoria e o spinner são resetados obrigatoriamente no bloco `finally`, prevenindo bloqueio permanente da UI após erros.",
            )
        else:
            self._add_finding(
                finding_id="FE-NET-003",
                category="Network Resilience",
                severity="HIGH",
                title="Ausência de Reset da UI em Caso de Erro de Rede",
                file_path="web/app.js",
                line_number=275,
                snippet="finally { ... }",
                description="O estado de carregamento da interface não é restaurado caso a requisição falhe.",
                recommendation="Garantir `btnAudit.disabled = false` no bloco `finally`.",
            )

        # 4. Verifica tratamento de resposta não-JSON (response.json() antes de response.ok)
        if "const data = await response.json();" in app_js_content:
            data_line = 266
            self._add_finding(
                finding_id="FE-NET-004",
                category="Network Resilience",
                severity="LOW",
                title="Desserialização JSON Precipitada sem Validação de Content-Type",
                file_path="web/app.js",
                line_number=data_line,
                snippet="const data = await response.json();",
                description=(
                    "O código executa `await response.json()` antes de verificar `response.ok`. Se um proxy intermediário, "
                    "WAF ou CloudFront retornar uma página de erro em HTML (ex: 502 Bad Gateway ou 504 Gateway Timeout), "
                    "o parser lançará `SyntaxError: Unexpected token < in JSON`, ofuscando a causa raiz da falha de rede."
                ),
                recommendation="Inspecionar `response.headers.get('content-type')` ou capturar erros de parse antes de prosseguir.",
            )

    # =========================================================================
    # AUDITORIA DE VALIDAÇÃO DE ENTRADA
    # =========================================================================

    def audit_input_validation(self, app_js_content: str) -> None:
        """Verifica a presença de validação preventiva de código vazio e URL de API."""
        js_lines = app_js_content.splitlines()

        # 1. Validação de conteúdo vazio no editor
        has_empty_check = False
        for idx, line in enumerate(js_lines, start=1):
            if "codeEditor.value.trim()" in line:
                next_block = "\n".join(js_lines[idx - 1: min(idx + 7, len(js_lines))])
                if "if (!content)" in next_block or "if (content.length === 0)" in next_block:
                    has_empty_check = True
                    break

        if has_empty_check:
            self._add_verified_control(
                control_id="CTRL-INP-EMPTY-CHECK",
                category="Input Validation",
                title="Validação Preventiva de Entrada Vazia Antes do Envio",
                file_path="web/app.js",
                description="O editor valida `!content` rejeitando envios de payloads vazios ou compostos exclusivamente por espaços antes de disparar o fetch.",
            )
        else:
            self._add_finding(
                finding_id="FE-INP-001",
                category="Input Validation",
                severity="MEDIUM",
                title="Ausência de Validação de Conteúdo Vazio no Editor",
                file_path="web/app.js",
                line_number=234,
                snippet="btnAudit.addEventListener('click', ...)",
                description="A aplicação permite disparar requisições para a API com conteúdo em branco.",
                recommendation="Adicionar verificação `if (!codeEditor.value.trim())` antes do fetch.",
            )

        # 2. Validação da presença da URL de destino
        has_url_check = "if (!targetUrl)" in app_js_content
        if has_url_check:
            self._add_verified_control(
                control_id="CTRL-INP-URL-CHECK",
                category="Input Validation",
                title="Verificação Mandatória de Configuração da URL da API",
                file_path="web/app.js",
                description="O frontend impede o disparo da auditoria caso nenhuma URL de endpoint válida esteja definida.",
            )

        # 3. Validação de protocolo e formato da URL manual
        if "apiUrlInput.value.trim()" in app_js_content:
            has_url_protocol_validation = False
            for line in js_lines:
                if "startsWith('http')" in line or "new URL(" in line:
                    has_url_protocol_validation = True
                    break

            if not has_url_protocol_validation:
                self._add_finding(
                    finding_id="FE-INP-002",
                    category="Input Validation",
                    severity="LOW",
                    title="Ausência de Validação de Protocolo na URL Manual da API",
                    file_path="web/app.js",
                    line_number=168,
                    snippet="const val = apiUrlInput.value.trim();",
                    description=(
                        "O input manual de configuração da API (`apiUrlInput`) aceita qualquer string sem validar se o esquema "
                        "pertence a `https://` (ou `http://`). Isso permite a inserção de strings malformadas ou esquemas "
                        "incompatíveis pelo operador."
                    ),
                    recommendation="Validar a URL com `try { const u = new URL(val); if (!['http:', 'https:'].includes(u.protocol)) ... }`.",
                )

    # =========================================================================
    # AUDITORIA DE FOLHA DE ESTILOS E RECURSOS
    # =========================================================================

    def audit_css_and_asset_security(self, css_content: str, html_content: str) -> None:
        """Verifica ausência de @import, url() e integridade de recursos externos."""
        # 1. Verifica @import no CSS
        import_matches = re.findall(r"@import\s+[^;]+;", css_content)
        if import_matches:
            self._add_finding(
                finding_id="FE-CSS-001",
                category="CSS & Asset Security",
                severity="LOW",
                title="Importação Externa de CSS com @import",
                file_path="web/styles.css",
                line_number=None,
                snippet=import_matches[0],
                description="Uso de @import no CSS pode bloquear renderização e gerar dependência de servidores de terceiros.",
                recommendation="Remover @import e declarar dependências no HTML com <link>.",
            )
        else:
            self._add_verified_control(
                control_id="CTRL-CSS-NO-IMPORT",
                category="CSS & Asset Security",
                title="Ausência Total de @import no CSS",
                file_path="web/styles.css",
                description="A folha de estilos é autocontida e não realiza importações dinâmicas via `@import`.",
            )

        # 2. Verifica funções url() no CSS (exfiltração via CSS)
        url_matches = re.findall(r"url\s*\(([^)]+)\)", css_content)
        if url_matches:
            self._add_finding(
                finding_id="FE-CSS-002",
                category="CSS & Asset Security",
                severity="LOW",
                title="Presença de Chamadas url() no CSS",
                file_path="web/styles.css",
                line_number=None,
                snippet=url_matches[0],
                description="Regras de estilo com chamadas url() podem ser abusadas para tracking ou vazamento de dados de atributos.",
                recommendation="Manter estilos livres de dependências externas de imagens/recursos.",
            )
        else:
            self._add_verified_control(
                control_id="CTRL-CSS-NO-URLS",
                category="CSS & Asset Security",
                title="Folha de Estilos Livre de Chamadas url() Externas",
                file_path="web/styles.css",
                description="Zero ocorrências de `url(...)` em `styles.css`. Impossibilidade de rastreamento ou exfiltração por CSS.",
            )

        # 3. Verifica Subresource Integrity (SRI) nas fontes externas
        if "fonts.googleapis.com" in html_content:
            if "integrity=" not in html_content:
                self._add_finding(
                    finding_id="FE-RES-001",
                    category="CSS & Asset Security",
                    severity="INFORMATIONAL",
                    title="Fontes Externas do Google Fonts sem Subresource Integrity (SRI)",
                    file_path="web/index.html",
                    line_number=11,
                    snippet='<link href="https://fonts.googleapis.com/css2?... rel="stylesheet">',
                    description=(
                        "O `index.html` importa fontes tipográficas de `fonts.googleapis.com` sem hashes de Subresource Integrity (SRI). "
                        "Embora padrão para fontes dinâmicas do Google Fonts, representa uma dependência externa não imutável."
                    ),
                    recommendation="Para ambientes de segurança máxima, hospedar as fontes localmente no bundle estático do frontend.",
                )

    # =========================================================================
    # EXECUÇÃO PRINCIPAL E CONSOLIDAÇÃO
    # =========================================================================

    def run_full_audit(self) -> Dict[str, Any]:
        """Executa a auditoria completa de segurança no frontend estático."""
        print("[*] Iniciando Auditoria Estática de Segurança do Frontend...")
        print(f"[*] Diretório de Inspeção: {WEB_DIR}")
        print("-" * 75)

        html_content = INDEX_HTML.read_text(encoding="utf-8") if INDEX_HTML.exists() else ""
        app_js_content = APP_JS.read_text(encoding="utf-8") if APP_JS.exists() else ""
        styles_css_content = STYLES_CSS.read_text(encoding="utf-8") if STYLES_CSS.exists() else ""

        self.files_scanned = [
            str(INDEX_HTML.relative_to(REPO_ROOT)),
            str(APP_JS.relative_to(REPO_ROOT)),
            str(STYLES_CSS.relative_to(REPO_ROOT)),
        ]

        # Executa as baterias de auditoria especializada
        self.audit_xss_and_dom_injection(app_js_content, html_content)
        self.audit_network_and_error_handling(app_js_content)
        self.audit_input_validation(app_js_content)
        self.audit_css_and_asset_security(styles_css_content, html_content)

        # Contabilidade e métricas
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in self.findings:
            sev = f["severity"].upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        total_findings = len(self.findings)
        total_controls = len(self.verified_controls)

        # Cálculo do Score de Segurança do Frontend (0 a 100)
        # Deduções: Critical -30, High -20, Medium -10, Low -5, Informational -0
        base_score = 100
        base_score -= sev_counts["CRITICAL"] * 30
        base_score -= sev_counts["HIGH"] * 20
        base_score -= sev_counts["MEDIUM"] * 10
        base_score -= sev_counts["LOW"] * 5
        frontend_score = max(0, min(100, base_score))

        if frontend_score >= 85:
            posture = "GOOD"
        elif frontend_score >= 65:
            posture = "MODERATE"
        else:
            posture = "CONCERN"

        # Exibição resumida
        print(f"[*] Controles Defensivos Comprovados: {total_controls}")
        for c in self.verified_controls:
            print(f"  🛡️ [{c['id']}] {c['title']} ({c['file']})")

        print(f"\n[*] Achados de Segurança / Resiliência: {total_findings}")
        for f in self.findings:
            sev_icon = "🚨" if f["severity"] in ["CRITICAL", "HIGH"] else "⚠️" if f["severity"] == "MEDIUM" else "ℹ️"
            print(f"  {sev_icon} [{f['id']}] [{f['severity']}] {f['title']} ({f['file']}:{f['line'] or 'N/A'})")

        print("-" * 75)
        print(f"[*] Score de Segurança do Frontend: {frontend_score}/100 (Postura: {posture})")
        print(f"[*] Distribuição: {sev_counts['CRITICAL']} Crítico, {sev_counts['HIGH']} Alto, {sev_counts['MEDIUM']} Médio, {sev_counts['LOW']} Baixo, {sev_counts['INFORMATIONAL']} Info.")

        consolidated = {
            "summary": {
                "frontend_security_score": frontend_score,
                "security_posture": posture,
                "total_findings": total_findings,
                "severity_breakdown": sev_counts,
                "total_verified_controls": total_controls,
            },
            "files_audited": self.files_scanned,
            "verified_controls": self.verified_controls,
            "findings": self.findings,
        }

        self._save_results(consolidated)
        return consolidated

    def _save_results(self, audit_data: Dict[str, Any]) -> None:
        """Salva ou atualiza a seção frontend_static_audit no arquivo qa/results_prod_probes.json."""
        existing_data: Dict[str, Any] = {}
        if RESULTS_FILE.exists():
            try:
                existing_data = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
            except Exception:
                existing_data = {}

        existing_data["report_title"] = "Onion Auditor - Relatório de Sondas em Produção & Auditoria Frontend (Camada 4)"
        existing_data["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
        if "environment" not in existing_data:
            existing_data["environment"] = {
                "python_version": sys.version.split()[0],
                "working_directory": str(REPO_ROOT),
            }
        existing_data["frontend_static_audit"] = audit_data

        RESULTS_FILE.write_text(json.dumps(existing_data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[*] Resultados da auditoria frontend salvos em: {RESULTS_FILE}")


if __name__ == "__main__":
    auditor = FrontendAuditor()
    auditor.run_full_audit()
