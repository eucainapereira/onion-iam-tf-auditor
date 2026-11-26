/**
 * Onion Auditor - Client-side Logic (Vanilla JavaScript)
 * Zero frameworks, FinOps Scale-to-Zero frontend.
 * Hardened with Anti-XSS, AbortController timeouts, and accessible visual alerts.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const codeEditor = document.getElementById('codeEditor');
  const tabIam = document.getElementById('tabIam');
  const tabTf = document.getElementById('tabTf');
  const btnSampleIam = document.getElementById('btnSampleIam');
  const btnSampleTf = document.getElementById('btnSampleTf');
  const btnClear = document.getElementById('btnClear');
  const btnAudit = document.getElementById('btnAudit');
  const btnAuditText = document.getElementById('btnAuditText');
  const auditSpinner = document.getElementById('auditSpinner');

  const editorLangIndicator = document.getElementById('editorLangIndicator');
  const editorStats = document.getElementById('editorStats');

  const apiStatusIndicator = document.getElementById('apiStatusIndicator');
  const apiStatusText = document.getElementById('apiStatusText');
  const apiConfigBanner = document.getElementById('apiConfigBanner');
  const apiUrlInput = document.getElementById('apiUrlInput');
  const btnSaveApiUrl = document.getElementById('btnSaveApiUrl');

  const alertBanner = document.getElementById('alertBanner');
  const alertIcon = document.getElementById('alertIcon');
  const alertTitle = document.getElementById('alertTitle');
  const alertMessage = document.getElementById('alertMessage');
  const btnAlertClose = document.getElementById('btnAlertClose');

  const emptyState = document.getElementById('emptyState');
  const auditDashboard = document.getElementById('auditDashboard');
  const resultsStatusBadge = document.getElementById('resultsStatusBadge');

  const scoreDisplay = document.getElementById('scoreDisplay');
  const scoreCircleProgress = document.getElementById('scoreCircleProgress');
  const scoreStatusDesc = document.getElementById('scoreStatusDesc');
  const riskBadge = document.getElementById('riskBadge');
  const riskDescription = document.getElementById('riskDescription');

  const countCritical = document.getElementById('countCritical');
  const countHigh = document.getElementById('countHigh');
  const countMedium = document.getElementById('countMedium');
  const countLow = document.getElementById('countLow');
  const findingsCount = document.getElementById('findingsCount');
  const findingsList = document.getElementById('findingsList');
  const perfectBanner = document.getElementById('perfectBanner');

  // Whitelist of valid severity values against injection (QA-004)
  const ALLOWED_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

  // Application State
  let currentType = 'iam'; // 'iam' | 'terraform'
  let activeApiUrl = (typeof window.API_URL === 'string' && window.API_URL.trim()) ? window.API_URL.trim() : '';

  // Vulnerable Sample Templates
  const VULNERABLE_IAM_SAMPLE = JSON.stringify({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DangerousWildcardAdmin",
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      },
      {
        "Sid": "DangerousNotActionWithAllow",
        "Effect": "Allow",
        "NotAction": "iam:Delete*",
        "Resource": "*"
      },
      {
        "Sid": "UnrestrictedPassRolePrivEsc",
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "arn:aws:iam::123456789012:role/*"
      },
      {
        "Sid": "PublicResourcePolicyWildcardPrincipal",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::critical-finance-data/*"
      }
    ]
  }, null, 2);

  const VULNERABLE_TF_SAMPLE = `resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-web-sg"
  description = "Security Group com portas administrativas abertas para o mundo"

  # SSH aberto para a internet
  ingress {
    description = "SSH Irrestrito"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP aberto para a internet
  ingress {
    description = "RDP Irrestrito"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Banco PostgreSQL exposto
  ingress {
    description = "PostgreSQL Publico"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Banco MySQL exposto
  ingress {
    description = "MySQL Publico"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Bucket S3 com ACL pública e sem bloqueio público
resource "aws_s3_bucket" "public_bucket" {
  bucket = "empresa-documentos-publicos"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "disabled_block" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Volume EBS sem criptografia ativada
resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 200
  encrypted         = false
}

# Banco de dados RDS sem criptografia em repouso
resource "aws_db_instance" "unencrypted_rds" {
  allocated_storage = 50
  engine            = "mysql"
  instance_class    = "db.t3.large"
  storage_encrypted = false
}
`;

  // Accessible Notification System (replaces native blocking dialogs - QA-012)
  function showAlert(message, type = 'error', title = null) {
    if (!alertBanner || !alertMessage) return;

    const typeConfig = {
      error: {
        title: title || 'Erro na Requisição',
        icon: '🚨',
        className: 'alert-banner alert-error',
      },
      warning: {
        title: title || 'Atenção na Validação',
        icon: '⚠️',
        className: 'alert-banner alert-warning',
      },
      info: {
        title: title || 'Informação',
        icon: 'ℹ️',
        className: 'alert-banner alert-info',
      },
    };

    const config = typeConfig[type] || typeConfig.error;
    alertBanner.className = config.className;
    if (alertIcon) alertIcon.textContent = config.icon;
    if (alertTitle) alertTitle.textContent = config.title;
    alertMessage.textContent = message;
    alertBanner.style.display = 'flex';
    alertBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function hideAlert() {
    if (alertBanner) {
      alertBanner.style.display = 'none';
    }
  }

  if (btnAlertClose) {
    btnAlertClose.addEventListener('click', hideAlert);
  }

  // Initialize API Endpoint Status
  function checkApiStatus() {
    const dot = apiStatusIndicator.querySelector('.status-dot');
    if (activeApiUrl) {
      dot.className = 'status-dot connected';
      apiStatusText.textContent = 'API Conectada';
      apiConfigBanner.style.display = 'none';
    } else {
      dot.className = 'status-dot disconnected';
      apiStatusText.textContent = 'Endpoint Pendente';
      apiConfigBanner.style.display = 'block';
    }
  }

  if (btnSaveApiUrl) {
    btnSaveApiUrl.addEventListener('click', () => {
      const val = apiUrlInput.value.trim();
      if (!val) {
        showAlert('Por favor, informe a URL do endpoint.', 'warning', 'URL Obrigatória');
        return;
      }

      try {
        const parsedUrl = new URL(val);
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
          showAlert('Protocolo inválido. Apenas URLs HTTP ou HTTPS são permitidas.', 'warning', 'Protocolo Inválido');
          return;
        }
        activeApiUrl = parsedUrl.toString();
        window.API_URL = activeApiUrl;
        checkApiStatus();
        hideAlert();
      } catch (err) {
        showAlert('Formato de URL inválido. Certifique-se de incluir o protocolo (ex: https://...).', 'warning', 'URL Inválida');
      }
    });
  }

  // Update Stats and Language Indicator
  function updateStats() {
    const text = codeEditor.value;
    const chars = text.length;
    const lines = text ? text.split('\n').length : 0;
    editorStats.textContent = `${chars} caracteres | ${lines} linhas`;
  }

  codeEditor.addEventListener('input', updateStats);

  // Tab Selection
  function setAuditType(type) {
    currentType = type;
    if (type === 'iam') {
      tabIam.classList.add('active');
      tabTf.classList.remove('active');
      editorLangIndicator.textContent = 'JSON (IAM)';
      codeEditor.placeholder = 'Cole aqui sua política IAM em formato JSON...';
    } else {
      tabTf.classList.add('active');
      tabIam.classList.remove('active');
      editorLangIndicator.textContent = 'HCL (Terraform)';
      codeEditor.placeholder = 'Cole aqui seu manifesto Terraform HCL...';
    }
  }

  tabIam.addEventListener('click', () => setAuditType('iam'));
  tabTf.addEventListener('click', () => setAuditType('terraform'));

  // Load Samples
  btnSampleIam.addEventListener('click', () => {
    setAuditType('iam');
    codeEditor.value = VULNERABLE_IAM_SAMPLE;
    updateStats();
    hideAlert();
  });

  btnSampleTf.addEventListener('click', () => {
    setAuditType('terraform');
    codeEditor.value = VULNERABLE_TF_SAMPLE;
    updateStats();
    hideAlert();
  });

  btnClear.addEventListener('click', () => {
    codeEditor.value = '';
    updateStats();
    resetResults();
    hideAlert();
  });

  function resetResults() {
    emptyState.style.display = 'flex';
    auditDashboard.style.display = 'none';
    resultsStatusBadge.textContent = 'Aguardando Análise';
    resultsStatusBadge.className = 'results-badge';
  }

  // Audit Execution with 15s timeout via AbortController and strict input validation
  btnAudit.addEventListener('click', async () => {
    hideAlert();

    const content = codeEditor.value.trim();
    if (!content) {
      showAlert('Por favor, insira o código IAM ou Terraform a ser auditado.', 'warning', 'Conteúdo Obrigatório');
      codeEditor.focus();
      return;
    }

    // Defensive payload size validation against FinOps DoS (max 512 KB)
    const MAX_PAYLOAD_BYTES = 512 * 1024;
    const payloadBytes = new Blob([content]).size;
    if (payloadBytes > MAX_PAYLOAD_BYTES) {
      const sizeKb = (payloadBytes / 1024).toFixed(1);
      showAlert(`O código inserido possui ${sizeKb} KB e excede o limite máximo permitido de 512 KB. Reduza o volume do documento para prosseguir.`, 'warning', 'Payload Excessivo (FinOps Guard)');
      return;
    }

    const targetUrl = activeApiUrl || window.API_URL;
    if (!targetUrl) {
      showAlert('URL da API não configurada. Por favor, insira a URL do endpoint no banner superior.', 'warning', 'Endpoint Não Configurado');
      apiConfigBanner.style.display = 'block';
      apiUrlInput.focus();
      return;
    }

    // AbortController for explicit 15-second timeout (QA-009)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, 15000);

    // Set UI loading state
    btnAudit.disabled = true;
    auditSpinner.style.display = 'inline-block';
    btnAuditText.textContent = 'Analisando Vulnerabilidades...';

    try {
      const response = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: currentType,
          content: content,
        }),
        signal: controller.signal,
      });

      // Validates Content-Type header before JSON deserialization (QA-013)
      let data = null;
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        try {
          data = await response.json();
        } catch (parseErr) {
          const err = new Error(`Falha ao decodificar resposta JSON do servidor: ${parseErr.message}`);
          err.status = response.status;
          throw err;
        }
      } else {
        const rawText = await response.text();
        const snippet = rawText ? rawText.slice(0, 150) : '';
        const err = new Error(`Resposta com formato inesperado (Content-Type: ${contentType || 'indefinido'}, HTTP ${response.status}): ${snippet}`);
        err.status = response.status;
        throw err;
      }

      if (!response.ok) {
        const status = response.status;
        const apiError = (data && typeof data.error === 'string')
          ? data.error
          : (data && data.message)
            ? String(data.message)
            : `Erro HTTP ${status}`;
        const err = new Error(apiError);
        err.status = status;
        throw err;
      }

      renderAuditResults(data);
    } catch (err) {
      if (err.name === 'AbortError') {
        showAlert('A requisição excedeu o tempo limite defensivo de 15 segundos. O backend serverless pode estar em cold-start ou inacessível.', 'error', 'Tempo Limite Excedido (Timeout 15s)');
      } else if (err.status === 400) {
        showAlert(`Requisição inválida (HTTP 400): ${err.message}`, 'error', 'Erro 400 — Bad Request');
      } else if (err.status === 413) {
        showAlert('O payload enviado excede o limite máximo permitido pelo servidor (HTTP 413 Payload Too Large / máx. 512 KB).', 'error', 'Erro 413 — Payload Too Large');
      } else if (err.status === 429) {
        showAlert('Limite de requisições por segundo excedido (HTTP 429 Too Many Requests). Aguarde alguns segundos antes de tentar novamente.', 'warning', 'Erro 429 — Rate Limit Excedido');
      } else if (err.status && err.status >= 500) {
        showAlert(`Falha interna no serviço (HTTP ${err.status}): ${err.message}`, 'error', `Erro ${err.status} — Falha no Servidor`);
      } else if (err.status && err.status >= 400) {
        showAlert(`Erro na requisição (HTTP ${err.status}): ${err.message}`, 'error', `Erro ${err.status} — Falha na Requisição`);
      } else {
        showAlert(`Falha de comunicação ou rede: ${err.message}`, 'error', 'Erro de Conexão');
      }
    } finally {
      clearTimeout(timeoutId);
      btnAudit.disabled = false;
      auditSpinner.style.display = 'none';
      btnAuditText.textContent = 'Executar Auditoria de Segurança';
    }
  });

  // Render Findings and Metrics
  function renderAuditResults(result) {
    emptyState.style.display = 'none';
    auditDashboard.style.display = 'flex';

    const { score, risk_level, findings } = result;

    const rawRisk = String(risk_level || 'LOW').toUpperCase().trim();
    const safeRiskLevel = ALLOWED_SEVERITIES.has(rawRisk) ? rawRisk : 'LOW';

    // Update Results Status Badge
    resultsStatusBadge.textContent = `Concluído: ${safeRiskLevel}`;
    resultsStatusBadge.className = `results-badge risk-${safeRiskLevel.toLowerCase()}`;

    // Animate Circular Score
    animateScore(typeof score === 'number' ? score : 0);

    // Update Risk Badge & Description
    riskBadge.textContent = safeRiskLevel;
    riskBadge.className = `risk-badge risk-${safeRiskLevel.toLowerCase()}`;

    const riskDescriptions = {
      CRITICAL: 'Ação imediata requerida. Presença de wildcards globais ou exposição pública crítica.',
      HIGH: 'Risco elevado. Permissões amplas ou ausência de controles essenciais de segurança.',
      MEDIUM: 'Risco moderado. Desvio de boas práticas e ausência de restrições contextuais.',
      LOW: 'Baixo risco. Código aderente aos princípios de menor privilégio e DevSecOps.',
    };
    riskDescription.textContent = riskDescriptions[safeRiskLevel] || '';

    // Count severities
    let criticals = 0;
    let highs = 0;
    let mediums = 0;
    let lows = 0;

    const safeFindingsList = Array.isArray(findings)
      ? findings.filter(f => f && typeof f === 'object')
      : [];

    safeFindingsList.forEach(f => {
      const itemSev = String(f.severity || '').toUpperCase().trim();
      if (itemSev === 'CRITICAL') criticals++;
      else if (itemSev === 'HIGH') highs++;
      else if (itemSev === 'MEDIUM') mediums++;
      else if (itemSev === 'LOW') lows++;
    });

    countCritical.textContent = criticals;
    countHigh.textContent = highs;
    countMedium.textContent = mediums;
    countLow.textContent = lows;
    findingsCount.textContent = safeFindingsList.length;

    // Toggle Perfect Banner vs Findings List
    if (safeFindingsList.length === 0) {
      perfectBanner.style.display = 'flex';
      findingsList.innerHTML = '';
    } else {
      perfectBanner.style.display = 'none';
      renderFindingsList(safeFindingsList);
    }
  }

  function animateScore(targetScore) {
    const duration = 800;
    const startTime = performance.now();
    const circumference = 2 * Math.PI * 50; // r=50 -> 314.16

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const currentVal = Math.round(progress * targetScore);

      scoreDisplay.textContent = currentVal;

      // Stroke dashoffset: 314.16 is empty (0), 0 is full (100)
      const offset = circumference - (currentVal / 100) * circumference;
      scoreCircleProgress.style.strokeDashoffset = offset;

      // Color progress based on score
      if (currentVal < 40) {
        scoreCircleProgress.style.stroke = 'var(--color-critical)';
        scoreStatusDesc.textContent = 'Reprovado / Crítico';
      } else if (currentVal < 70) {
        scoreCircleProgress.style.stroke = 'var(--color-high)';
        scoreStatusDesc.textContent = 'Atenção Necessária';
      } else if (currentVal < 90) {
        scoreCircleProgress.style.stroke = 'var(--color-medium)';
        scoreStatusDesc.textContent = 'Boas Práticas Parciais';
      } else {
        scoreCircleProgress.style.stroke = 'var(--color-low)';
        scoreStatusDesc.textContent = 'Em Conformidade';
      }

      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }

    requestAnimationFrame(update);
  }

  // Strict Anti-XSS Rendering of Findings (QA-004)
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

  // Type-coerced Defensive HTML Escape Function (QA-011)
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initial check
  checkApiStatus();
  updateStats();
});
