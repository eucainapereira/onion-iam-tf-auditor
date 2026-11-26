/**
 * Onion Auditor - Client-side Logic (Vanilla JavaScript)
 * Zero frameworks, FinOps Scale-to-Zero frontend.
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
      if (val) {
        activeApiUrl = val;
        window.API_URL = val;
        checkApiStatus();
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
  });

  btnSampleTf.addEventListener('click', () => {
    setAuditType('terraform');
    codeEditor.value = VULNERABLE_TF_SAMPLE;
    updateStats();
  });

  btnClear.addEventListener('click', () => {
    codeEditor.value = '';
    updateStats();
    resetResults();
  });

  function resetResults() {
    emptyState.style.display = 'flex';
    auditDashboard.style.display = 'none';
    resultsStatusBadge.textContent = 'Aguardando Análise';
    resultsStatusBadge.className = 'results-badge';
  }

  // Audit Execution
  btnAudit.addEventListener('click', async () => {
    const content = codeEditor.value.trim();
    if (!content) {
      alert('Por favor, insira o código IAM ou Terraform a ser auditado.');
      codeEditor.focus();
      return;
    }

    const targetUrl = activeApiUrl || window.API_URL;
    if (!targetUrl) {
      alert('URL da API não configurada. Por favor, insira a URL do endpoint no topo da página.');
      apiConfigBanner.style.display = 'block';
      apiUrlInput.focus();
      return;
    }

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
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Erro HTTP ${response.status}`);
      }

      renderAuditResults(data);
    } catch (err) {
      alert(`Falha na requisição de auditoria: ${err.message}`);
    } finally {
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

    // Update Results Status Badge
    resultsStatusBadge.textContent = `Concluído: ${risk_level}`;
    resultsStatusBadge.className = `results-badge risk-${risk_level.toLowerCase()}`;

    // Animate Circular Score
    animateScore(score);

    // Update Risk Badge & Description
    riskBadge.textContent = risk_level;
    riskBadge.className = `risk-badge risk-${risk_level.toLowerCase()}`;

    const riskDescriptions = {
      CRITICAL: 'Ação imediata requerida. Presença de wildcards globais ou exposição pública crítica.',
      HIGH: 'Risco elevado. Permissões amplas ou ausência de controles essenciais de segurança.',
      MEDIUM: 'Risco moderado. Desvio de boas práticas e ausência de restrições contextuais.',
      LOW: 'Baixo risco. Código aderente aos princípios de menor privilégio e DevSecOps.',
    };
    riskDescription.textContent = riskDescriptions[risk_level] || '';

    // Count severities
    let criticals = 0;
    let highs = 0;
    let mediums = 0;
    let lows = 0;

    findings.forEach(f => {
      const sev = (f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') criticals++;
      else if (sev === 'HIGH') highs++;
      else if (sev === 'MEDIUM') mediums++;
      else if (sev === 'LOW') lows++;
    });

    countCritical.textContent = criticals;
    countHigh.textContent = highs;
    countMedium.textContent = mediums;
    countLow.textContent = lows;
    findingsCount.textContent = findings.length;

    // Toggle Perfect Banner vs Findings List
    if (findings.length === 0) {
      perfectBanner.style.display = 'flex';
      findingsList.innerHTML = '';
    } else {
      perfectBanner.style.display = 'none';
      renderFindingsList(findings);
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

  function renderFindingsList(findings) {
    findingsList.innerHTML = '';

    findings.forEach(finding => {
      const card = document.createElement('div');
      const sev = (finding.severity || 'LOW').toUpperCase();
      card.className = `finding-card severity-${sev}`;

      card.innerHTML = `
        <div class="finding-card-header">
          <span class="finding-id-badge">${escapeHtml(finding.id)}</span>
          <span class="finding-severity-badge severity-badge-${sev}">${sev}</span>
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

  function escapeHtml(str) {
    if (!str) return '';
    return str
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
