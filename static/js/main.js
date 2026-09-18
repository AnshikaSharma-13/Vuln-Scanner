// ── SIDEBAR TOGGLE ──
const sidebar     = document.getElementById('sidebar');
const mainWrapper = document.getElementById('mainWrapper');
const toggle      = document.getElementById('sidebarToggle');

if (toggle) {
  toggle.addEventListener('click', () => {
    if (window.innerWidth <= 768) {
      sidebar.classList.toggle('open');
    } else {
      sidebar.classList.toggle('hidden');
      mainWrapper.classList.toggle('collapsed');
    }
  });
}

// ── SCAN ENGINE ──
function initScanner(scanType) {
  const form       = document.getElementById('scanForm');
  const urlInput   = document.getElementById('urlInput');
  const scanBtn    = document.getElementById('scanBtn');
  const scanBar    = document.getElementById('scanBar');
  const terminal   = document.getElementById('terminal');
  const resultCard = document.getElementById('resultCard');
  const resultText = document.getElementById('resultText');
  const resultSev  = document.getElementById('resultSev');
  const dlBtn      = document.getElementById('downloadBtn');

  if (!form) return;

  let lastScanId = null;

  function typeIn(el, text, delay = 18) {
    const lines = text.split('\n');
    let i = 0;
    el.textContent = '';
    function nextLine() {
      if (i < lines.length) {
        const line = lines[i++];
        const colorized = colorize(line);
        el.innerHTML += colorized + '\n';
        el.scrollTop = el.scrollHeight;
        setTimeout(nextLine, delay);
      }
    }
    nextLine();
  }

  function colorize(line) {
    const esc = line.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (esc.startsWith('✓') || esc.includes('OPEN') || esc.includes('Safe'))
      return `<span class="t-ok">${esc}</span>`;
    if (esc.startsWith('✗') || esc.includes('MISSING') || esc.includes('WARNING'))
      return `<span class="t-warn">${esc}</span>`;
    if (esc.includes('VULNERABLE') || esc.includes('ERROR') || esc.includes('injection'))
      return `<span class="t-prompt">${esc}</span>`;
    if (esc.startsWith('Target:') || esc.startsWith('Server:') || esc.startsWith('INFO'))
      return `<span class="t-info">${esc}</span>`;
    return esc;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    // Reset UI
    scanBtn.disabled = true;
    scanBar.classList.add('active');
    terminal.textContent = `> Initializing ${scanType.toUpperCase()} scan...\n> Target: ${url}\n> Please wait...\n`;
    resultCard.className = 'result-card';
    if (dlBtn) dlBtn.style.display = 'none';

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, scan_type: scanType })
      });
      const data = await resp.json();

      if (data.error) {
        terminal.textContent += `\n> ERROR: ${data.error}\n`;
        return;
      }

      lastScanId = data.id;

      // show terminal output
      typeIn(terminal, `> Scan complete [${data.scanned_at}]\n\n${data.raw_details}`);

      // show result card
      setTimeout(() => {
        const sev = data.severity;
        resultCard.className = `result-card show ${sev}`;
        resultSev.innerHTML  = `<span class="badge sev-${sev} me-2">${sev.toUpperCase()}</span>`;
        resultText.textContent = data.findings;
        if (dlBtn) {
          dlBtn.style.display = 'inline-flex';
          dlBtn.href = `/scan/${data.id}/pdf`;
        }
        addToLocalHistory(scanType, url, sev, data.findings, data.id);
      }, 300);

    } catch (err) {
      terminal.textContent += `\n> FATAL: ${err.message}\n`;
    } finally {
      scanBtn.disabled = false;
      scanBar.classList.remove('active');
    }
  });
}

function addToLocalHistory(scanType, url, sev, findings, id) {
  const tbody = document.getElementById('liveHistory');
  if (!tbody) return;
  const row = document.createElement('tr');
  const now = new Date().toLocaleString();
  row.innerHTML = `
    <td>${now}</td>
    <td class="text-truncate" style="max-width:180px" title="${url}">${url}</td>
    <td><span class="badge sev-${sev}">${sev.toUpperCase()}</span></td>
    <td class="text-truncate" style="max-width:200px">${findings}</td>
    <td><a href="/scan/${id}/pdf" class="btn btn-danger-outline btn-sm"><i class="bi bi-download me-1"></i>PDF</a></td>`;
  tbody.prepend(row);
}

// ── CHART LOADER ──
function loadChart(endpoint, severityChartId, typeChartId) {
  fetch(endpoint)
    .then(r => r.json())
    .then(data => {
      // Severity doughnut
      const sevCtx = document.getElementById(severityChartId);
      if (sevCtx) {
        new Chart(sevCtx, {
          type: 'doughnut',
          data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
              data: [data.high, data.medium, data.low],
              backgroundColor: ['#dc3545','#fd7e14','#20c997'],
              borderColor: '#0d1520',
              borderWidth: 3,
              hoverOffset: 8
            }]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
              legend: { position: 'bottom', labels: { color: '#8faac8', padding: 16, font: { family: 'Share Tech Mono', size: 11 } } }
            },
            cutout: '68%'
          }
        });
      }

      // Type bar chart
      const typeCtx = document.getElementById(typeChartId);
      if (typeCtx && data.by_type) {
        new Chart(typeCtx, {
          type: 'bar',
          data: {
            labels: ['Port', 'XSS', 'Header', 'SQLi'],
            datasets: [{
              label: 'Scans',
              data: [data.by_type.port, data.by_type.xss, data.by_type.header, data.by_type.sqli],
              backgroundColor: ['#0d6efd','#e63946','#20c997','#fd7e14'],
              borderRadius: 6,
              borderSkipped: false
            }]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { ticks: { color: '#8faac8', font: { family: 'Share Tech Mono' } }, grid: { color: '#1e3050' } },
              y: { ticks: { color: '#8faac8', font: { family: 'Share Tech Mono' } }, grid: { color: '#1e3050' }, beginAtZero: true }
            }
          }
        });
      }
    })
    .catch(console.error);
}
