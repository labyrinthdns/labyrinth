package main

// dashboardHTML contains the embedded single-page dashboard for the coordinator.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Labyrinth DNS Benchmark</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0a0e1a;
    color: #e0e0e0;
    min-height: 100vh;
  }
  .header {
    background: linear-gradient(135deg, #0d1326 0%, #1a1f3a 100%);
    border-bottom: 2px solid #c9a84c;
    padding: 18px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .header h1 {
    color: #c9a84c;
    font-size: 22px;
    font-weight: 600;
    letter-spacing: 1px;
  }
  .header .status {
    font-size: 13px;
    color: #8892b0;
  }
  .header .status .dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    background: #4caf50;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  .container { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }

  /* Metric cards */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .metric-card {
    background: #111730;
    border: 1px solid #1e2845;
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
  }
  .metric-card .label {
    font-size: 11px;
    text-transform: uppercase;
    color: #8892b0;
    letter-spacing: 1px;
    margin-bottom: 6px;
  }
  .metric-card .value {
    font-size: 28px;
    font-weight: 700;
    color: #c9a84c;
  }
  .metric-card .unit {
    font-size: 13px;
    color: #8892b0;
    margin-left: 4px;
  }
  .metric-card.green .value { color: #4caf50; }
  .metric-card.yellow .value { color: #ffc107; }
  .metric-card.red .value { color: #f44336; }

  /* Charts */
  .charts-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 24px;
  }
  .chart-card {
    background: #111730;
    border: 1px solid #1e2845;
    border-radius: 8px;
    padding: 16px;
  }
  .chart-card h3 {
    font-size: 13px;
    text-transform: uppercase;
    color: #8892b0;
    letter-spacing: 1px;
    margin-bottom: 12px;
  }
  .chart-card canvas {
    width: 100%;
    height: 200px;
  }

  /* Runner table */
  .table-card {
    background: #111730;
    border: 1px solid #1e2845;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
  }
  .table-card h3 {
    font-size: 13px;
    text-transform: uppercase;
    color: #8892b0;
    letter-spacing: 1px;
    margin-bottom: 12px;
  }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    text-transform: uppercase;
    color: #8892b0;
    border-bottom: 1px solid #1e2845;
    letter-spacing: 0.5px;
  }
  td {
    padding: 10px 12px;
    font-size: 14px;
    border-bottom: 1px solid #0d1326;
  }
  .status-dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    margin-right: 8px;
  }
  .status-dot.active { background: #4caf50; }
  .status-dot.stale { background: #f44336; }

  /* Histogram */
  .hist-bar-container {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 120px;
    padding-top: 8px;
  }
  .hist-bar-wrapper {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    height: 100%;
    justify-content: flex-end;
  }
  .hist-bar {
    width: 100%;
    background: linear-gradient(to top, #c9a84c, #e8cc6e);
    border-radius: 2px 2px 0 0;
    min-height: 1px;
    transition: height 0.3s;
  }
  .hist-label {
    font-size: 9px;
    color: #8892b0;
    margin-top: 4px;
    text-align: center;
    white-space: nowrap;
  }
  .hist-count {
    font-size: 9px;
    color: #c9a84c;
    margin-bottom: 2px;
  }

  .no-data {
    text-align: center;
    padding: 60px 20px;
    color: #8892b0;
    font-size: 16px;
  }

  @media (max-width: 768px) {
    .charts-row { grid-template-columns: 1fr; }
    .container { padding: 16px; }
  }
</style>
</head>
<body>
<div class="header">
  <h1>Labyrinth DNS Benchmark</h1>
  <div class="status"><span class="dot"></span><span id="statusText">Waiting for runners...</span></div>
</div>
<div class="container">
  <div class="metrics-grid" id="metricsGrid">
    <div class="metric-card"><div class="label">Total QPS</div><div class="value" id="mQPS">--</div></div>
    <div class="metric-card" id="mAvgCard"><div class="label">Avg Latency</div><div class="value" id="mAvg">--</div><div class="unit">ms</div></div>
    <div class="metric-card" id="mP50Card"><div class="label">P50 Latency</div><div class="value" id="mP50">--</div><div class="unit">ms</div></div>
    <div class="metric-card" id="mP95Card"><div class="label">P95 Latency</div><div class="value" id="mP95">--</div><div class="unit">ms</div></div>
    <div class="metric-card" id="mP99Card"><div class="label">P99 Latency</div><div class="value" id="mP99">--</div><div class="unit">ms</div></div>
    <div class="metric-card"><div class="label">Success Rate</div><div class="value green" id="mSuccess">--</div><div class="unit">%</div></div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>QPS Over Time</h3>
      <canvas id="qpsChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Latency Percentiles Over Time</h3>
      <canvas id="latChart" height="200"></canvas>
    </div>
  </div>

  <div class="chart-card" style="margin-bottom:24px">
    <h3>Latency Distribution</h3>
    <div class="hist-bar-container" id="histContainer">
      <div class="no-data">Waiting for data...</div>
    </div>
  </div>

  <div class="table-card">
    <h3>Runners</h3>
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>QPS</th>
          <th>Avg Latency</th>
          <th>P95 Latency</th>
          <th>Success</th>
          <th>Errors</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="runnersBody">
        <tr><td colspan="8" style="text-align:center;color:#8892b0;padding:30px">No runners connected</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
// Data stores for charts
const qpsSeries = [];
const latP50Series = [];
const latP95Series = [];
const latP99Series = [];
const maxPoints = 120;

function latencyColor(ms) {
  if (ms < 5) return 'green';
  if (ms < 50) return 'yellow';
  return 'red';
}

function setLatencyCard(cardId, valueId, ms) {
  const card = document.getElementById(cardId);
  const el = document.getElementById(valueId);
  el.textContent = ms.toFixed(1);
  card.className = 'metric-card ' + latencyColor(ms);
}

function drawChart(canvasId, datasets, labels) {
  const canvas = document.getElementById(canvasId);
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const w = rect.width;
  const h = rect.height;

  ctx.clearRect(0, 0, w, h);

  if (datasets[0].data.length < 2) return;

  // Find max value
  let maxVal = 0;
  for (const ds of datasets) {
    for (const v of ds.data) {
      if (v > maxVal) maxVal = v;
    }
  }
  if (maxVal === 0) maxVal = 1;
  maxVal *= 1.1;

  const padL = 50, padR = 10, padT = 10, padB = 25;
  const chartW = w - padL - padR;
  const chartH = h - padT - padB;

  // Grid lines
  ctx.strokeStyle = '#1e2845';
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= 4; i++) {
    const y = padT + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    // Label
    ctx.fillStyle = '#8892b0';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    const val = maxVal - (maxVal / 4) * i;
    ctx.fillText(val.toFixed(val >= 100 ? 0 : 1), padL - 6, y + 3);
  }

  const n = datasets[0].data.length;

  for (const ds of datasets) {
    ctx.beginPath();
    ctx.strokeStyle = ds.color;
    ctx.lineWidth = ds.fill ? 0.5 : 1.5;
    for (let i = 0; i < n; i++) {
      const x = padL + (i / (n - 1)) * chartW;
      const y = padT + chartH - (ds.data[i] / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();

    if (ds.fill) {
      const lastX = padL + chartW;
      ctx.lineTo(lastX, padT + chartH);
      ctx.lineTo(padL, padT + chartH);
      ctx.closePath();
      ctx.fillStyle = ds.color.replace(')', ',0.15)').replace('rgb', 'rgba');
      ctx.fill();
    }
  }

  // Legend
  if (datasets.length > 1 && labels) {
    ctx.font = '10px sans-serif';
    let lx = padL + 10;
    for (let i = 0; i < datasets.length; i++) {
      ctx.fillStyle = datasets[i].color;
      ctx.fillRect(lx, padT + 4, 12, 3);
      ctx.fillStyle = '#8892b0';
      const label = labels[i] || '';
      ctx.textAlign = 'left';
      ctx.fillText(label, lx + 16, padT + 10);
      lx += ctx.measureText(label).width + 36;
    }
  }
}

function renderHistogram(hist) {
  const container = document.getElementById('histContainer');
  if (!hist || hist.length === 0) return;

  let maxCount = 0;
  for (const b of hist) {
    if (b.count > maxCount) maxCount = b.count;
  }
  if (maxCount === 0) maxCount = 1;

  let html = '';
  for (const b of hist) {
    const pct = (b.count / maxCount) * 100;
    html += '<div class="hist-bar-wrapper">' +
      '<div class="hist-count">' + b.count + '</div>' +
      '<div class="hist-bar" style="height:' + pct + '%"></div>' +
      '<div class="hist-label">' + b.label + '</div></div>';
  }
  container.innerHTML = html;
}

function renderRunners(runners) {
  const tbody = document.getElementById('runnersBody');
  if (!runners || Object.keys(runners).length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#8892b0;padding:30px">No runners connected</td></tr>';
    return;
  }

  let html = '';
  for (const [name, rs] of Object.entries(runners)) {
    const now = Date.now() / 1000;
    const lastSeen = new Date(rs.last_seen).getTime() / 1000;
    const stale = (now - lastSeen) > 10;
    const ago = Math.round(now - lastSeen);
    const r = rs.last_result;
    const successPct = r.total_queries > 0 ? (r.success_count / r.total_queries * 100).toFixed(1) : '0';

    html += '<tr>' +
      '<td>' + name + '</td>' +
      '<td><span class="status-dot ' + (stale ? 'stale' : 'active') + '"></span>' + (stale ? 'Offline' : 'Active') + '</td>' +
      '<td>' + r.qps.toFixed(1) + '</td>' +
      '<td>' + r.avg_latency_ms.toFixed(1) + ' ms</td>' +
      '<td>' + r.p95_latency_ms.toFixed(1) + ' ms</td>' +
      '<td>' + successPct + '%</td>' +
      '<td>' + r.error_count + '</td>' +
      '<td>' + ago + 's ago</td>' +
      '</tr>';
  }
  tbody.innerHTML = html;
}

function update() {
  fetch('/api/status')
    .then(r => r.json())
    .then(data => {
      const runners = data.runners || {};
      const names = Object.keys(runners);
      const active = names.filter(n => {
        const ls = new Date(runners[n].last_seen).getTime() / 1000;
        return (Date.now()/1000 - ls) < 10;
      });

      document.getElementById('statusText').textContent =
        active.length + ' runner(s) active';

      // Aggregate current metrics
      let totalQPS = 0, totalAvg = 0, totalP50 = 0, totalP95 = 0, totalP99 = 0;
      let totalQ = 0, totalS = 0;
      let histData = null;
      let count = 0;

      for (const n of active) {
        const r = runners[n].last_result;
        totalQPS += r.qps;
        totalAvg += r.avg_latency_ms;
        totalP50 += r.p50_latency_ms;
        totalP95 += r.p95_latency_ms;
        totalP99 += r.p99_latency_ms;
        totalQ += r.total_queries;
        totalS += r.success_count;
        if (r.latency_hist) histData = r.latency_hist;
        count++;
      }

      document.getElementById('mQPS').textContent = totalQPS.toFixed(0);
      if (count > 0) {
        setLatencyCard('mAvgCard', 'mAvg', totalAvg / count);
        setLatencyCard('mP50Card', 'mP50', totalP50 / count);
        setLatencyCard('mP95Card', 'mP95', totalP95 / count);
        setLatencyCard('mP99Card', 'mP99', totalP99 / count);
      }
      document.getElementById('mSuccess').textContent =
        totalQ > 0 ? (totalS / totalQ * 100).toFixed(1) : '--';

      // Push to time series
      qpsSeries.push(totalQPS);
      latP50Series.push(count > 0 ? totalP50 / count : 0);
      latP95Series.push(count > 0 ? totalP95 / count : 0);
      latP99Series.push(count > 0 ? totalP99 / count : 0);

      if (qpsSeries.length > maxPoints) qpsSeries.shift();
      if (latP50Series.length > maxPoints) latP50Series.shift();
      if (latP95Series.length > maxPoints) latP95Series.shift();
      if (latP99Series.length > maxPoints) latP99Series.shift();

      // Draw charts
      drawChart('qpsChart', [{data: qpsSeries, color: 'rgb(201,168,76)', fill: true}]);
      drawChart('latChart', [
        {data: latP50Series, color: 'rgb(76,175,80)'},
        {data: latP95Series, color: 'rgb(255,193,7)'},
        {data: latP99Series, color: 'rgb(244,67,54)'},
      ], ['P50', 'P95', 'P99']);

      // Histogram
      if (histData) renderHistogram(histData);

      // Runners table
      renderRunners(runners);
    })
    .catch(() => {});
}

setInterval(update, 1000);
update();
</script>
</body>
</html>`
