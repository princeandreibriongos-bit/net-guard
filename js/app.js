/* Dashboard state, charts, SSE client, tab UI */

// Global State
const state = {
  running: true,
  cadenceSec: 2.0,
  totalPackets: 0,
  anomalyCount: 0,
  normalCount: 0,
  lastPacketTime: Date.now(),
  recentPackets: [],
  rollingFeatures: {
    iatMs: 2000,
    entropy: 4.25,
    tempGradient: 0.05,
    humidityGradient: 0.12,
    packetRatePPS: 0.5,
    anomalyScore: 0.18
  },
  sensorState: {
    temp: 24.2,
    humidity: 56.4,
    seq: 1
  }
};

// DOM References
let topologyViz = null;
let charts = {};

// Calculation Helper: Shannon Entropy of Byte Sequence
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const freqs = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    freqs[char] = (freqs[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freqs) {
    const p = freqs[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Calculation Helper: Simulated Isolation Forest Outlier Score (0.0 to 1.0)
function computeIsolationScore(iatMs, entropy, temp, hum, isAttack, attackType) {
  if (isAttack) {
    if (attackType === 'flood') return +(0.85 + Math.random() * 0.12).toFixed(2);
    if (attackType === 'malformed') return +(0.82 + Math.random() * 0.15).toFixed(2);
    if (attackType === 'spoof') return +(0.78 + Math.random() * 0.18).toFixed(2);
  }
  // Normal telemetry scoring with slight noise
  let baseScore = 0.15;
  if (iatMs < 100) baseScore += 0.4;
  if (temp > 40 || temp < 0) baseScore += 0.5;
  if (entropy > 6.0 || entropy < 2.0) baseScore += 0.25;
  return +Math.min(0.99, Math.max(0.05, baseScore + (Math.random() * 0.08 - 0.04))).toFixed(2);
}

// Format Hex Dump
function stringToHexDump(str) {
  let hex = '';
  for (let i = 0; i < Math.min(str.length, 64); i++) {
    const byte = str.charCodeAt(i).toString(16).padStart(2, '0');
    hex += byte + ' ';
    if ((i + 1) % 16 === 0) hex += '\n';
  }
  return hex.toUpperCase();
}

// Initialize Dashboard Charts
function initCharts() {
  const chartColors = {
    cyan: '#06b6d4',
    rose: '#f43f5e',
    emerald: '#10b981',
    amber: '#f59e0b',
    purple: '#a855f7',
    grid: 'rgba(255, 255, 255, 0.06)'
  };

  // 1. Throughput & Inter-Arrival Time Chart
  const ctxIAT = document.getElementById('chartIAT')?.getContext('2d');
  if (ctxIAT) {
    charts.iat = new Chart(ctxIAT, {
      type: 'line',
      data: {
        labels: Array(20).fill(''),
        datasets: [
          {
            label: 'Inter-Arrival Time (ms)',
            borderColor: chartColors.cyan,
            backgroundColor: 'rgba(6, 182, 212, 0.1)',
            data: Array(20).fill(2000),
            yAxisID: 'y',
            tension: 0.3,
            fill: true
          },
          {
            label: 'Throughput (Packets/s)',
            borderColor: chartColors.purple,
            backgroundColor: 'transparent',
            data: Array(20).fill(0.5),
            yAxisID: 'y1',
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: chartColors.grid } },
          y: { 
            position: 'left',
            grid: { color: chartColors.grid },
            title: { display: true, text: 'IAT (ms)', color: '#94a3b8' },
            suggestedMin: 0,
            suggestedMax: 2500
          },
          y1: {
            position: 'right',
            grid: { drawOnChartArea: false },
            title: { display: true, text: 'PPS', color: '#94a3b8' },
            suggestedMin: 0,
            suggestedMax: 50
          }
        },
        plugins: { legend: { labels: { color: '#cbd5e1', font: { size: 10 } } } }
      }
    });
  }

  // 2. DHT11 Sensor Telemetry Chart
  const ctxSensor = document.getElementById('chartSensor')?.getContext('2d');
  if (ctxSensor) {
    charts.sensor = new Chart(ctxSensor, {
      type: 'line',
      data: {
        labels: Array(20).fill(''),
        datasets: [
          {
            label: 'Temperature (°C)',
            borderColor: chartColors.amber,
            backgroundColor: 'rgba(245, 158, 11, 0.08)',
            data: Array(20).fill(24.0),
            tension: 0.3,
            yAxisID: 'y'
          },
          {
            label: 'Humidity (%)',
            borderColor: chartColors.emerald,
            backgroundColor: 'rgba(16, 185, 129, 0.08)',
            data: Array(20).fill(55.0),
            tension: 0.3,
            yAxisID: 'y1'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: chartColors.grid } },
          y: { 
            position: 'left',
            grid: { color: chartColors.grid },
            title: { display: true, text: 'Temp °C', color: '#94a3b8' },
            suggestedMin: 15,
            suggestedMax: 35
          },
          y1: {
            position: 'right',
            grid: { drawOnChartArea: false },
            title: { display: true, text: 'Humidity %', color: '#94a3b8' },
            suggestedMin: 30,
            suggestedMax: 80
          }
        },
        plugins: { legend: { labels: { color: '#cbd5e1', font: { size: 10 } } } }
      }
    });
  }

  // 3. Isolation Forest Anomaly Timeline
  const ctxML = document.getElementById('chartML')?.getContext('2d');
  if (ctxML) {
    charts.ml = new Chart(ctxML, {
      type: 'line',
      data: {
        labels: Array(20).fill(''),
        datasets: [
          {
            label: 'iForest Anomaly Score',
            borderColor: chartColors.rose,
            backgroundColor: 'rgba(244, 63, 94, 0.15)',
            data: Array(20).fill(0.18),
            tension: 0.25,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: chartColors.grid } },
          y: { 
            grid: { color: chartColors.grid },
            suggestedMin: 0,
            suggestedMax: 1.0,
            title: { display: true, text: 'Score [0 = Normal, 1 = Attack]', color: '#94a3b8' }
          }
        },
        plugins: { 
          legend: { labels: { color: '#cbd5e1', font: { size: 10 } } },
          annotation: {
            annotations: {
              line1: {
                type: 'line',
                yMin: 0.7,
                yMax: 0.7,
                borderColor: 'red',
                borderWidth: 2,
                label: { content: 'Threat Threshold (0.70)', enabled: true }
              }
            }
          }
        }
      }
    });
  }
}

// Ingest Packet into Stream & Update Dashboard
function processIncomingPacket(packetData) {
  state.totalPackets++;
  const now = Date.now();
  const iatMs = now - state.lastPacketTime;
  state.lastPacketTime = now;

  const entropy = calculateShannonEntropy(packetData.rawPayload);
  const anomalyScore = computeIsolationScore(
    iatMs,
    entropy,
    packetData.temp,
    packetData.humidity,
    packetData.isAttack,
    packetData.attackType
  );

  if (packetData.isAttack || anomalyScore >= 0.70) {
    state.anomalyCount++;
  } else {
    state.normalCount++;
  }

  // Update State Features
  state.rollingFeatures = {
    iatMs: iatMs,
    entropy: +entropy.toFixed(3),
    tempGradient: +(Math.abs(packetData.temp - state.sensorState.temp) / (Math.max(1, iatMs / 1000))).toFixed(3),
    humidityGradient: +(Math.abs(packetData.humidity - state.sensorState.humidity) / (Math.max(1, iatMs / 1000))).toFixed(3),
    packetRatePPS: +(1000 / Math.max(10, iatMs)).toFixed(1),
    anomalyScore: anomalyScore
  };

  if (!packetData.isAttack && packetData.temp) {
    state.sensorState.temp = packetData.temp;
    state.sensorState.humidity = packetData.humidity;
  }

  // Update DOM Metric Cards
  document.getElementById('statTotalPackets').textContent = state.totalPackets;
  document.getElementById('statAnomalyCount').textContent = state.anomalyCount;
  document.getElementById('statPPS').textContent = state.rollingFeatures.packetRatePPS;
  document.getElementById('statIAT').textContent = Math.round(iatMs);
  document.getElementById('statEntropy').textContent = state.rollingFeatures.entropy;

  // Update Anomaly Gauge
  const gaugeScoreEl = document.getElementById('gaugeScore');
  const gaugeVerdictEl = document.getElementById('gaugeVerdict');
  const threatBadgeEl = document.getElementById('threatBadge');
  
  if (gaugeScoreEl) {
    gaugeScoreEl.textContent = anomalyScore.toFixed(2);
    if (anomalyScore >= 0.70) {
      gaugeScoreEl.style.color = '#f43f5e';
      gaugeVerdictEl.textContent = 'MALICIOUS THREAT DETECTED';
      gaugeVerdictEl.style.color = '#f43f5e';
      threatBadgeEl.className = 'status-badge';
      threatBadgeEl.innerHTML = '<span class="status-dot alert"></span> Threat Level: CRITICAL';
    } else if (anomalyScore >= 0.45) {
      gaugeScoreEl.style.color = '#f59e0b';
      gaugeVerdictEl.textContent = 'SUSPICIOUS TELEMETRY';
      gaugeVerdictEl.style.color = '#f59e0b';
      threatBadgeEl.className = 'status-badge';
      threatBadgeEl.innerHTML = '<span class="status-dot warning"></span> Threat Level: ELEVATED';
    } else {
      gaugeScoreEl.style.color = '#10b981';
      gaugeVerdictEl.textContent = 'NORMAL OPERATION';
      gaugeVerdictEl.style.color = '#10b981';
      threatBadgeEl.className = 'status-badge';
      threatBadgeEl.innerHTML = '<span class="status-dot active"></span> Threat Level: NORMAL';
    }
  }

  // Update Live Feature Math Deep-Dive Panel
  updateFeatureMathCards();

  // Push to Packet Table
  appendPacketToTable(packetData, iatMs, entropy, anomalyScore);

  // Update Charts
  updateCharts(iatMs, state.rollingFeatures.packetRatePPS, packetData.temp, packetData.humidity, anomalyScore);

  // Spawn Animation Particle in Topology
  if (topologyViz) {
    topologyViz.spawnParticle(packetData.attackType || 'normal');
  }
}

function updateCharts(iat, pps, temp, hum, score) {
  if (charts.iat) {
    charts.iat.data.datasets[0].data.shift();
    charts.iat.data.datasets[0].data.push(iat);
    charts.iat.data.datasets[1].data.shift();
    charts.iat.data.datasets[1].data.push(pps);
    charts.iat.update('none');
  }
  if (charts.sensor && temp !== undefined && hum !== undefined) {
    charts.sensor.data.datasets[0].data.shift();
    charts.sensor.data.datasets[0].data.push(temp);
    charts.sensor.data.datasets[1].data.shift();
    charts.sensor.data.datasets[1].data.push(hum);
    charts.sensor.update('none');
  }
  if (charts.ml) {
    charts.ml.data.datasets[0].data.shift();
    charts.ml.data.datasets[0].data.push(score);
    charts.ml.update('none');
  }
}

function appendPacketToTable(pkt, iat, entropy, score) {
  const tbody = document.getElementById('packetTableBody');
  if (!tbody) return;

  const row = document.createElement('tr');
  row.className = pkt.isAttack ? 'packet-row anomaly-row' : (score > 0.45 ? 'packet-row warning-row' : 'packet-row');
  
  let tagHtml = '<span class="badge-tag badge-normal">NORMAL</span>';
  if (pkt.attackType === 'flood') tagHtml = '<span class="badge-tag badge-flood">UDP FLOOD</span>';
  if (pkt.attackType === 'malformed') tagHtml = '<span class="badge-tag badge-malformed">FUZZ / MALFORMED</span>';
  if (pkt.attackType === 'spoof') tagHtml = '<span class="badge-tag badge-spoof">SPOOFED SENSOR</span>';

  row.innerHTML = `
    <td>#${String(state.totalPackets).padStart(4, '0')}</td>
    <td>${new Date().toLocaleTimeString()}</td>
    <td>${pkt.srcIp}:${pkt.srcPort}</td>
    <td>${pkt.dstIp}:${pkt.dstPort}</td>
    <td>${tagHtml}</td>
    <td>${pkt.temp ? pkt.temp + '°C / ' + pkt.humidity + '%' : 'N/A'}</td>
    <td>${Math.round(iat)} ms</td>
    <td>${score.toFixed(2)}</td>
  `;

  row.addEventListener('click', () => {
    inspectPacket(pkt, iat, entropy, score);
  });

  tbody.insertBefore(row, tbody.firstChild);

  // Keep table bounded to latest 30 rows
  while (tbody.children.length > 30) {
    tbody.removeChild(tbody.lastChild);
  }
}

function inspectPacket(pkt, iat, entropy, score) {
  const container = document.getElementById('packetInspectorContent');
  if (!container) return;

  const hex = stringToHexDump(pkt.rawPayload);

  container.innerHTML = `
    <div style="margin-bottom: 0.8rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-subtle)">
      <strong style="color: var(--accent-cyan)">[PACKET DISSECTION SUMMARY]</strong><br>
      <span class="layer-tag">Layer 2:</span> Ethernet II | Frame Length: ${pkt.rawPayload.length + 42} bytes<br>
      <span class="layer-tag">Layer 3:</span> IPv4 | Src: <code>${pkt.srcIp}</code> -> Dst: <code>${pkt.dstIp}</code> | Protocol: 17 (UDP) | TTL: 64<br>
      <span class="layer-tag">Layer 4:</span> UDP Datagram | Sport: <code>${pkt.srcPort}</code> -> Dport: <code>${pkt.dstPort}</code> | Length: ${pkt.rawPayload.length + 8} bytes<br>
      <span class="layer-tag">Layer 7:</span> Application Telemetry (DHT11 / JSON payload)
    </div>
    <div style="margin-bottom: 0.8rem;">
      <strong style="color: var(--accent-amber)">[EXTRACTED ML FEATURE VALUES]</strong><br>
      • Inter-Arrival Time (IAT): <strong>${Math.round(iat)} ms</strong><br>
      • Shannon Entropy: <strong>${entropy.toFixed(3)} bits/byte</strong><br>
      • Payload Size: <strong>${pkt.rawPayload.length} bytes</strong><br>
      • Isolation Forest Anomaly Score: <strong style="color: ${score >= 0.7 ? 'var(--accent-rose)' : 'var(--accent-emerald)'}">${score.toFixed(2)}</strong>
    </div>
    <strong style="color: var(--accent-cyan)">[RAW PAYLOAD & HEX DUMP]</strong>
    <pre class="hex-dump">${hex}</pre>
    <div style="margin-top: 0.5rem; color: #94a3b8;">
      Decoded Content: <code style="color: #e2e8f0;">${pkt.rawPayload}</code>
    </div>
  `;
}

function updateFeatureMathCards() {
  const f = state.rollingFeatures;
  const elIatVal = document.getElementById('liveIatVal');
  const elEntropyVal = document.getElementById('liveEntropyVal');
  const elGradVal = document.getElementById('liveGradVal');
  const elScoreVal = document.getElementById('liveScoreVal');

  if (elIatVal) elIatVal.textContent = `${Math.round(f.iatMs)} ms`;
  if (elEntropyVal) elEntropyVal.textContent = `${f.entropy} bits/byte`;
  if (elGradVal) elGradVal.textContent = `ΔT: ${f.tempGradient}°C/s | ΔH: ${f.humidityGradient}%/s`;
  if (elScoreVal) elScoreVal.textContent = `${f.anomalyScore}`;
}

// Generate Mock Normal Telemetry
function generateMockNormalPacket() {
  state.sensorState.seq++;
  state.sensorState.temp += (Math.random() * 0.4 - 0.2);
  state.sensorState.temp = Math.max(21.0, Math.min(28.0, state.sensorState.temp));
  
  state.sensorState.humidity += (Math.random() * 0.6 - 0.3);
  state.sensorState.humidity = Math.max(45.0, Math.min(65.0, state.sensorState.humidity));

  const payloadObj = {
    device_id: "esp32-node-01",
    seq: state.sensorState.seq,
    timestamp: +(Date.now() / 1000).toFixed(3),
    sensor: "DHT11",
    temp: +state.sensorState.temp.toFixed(2),
    humidity: +state.sensorState.humidity.toFixed(2),
    status: "HEALTHY"
  };

  const payloadStr = JSON.stringify(payloadObj);

  return {
    srcIp: "192.168.1.50",
    dstIp: "127.0.0.1",
    srcPort: 52144,
    dstPort: 5005,
    temp: payloadObj.temp,
    humidity: payloadObj.humidity,
    rawPayload: payloadStr,
    isAttack: false,
    attackType: null
  };
}

// Attack Injections
function triggerAttack(type) {
  if (type === 'flood') {
    let count = 0;
    const floodInterval = setInterval(() => {
      count++;
      const pkt = {
        srcIp: `192.168.1.${Math.floor(Math.random() * 100 + 100)}`,
        dstIp: "127.0.0.1",
        srcPort: Math.floor(Math.random() * 50000 + 1024),
        dstPort: 5005,
        temp: 0,
        humidity: 0,
        rawPayload: JSON.stringify({ attack_type: "UDP_FLOOD_BURST", burst_id: count, padding: "X".repeat(256) }),
        isAttack: true,
        attackType: 'flood'
      };
      processIncomingPacket(pkt);
      if (count >= 25) clearInterval(floodInterval);
    }, 40);
  } else if (type === 'malformed') {
    const malformedPayloads = [
      "\x00\xff\xfe\xba\xbe\xde\xad\xbe\xef" + "MALFORMED_HEAP_OVERFLOW",
      '{"device_id": "esp32", "temp": NaN, "broken_json": ',
      "GET /../../etc/shadow HTTP/1.1\r\nHost: iot\r\n\r\n",
      "A".repeat(512)
    ];
    for (let i = 0; i < 4; i++) {
      setTimeout(() => {
        const sample = malformedPayloads[i % malformedPayloads.length];
        const pkt = {
          srcIp: "192.168.1.99",
          dstIp: "127.0.0.1",
          srcPort: 59912,
          dstPort: 5005,
          temp: 0,
          humidity: 0,
          rawPayload: sample,
          isAttack: true,
          attackType: 'malformed'
        };
        processIncomingPacket(pkt);
      }, i * 150);
    }
  } else if (type === 'spoof') {
    const spoofValues = [
      { temp: 185.5, hum: 12.0, status: "CRITICAL_OVERHEAT" },
      { temp: -40.0, hum: 99.9, status: "EXTREME_COLD" },
      { temp: 500.0, hum: 999.0, status: "IMPOSSIBLE_READING" }
    ];
    spoofValues.forEach((spoof, idx) => {
      setTimeout(() => {
        const payload = JSON.stringify({
          device_id: "esp32-node-spoofed",
          seq: 9000 + idx,
          timestamp: +(Date.now() / 1000).toFixed(3),
          sensor: "DHT11",
          temp: spoof.temp,
          humidity: spoof.hum,
          status: spoof.status
        });
        const pkt = {
          srcIp: "192.168.1.150",
          dstIp: "127.0.0.1",
          srcPort: 55123,
          dstPort: 5005,
          temp: spoof.temp,
          humidity: spoof.hum,
          rawPayload: payload,
          isAttack: true,
          attackType: 'spoof'
        };
        processIncomingPacket(pkt);
      }, idx * 400);
    });
  }
}

// Live Backend SSE Bridge
let eventSource = null;
let isLiveBackendActive = false;

function connectBackendSSE() {
  try {
    eventSource = new EventSource('/api/stream');
    
    eventSource.onopen = () => {
      isLiveBackendActive = true;
      const badge = document.getElementById('backendStatusBadge');
      if (badge) {
        badge.innerHTML = '<span class="status-dot active"></span> Backend: <strong style="color:#10b981; margin-left:4px;">LIVE PYTHON STREAM</strong>';
      }
      // If live python backend is broadcasting, reduce client mock cadence
      const toggleBtn = document.getElementById('btnToggleSim');
      if (toggleBtn) {
        toggleBtn.textContent = '🟢 Live Stream Connected';
        toggleBtn.classList.remove('btn-outline');
        toggleBtn.classList.add('btn-primary');
      }
    };

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'PACKET_EVENT') {
          const pkt = {
            srcIp: data.src_ip,
            dstIp: data.dst_ip,
            srcPort: data.src_port,
            dstPort: data.dst_port,
            temp: data.temp,
            humidity: data.humidity,
            rawPayload: data.raw_payload_preview || '{"telemetry": "active"}',
            isAttack: data.is_attack,
            attackType: data.attack_type ? data.attack_type.toLowerCase() : null
          };
          processIncomingPacket(pkt);
        }
      } catch (err) {
        console.error('Failed parsing SSE payload', err);
      }
    };

    eventSource.onerror = () => {
      isLiveBackendActive = false;
      const badge = document.getElementById('backendStatusBadge');
      if (badge) {
        badge.innerHTML = '<span class="status-dot warning"></span> Backend: <strong style="color:#f59e0b; margin-left:4px;">STANDALONE SIMULATION</strong>';
      }
    };
  } catch (e) {
    console.log('SSE connection error:', e);
  }
}

// Master Loop
let mainSimTimer = null;
function startSimulationLoop() {
  if (mainSimTimer) clearInterval(mainSimTimer);
  mainSimTimer = setInterval(() => {
    // Only generate local browser mock packets if live python backend is not currently feeding packets
    if (state.running && !isLiveBackendActive) {
      const pkt = generateMockNormalPacket();
      processIncomingPacket(pkt);
    }
  }, state.cadenceSec * 1000);
}

// Setup Event Listeners & Tabs
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  topologyViz = new TopologyVisualizer('topologyCanvas');
  connectBackendSSE();

  // Tab Navigation
  const tabBtns = document.querySelectorAll('.nav-tab-btn');
  const tabViews = document.querySelectorAll('.tab-view');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabViews.forEach(v => v.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId)?.classList.add('active');

      if (targetId === 'tab-flow' && topologyViz) {
        setTimeout(() => topologyViz.resize(), 100);
      }
    });
  });

  // Flow Step Card Selection
  const stepCards = document.querySelectorAll('.flow-step-card');
  stepCards.forEach(card => {
    card.addEventListener('click', () => {
      stepCards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      const detailId = card.getAttribute('data-step-detail');
      const detailEl = document.getElementById('stepDetailContent');
      if (detailEl && window.stepDetails && window.stepDetails[detailId]) {
        detailEl.innerHTML = window.stepDetails[detailId];
      }
    });
  });

  // Buttons
  document.getElementById('btnToggleSim')?.addEventListener('click', (e) => {
    state.running = !state.running;
    e.target.textContent = state.running ? '⏸️ Pause Telemetry' : '▶️ Resume Telemetry';
    e.target.className = state.running ? 'btn btn-outline' : 'btn btn-primary';
  });

  document.getElementById('cadenceSlider')?.addEventListener('input', (e) => {
    state.cadenceSec = parseFloat(e.target.value);
    document.getElementById('cadenceLabel').textContent = `${state.cadenceSec}s`;
    startSimulationLoop();
  });

  document.getElementById('btnAttackFlood')?.addEventListener('click', () => triggerAttack('flood'));
  document.getElementById('btnAttackMalformed')?.addEventListener('click', () => triggerAttack('malformed'));
  document.getElementById('btnAttackSpoof')?.addEventListener('click', () => triggerAttack('spoof'));

  startSimulationLoop();
});

// Step-by-step Interactive Explanations Data
window.stepDetails = {
  step1: `
    <h3 style="color: var(--accent-cyan); margin-bottom: 0.5rem;">Step 1: Edge Sensing & UDP Broadcast (ESP32 + DHT11)</h3>
    <p>The ESP32 microcontroller samples ambient temperature and humidity from the DHT11 sensor every 2 seconds. It serializes this data into a JSON payload and transmits it over UDP (User Datagram Protocol) to destination port 5005.</p>
    <div style="background: #090e17; padding: 0.8rem; border-radius: 6px; margin: 0.8rem 0; font-family: var(--font-mono); font-size: 0.8rem;">
      <code>IP(src="192.168.1.50", dst="192.168.1.255") / UDP(sport=52144, dport=5005) / Raw('{"temp": 24.5, "humidity": 58.2}')</code>
    </div>
    <p><strong>Why UDP?</strong> UDP has minimal overhead for battery/compute-constrained IoT microcontrollers, but provides no encryption or handshakes, making it critical to passively monitor with an external NIDS.</p>
  `,
  step2: `
    <h3 style="color: var(--accent-blue); margin-bottom: 0.5rem;">Step 2: Port Mirroring / SPAN (TP-Link TL-SG105E)</h3>
    <p>The managed Ethernet switch is configured with a <strong>Switched Port Analyzer (SPAN)</strong> mirror. All ingress/egress traffic on Port 1 (ESP32) and Port 2 (Attacker) is copied at the hardware layer and sent out of Port 5 (Mirror Port) directly into our NIDS laptop.</p>
    <p><strong>Key Security Advantage:</strong> The NIDS operates in complete stealth mode. It does not possess an active IP or respond to ARP queries, meaning attackers cannot discover, scan, or attack the detection system!</p>
  `,
  step3: `
    <h3 style="color: var(--accent-emerald); margin-bottom: 0.5rem;">Step 3: Passive DPI Sniffer (Scapy / Kernel Filter)</h3>
    <p>The Python listener runs a kernel-level Berkeley Packet Filter (BPF): <code>udp and port 5005</code>. It sniffs raw packets directly from the network card without disturbing network latency.</p>
    <p>The sniffer verifies IP checksums, dissects the UDP header, extracts the raw payload, and performs initial syntax validation.</p>
  `,
  step4: `
    <h3 style="color: var(--accent-amber); margin-bottom: 0.5rem;">Step 4: Windowed Feature Extraction Engine</h3>
    <p>Raw packets cannot be directly fed into an ML algorithm. We maintain a sliding rolling window (e.g., last 20 packets / 10-second window) and compute 5 key statistical vectors:</p>
    <ul>
      <li><strong>Inter-Arrival Time (IAT):</strong> Time delta between consecutive packets (drops to ~5ms during floods).</li>
      <li><strong>Payload Shannon Entropy:</strong> Randomness of byte distribution (distinguishes structured JSON from encrypted exfiltration or fuzzing).</li>
      <li><strong>Packet Rate (PPS):</strong> Volumetric throughput.</li>
      <li><strong>Thermal / Humidity Gradient ($\Delta T/\Delta t$):</strong> Detects impossible physical temperature spikes.</li>
    </ul>
  `,
  step5: `
    <h3 style="color: var(--accent-purple); margin-bottom: 0.5rem;">Step 5: Unsupervised Isolation Forest (iForest)</h3>
    <p><strong>Isolation Forest</strong> builds an ensemble of randomized decision isolation trees. Because anomalies are "few and different", they are isolated near the root of the tree with very short path lengths $h(x)$, yielding high anomaly scores $s(x) \approx 1.0$.</p>
    <p><strong>Zero Labels Needed:</strong> iForest learns the normal baseline of the IoT ecosystem autonomously, allowing it to detect novel zero-day attacks without signature databases.</p>
  `,
  step6: `
    <h3 style="color: var(--accent-rose); margin-bottom: 0.5rem;">Step 6: Threat Alerting & Quarantine Dispatch</h3>
    <p>When an anomaly score exceeds the threshold ($\ge 0.70$), NET-GUARD raises an instant SOC alert with the rogue IP, attack vector classification (DoS / Fuzz / Spoof), and triggers optional port-isolation webhooks.</p>
  `
};
