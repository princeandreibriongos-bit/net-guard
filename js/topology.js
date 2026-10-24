/** Canvas topology: ESP32, attacker, SPAN switch, NIDS host. */

class TopologyVisualizer {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    
    this.nodes = [];
    this.links = [];
    this.particles = [];
    this.animationId = null;

    this.initLayout();
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.startAnimation();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width;
    this.canvas.height = 320;
    this.initLayout();
  }

  initLayout() {
    const w = this.canvas.width;
    const h = this.canvas.height;

    // Node coordinates arranged across the SPAN ingestion pipeline
    this.nodes = [
      { id: 'esp32', label: 'ESP32 IoT Node', sub: 'DHT11 Sensor (UDP 5005)', x: w * 0.12, y: h * 0.30, color: '#06b6d4', icon: '📡' },
      { id: 'attacker', label: 'Rogue / Attacker Node', sub: 'DoS / Spoof / Fuzz', x: w * 0.12, y: h * 0.75, color: '#f43f5e', icon: '💀' },
      { id: 'switch', label: 'TP-Link TL-SG105E', sub: 'Managed SPAN Mirror Port', x: w * 0.38, y: h * 0.50, color: '#3b82f6', icon: '🔀' },
      { id: 'sniffer', label: 'NIDS Passive Sniffer', sub: 'Scapy DPI (eth0 / lo)', x: w * 0.62, y: h * 0.50, color: '#10b981', icon: '🛡️' },
      { id: 'features', label: 'Feature Extractor', sub: 'Rolling Window (IAT/Entropy)', x: w * 0.82, y: h * 0.30, color: '#f59e0b', icon: '⚙️' },
      { id: 'ml', label: 'Isolation Forest ML', sub: 'Outlier Anomaly Engine', x: w * 0.82, y: h * 0.75, color: '#a855f7', icon: '🧠' }
    ];

    // Pipeline Connections
    this.links = [
      { from: 'esp32', to: 'switch', label: 'Port 1 (Normal Telemetry)', type: 'normal' },
      { from: 'attacker', to: 'switch', label: 'Port 2 (Injected Attacks)', type: 'attack' },
      { from: 'switch', to: 'sniffer', label: 'Port 5 SPAN Mirror (Passive Tap)', type: 'span' },
      { from: 'sniffer', to: 'features', label: 'Parsed Datagrams', type: 'pipeline' },
      { from: 'features', to: 'ml', label: 'Feature Vectors', type: 'pipeline' }
    ];
  }

  spawnParticle(type = 'normal') {
    const startNodeId = (type === 'normal') ? 'esp32' : 'attacker';
    const color = (type === 'normal') ? '#06b6d4' : (type === 'flood' ? '#f43f5e' : (type === 'malformed' ? '#f59e0b' : '#c084fc'));

    // Path 1: Source -> Switch
    this.particles.push({
      from: startNodeId,
      to: 'switch',
      progress: 0,
      speed: type === 'flood' ? 0.05 : 0.018,
      color: color,
      type: type,
      nextLegs: ['sniffer', 'features', 'ml']
    });
  }

  updateParticles() {
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.progress += p.speed;

      if (p.progress >= 1.0) {
        if (p.nextLegs && p.nextLegs.length > 0) {
          const nextTo = p.nextLegs.shift();
          p.from = p.to;
          p.to = nextTo;
          p.progress = 0;
        } else {
          this.particles.splice(i, 1);
        }
      }
    }
  }

  getNode(id) {
    return this.nodes.find(n => n.id === id);
  }

  draw() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Draw Links
    for (const link of this.links) {
      const src = this.getNode(link.from);
      const dst = this.getNode(link.to);
      if (!src || !dst) continue;

      this.ctx.beginPath();
      this.ctx.moveTo(src.x, src.y);
      this.ctx.lineTo(dst.x, dst.y);

      if (link.type === 'span') {
        this.ctx.strokeStyle = 'rgba(16, 185, 129, 0.6)';
        this.ctx.setLineDash([6, 6]);
        this.ctx.lineWidth = 2.5;
      } else if (link.type === 'attack') {
        this.ctx.strokeStyle = 'rgba(244, 63, 94, 0.4)';
        this.ctx.setLineDash([]);
        this.ctx.lineWidth = 1.8;
      } else {
        this.ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
        this.ctx.setLineDash([]);
        this.ctx.lineWidth = 1.8;
      }

      this.ctx.stroke();
      this.ctx.setLineDash([]);
    }

    // Draw Flow Particles
    for (const p of this.particles) {
      const src = this.getNode(p.from);
      const dst = this.getNode(p.to);
      if (!src || !dst) continue;

      const px = src.x + (dst.x - src.x) * p.progress;
      const py = src.y + (dst.y - src.y) * p.progress;

      this.ctx.save();
      this.ctx.beginPath();
      this.ctx.arc(px, py, p.type === 'flood' ? 3.5 : 5, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 10;
      this.ctx.fill();
      this.ctx.restore();
    }

    // Draw Nodes
    for (const node of this.nodes) {
      this.ctx.save();
      
      // Node Card Background
      const cardW = 140;
      const cardH = 54;
      const cardX = node.x - cardW / 2;
      const cardY = node.y - cardH / 2;

      this.ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
      this.ctx.strokeStyle = node.color;
      this.ctx.lineWidth = 1.5;
      this.ctx.shadowColor = node.color;
      this.ctx.shadowBlur = 8;

      // Rounded Rect
      this.ctx.beginPath();
      this.ctx.roundRect(cardX, cardY, cardW, cardH, 8);
      this.ctx.fill();
      this.ctx.stroke();

      // Node Icon & Text
      this.ctx.shadowBlur = 0;
      this.ctx.font = '14px Inter, sans-serif';
      this.ctx.fillStyle = '#ffffff';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(`${node.icon} ${node.label}`, node.x, node.y - 4);

      this.ctx.font = '9px JetBrains Mono, monospace';
      this.ctx.fillStyle = '#94a3b8';
      this.ctx.fillText(node.sub, node.x, node.y + 14);

      this.ctx.restore();
    }
  }

  startAnimation() {
    const loop = () => {
      this.updateParticles();
      this.draw();
      this.animationId = requestAnimationFrame(loop);
    };
    loop();
  }
}

window.TopologyVisualizer = TopologyVisualizer;
