// Mini-HA PWA Dynamic Controller & EMQX Cloud Bridge Engine
let mqttClient = null;
let currentSchema = null;
let currentState = null;

// Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then(reg => console.log('[PWA] Service Worker registered:', reg.scope))
      .catch(err => console.warn('[PWA] SW registration failed:', err));
  });
}

// Configuration Storage
function getSavedConfig() {
  return {
    brokerUrl: localStorage.getItem('miniha_broker') || '',
    homeId: localStorage.getItem('miniha_home_id') || 'home_1',
    user: localStorage.getItem('miniha_user') || '',
    pass: localStorage.getItem('miniha_pass') || '',
    localIp: localStorage.getItem('miniha_local_ip') || ''
  };
}

function saveConfig(cfg) {
  localStorage.setItem('miniha_broker', (cfg.brokerUrl || '').trim());
  localStorage.setItem('miniha_home_id', (cfg.homeId || 'home_1').trim());
  localStorage.setItem('miniha_user', (cfg.user || '').trim());
  localStorage.setItem('miniha_pass', cfg.pass || '');
  localStorage.setItem('miniha_local_ip', (cfg.localIp || '').trim());
}

// Check for Auto-Config Invite in URL (#cfg=... or ?cfg=...)
function checkUrlInvite() {
  let raw = '';
  if (window.location.hash && window.location.hash.includes('cfg=')) {
    raw = window.location.hash.split('cfg=')[1].split('&')[0];
  } else if (window.location.search && window.location.search.includes('cfg=')) {
    raw = window.location.search.split('cfg=')[1].split('&')[0];
  }

  if (raw) {
    try {
      const jsonStr = atob(decodeURIComponent(raw));
      const parsed = JSON.parse(jsonStr);
      if (parsed.brokerUrl) {
        saveConfig(parsed);
        // Clean URL so the key doesn't linger in browser history
        history.replaceState(null, '', window.location.pathname);
        showToast('Connected via invite link!', 'success');
        return true;
      }
    } catch (e) {
      console.error('[Invite Parse Failed]', e);
    }
  }
  return false;
}

// Status Banner Controller
function setStatus(text, type = 'info') {
  const dot = document.getElementById('statusDot');
  const label = document.getElementById('statusText');
  if (!dot || !label) return;

  dot.className = 'status-dot';
  if (type === 'online') {
    dot.classList.add('dot-online');
  } else if (type === 'connecting') {
    dot.classList.add('dot-connecting');
  } else {
    dot.classList.add('dot-offline');
  }
  label.textContent = text;
}

// Connect to Cloud Broker via WebSockets Secure (WSS)
function connectMqtt() {
  const cfg = getSavedConfig();
  if (!cfg.brokerUrl) {
    setStatus('Ready to Connect', 'offline');
    const emptyState = document.getElementById('emptyState');
    if (emptyState) emptyState.style.display = 'block';
    return;
  }

  if (mqttClient) {
    try { mqttClient.end(true); } catch (e) {}
  }

  setStatus('Connecting...', 'connecting');

  const clientId = 'miniha_pwa_' + Math.random().toString(16).substr(2, 8);
  const options = {
    clientId: clientId,
    clean: true,
    connectTimeout: 8000,
    reconnectPeriod: 4000,
    username: cfg.user || undefined,
    password: cfg.pass || undefined
  };

  try {
    mqttClient = mqtt.connect(cfg.brokerUrl, options);

    mqttClient.on('connect', () => {
      console.log('[MQTT] Connected to broker');
      setStatus('Online', 'online');

      const schemaTopic = `miniha/${cfg.homeId}/schema`;
      const stateTopic = `miniha/${cfg.homeId}/state`;

      mqttClient.subscribe([schemaTopic, stateTopic], (err) => {
        if (!err) {
          console.log(`[MQTT] Subscribed to ${schemaTopic} & ${stateTopic}`);
        } else {
          console.error('[MQTT] Subscription failed:', err);
        }
      });
    });

    mqttClient.on('message', (topic, payload) => {
      try {
        const data = JSON.parse(payload.toString());
        const cfg = getSavedConfig();

        if (topic === `miniha/${cfg.homeId}/schema`) {
          handleSchemaUpdate(data);
        } else if (topic === `miniha/${cfg.homeId}/state`) {
          handleStateUpdate(data);
        }
      } catch (err) {
        console.error('[MQTT] Error parsing payload:', err);
      }
    });

    mqttClient.on('reconnect', () => {
      setStatus('Reconnecting...', 'connecting');
    });

    mqttClient.on('close', () => {
      setStatus('Disconnected', 'offline');
    });

    mqttClient.on('error', (err) => {
      console.error('[MQTT Error]', err);
      setStatus('Connection Error', 'offline');
    });
  } catch (err) {
    console.error('[MQTT Init Failed]', err);
    setStatus('Connection Failed', 'offline');
  }
}

// Handle Dynamic Schema Update (Re-builds UI on the fly when nodes change)
function handleSchemaUpdate(schema) {
  currentSchema = schema;
  const container = document.getElementById('nodesGrid');
  const emptyState = document.getElementById('emptyState');
  if (!container) return;

  if (!schema.nodes || schema.nodes.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    container.innerHTML = '';
    return;
  }

  if (emptyState) emptyState.style.display = 'none';

  let html = '';
  schema.nodes.forEach(node => {
    html += `
      <div class="node-card" id="card_${node.id}">
        <div class="node-header">
          <div class="node-title-group">
            <div class="node-name">${escapeHtml(node.name || node.id)}</div>
            <div class="node-id-badge">${escapeHtml(node.id)}</div>
          </div>
          <div class="node-status" id="status_${node.id}">
            <span class="status-indicator-dot dot-offline"></span>
            <span class="status-indicator-text">Syncing</span>
          </div>
        </div>

        <div class="slots-container" id="slots_${node.id}">
          ${renderSlots(node)}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  if (currentState) {
    handleStateUpdate(currentState);
  }
}

function renderSlots(node) {
  if (!node.slots || node.slots.length === 0) {
    return `<div class="empty-slots">No devices configured</div>`;
  }

  let out = '';
  node.slots.forEach(s => {
    const slotNum = s.slot;
    const type = s.type;
    const name = s.name || `Slot ${slotNum}`;

    if (type === 1) { // Relay
      out += `
        <div class="slot-item slot-relay">
          <div class="slot-info">
            <span class="slot-label">${escapeHtml(name)}</span>
            <span class="slot-state-text" id="relay_text_${node.id}_${slotNum}">OFF</span>
          </div>
          <button class="toggle-btn" id="btn_${node.id}_${slotNum}" onclick="toggleRelay('${node.id}', ${slotNum})">
            <span class="toggle-slider"></span>
          </button>
        </div>
      `;
    } else if (type === 6 || type === 7) { // DHT
      out += `
        <div class="slot-item slot-dht">
          <div class="slot-label">${escapeHtml(name)}</div>
          <div class="sensor-readings">
            <div class="sensor-pill">
              <span class="pill-label">TEMP</span>
              <span class="pill-val" id="temp_${node.id}">--</span>
              <span class="pill-unit">°C</span>
            </div>
            <div class="sensor-pill">
              <span class="pill-label">HUM</span>
              <span class="pill-val" id="hum_${node.id}">--</span>
              <span class="pill-unit">%</span>
            </div>
          </div>
        </div>
      `;
    } else if (type === 4 || type === 5) { // Ultrasonic
      if (type === 4) {
        out += `
          <div class="slot-item slot-tank">
            <div class="slot-header-inline">
              <span class="slot-label">${escapeHtml(name)}</span>
              <span class="tank-metric" id="dist_${node.id}">-- cm</span>
            </div>
            <div class="tank-bar-container">
              <div class="tank-bar-fill" id="tank_fill_${node.id}" style="width: 0%"></div>
            </div>
          </div>
        `;
      }
    }
  });

  return out;
}

// Handle Live State Updates from Master
function handleStateUpdate(stateMsg) {
  currentState = stateMsg;
  if (!stateMsg || !stateMsg.nodes) return;

  Object.keys(stateMsg.nodes).forEach(nodeId => {
    const n = stateMsg.nodes[nodeId];

    // 1. Update Online/Offline status
    const statusEl = document.getElementById(`status_${nodeId}`);
    if (statusEl) {
      if (n.online) {
        statusEl.innerHTML = `<span class="status-indicator-dot dot-online"></span><span class="status-indicator-text">Online</span>`;
      } else {
        statusEl.innerHTML = `<span class="status-indicator-dot dot-offline"></span><span class="status-indicator-text">Offline</span>`;
      }
    }

    // 2. Update DHT Sensor Readings
    const tempEl = document.getElementById(`temp_${nodeId}`);
    const humEl = document.getElementById(`hum_${nodeId}`);
    if (tempEl && n.temp !== undefined && n.temp > -50) tempEl.textContent = n.temp.toFixed(1);
    if (humEl && n.hum !== undefined && n.hum >= 0) humEl.textContent = n.hum.toFixed(0);

    // 3. Update Ultrasonic Readings
    const distEl = document.getElementById(`dist_${nodeId}`);
    const tankFillEl = document.getElementById(`tank_fill_${nodeId}`);
    if (distEl && n.dist !== undefined) {
      distEl.textContent = `${n.dist} cm`;
      let pct = Math.max(0, Math.min(100, Math.round(((200 - n.dist) / 200) * 100)));
      if (tankFillEl) tankFillEl.style.width = `${pct}%`;
    }

    // 4. Update Relays
    if (n.slots) {
      Object.keys(n.slots).forEach(slotNum => {
        const val = n.slots[slotNum];
        const btn = document.getElementById(`btn_${nodeId}_${slotNum}`);
        const text = document.getElementById(`relay_text_${nodeId}_${slotNum}`);

        if (btn) {
          if (val === 1) {
            btn.classList.add('active');
            if (text) text.textContent = 'ON';
          } else {
            btn.classList.remove('active');
            if (text) text.textContent = 'OFF';
          }
        }
      });
    }
  });
}

// User Action: Toggle Relay (Sends Command to Master via MQTT)
function toggleRelay(nodeId, slot) {
  const btn = document.getElementById(`btn_${nodeId}_${slot}`);
  const isCurrentlyActive = btn ? btn.classList.contains('active') : false;
  const targetState = isCurrentlyActive ? 0 : 1;

  // Optimistic UI update (instant visual feedback for parents)
  if (btn) {
    btn.classList.toggle('active');
    const text = document.getElementById(`relay_text_${nodeId}_${slot}`);
    if (text) text.textContent = targetState === 1 ? 'ON' : 'OFF';
  }

  const cfg = getSavedConfig();
  if (mqttClient && mqttClient.connected) {
    const cmdTopic = `miniha/${cfg.homeId}/set`;
    const payload = JSON.stringify({
      target: nodeId,
      slot: parseInt(slot),
      state: targetState
    });
    mqttClient.publish(cmdTopic, payload);
    console.log(`[CMD Published] ${cmdTopic} -> ${payload}`);
  } else if (cfg.localIp) {
    fetch(`${cfg.localIp}/api/control`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: nodeId, slot: parseInt(slot), val: targetState })
    }).catch(err => console.error('[Local Control Error]', err));
  } else {
    showToast('Not connected. Check internet.', 'error');
  }
}

// Share Modal & Family Invite Generation
function openShareModal() {
  const cfg = getSavedConfig();
  if (!cfg.brokerUrl) {
    showToast('Configure broker connection first', 'error');
    openSettingsModal();
    return;
  }

  const encoded = btoa(JSON.stringify({
    brokerUrl: cfg.brokerUrl,
    homeId: cfg.homeId,
    user: cfg.user,
    pass: cfg.pass,
    localIp: cfg.localIp
  }));

  const inviteUrl = `${window.location.origin}${window.location.pathname}#cfg=${encodeURIComponent(encoded)}`;
  document.getElementById('shareLinkInput').value = inviteUrl;

  const qrImg = document.getElementById('shareQrImg');
  if (qrImg) {
    qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(inviteUrl)}`;
  }

  const modal = document.getElementById('shareModal');
  if (modal) modal.style.display = 'flex';
}

function closeShareModal() {
  const modal = document.getElementById('shareModal');
  if (modal) modal.style.display = 'none';
}

function copyShareLink() {
  const input = document.getElementById('shareLinkInput');
  input.select();
  navigator.clipboard.writeText(input.value)
    .then(() => showToast('Invite link copied! Send to family via WhatsApp.', 'success'))
    .catch(() => showToast('Link selected. Press Copy.', 'info'));
}

function promptPasteLink() {
  const input = prompt('Paste your Family Invite Link or Code:');
  if (input && input.trim()) {
    const val = input.trim();
    let raw = '';
    if (val.includes('cfg=')) {
      raw = val.split('cfg=')[1].split('&')[0];
    } else {
      raw = val;
    }

    try {
      const decoded = JSON.parse(atob(raw));
      if (decoded.brokerUrl) {
        saveConfig(decoded);
        showToast('Home configured successfully!', 'success');
        connectMqtt();
        return;
      }
    } catch (e) {
      alert('Invalid invite link. Please check and try again.');
    }
  }
}

// Settings Modal Controls
function openSettingsModal() {
  const cfg = getSavedConfig();
  document.getElementById('modalBroker').value = cfg.brokerUrl;
  document.getElementById('modalHomeId').value = cfg.homeId;
  document.getElementById('modalUser').value = cfg.user;
  document.getElementById('modalPass').value = cfg.pass;
  document.getElementById('modalLocalIp').value = cfg.localIp;

  const modal = document.getElementById('settingsModal');
  if (modal) modal.style.display = 'flex';
}

function closeSettingsModal() {
  const modal = document.getElementById('settingsModal');
  if (modal) modal.style.display = 'none';
}

function saveAndConnect() {
  const broker = document.getElementById('modalBroker').value.trim();
  const homeId = document.getElementById('modalHomeId').value.trim() || 'home_1';
  const user = document.getElementById('modalUser').value.trim();
  const pass = document.getElementById('modalPass').value;
  const localIp = document.getElementById('modalLocalIp').value.trim();

  saveConfig({
    brokerUrl: broker,
    homeId: homeId,
    user: user,
    pass: pass,
    localIp: localIp
  });

  closeSettingsModal();
  showToast('Settings saved. Connecting...', 'info');
  connectMqtt();
}

// Toast Notifications
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast');
  if (!container) return;
  container.textContent = msg;
  container.className = `toast toast-${type} show`;
  setTimeout(() => {
    container.classList.remove('show');
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, function(m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
  });
}

// Boot Sequence
window.addEventListener('DOMContentLoaded', () => {
  // 1. Check if user opened an invite link
  const hadInvite = checkUrlInvite();
  // 2. Connect if config exists
  const cfg = getSavedConfig();
  if (cfg.brokerUrl) {
    connectMqtt();
  } else {
    setStatus('Ready to Connect', 'offline');
    const emptyState = document.getElementById('emptyState');
    if (emptyState) emptyState.style.display = 'block';
  }
});
