// Mini-HA PWA: Multi-User & Home Architecture Engine
let mqttClient = null;
let currentSchema = null;
let currentState = null;
let authReplyCallback = null;

// Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then(reg => console.log('[PWA] SW registered:', reg.scope))
      .catch(err => console.warn('[PWA] SW registration failed:', err));
  });
}

// =========================================================================
// STORAGE: LEVEL 1 (HOME) & LEVEL 2 (USER IN HOME)
// =========================================================================

function getHomeConfig() {
  return {
    brokerUrl: localStorage.getItem('miniha_broker') || '',
    homeId: localStorage.getItem('miniha_home_id') || 'home_1',
    user: localStorage.getItem('miniha_user') || '',
    pass: localStorage.getItem('miniha_pass') || '',
    localIp: localStorage.getItem('miniha_local_ip') || ''
  };
}

function saveHomeConfig(cfg) {
  localStorage.setItem('miniha_broker', (cfg.brokerUrl || '').trim());
  localStorage.setItem('miniha_home_id', (cfg.homeId || 'home_1').trim());
  localStorage.setItem('miniha_user', (cfg.user || '').trim());
  localStorage.setItem('miniha_pass', cfg.pass || '');
  localStorage.setItem('miniha_local_ip', (cfg.localIp || '').trim());
}

function getUserSession() {
  return {
    token: localStorage.getItem('miniha_session_token') || '',
    user: localStorage.getItem('miniha_session_user') || '',
    role: localStorage.getItem('miniha_session_role') || ''
  };
}

function saveUserSession(session) {
  localStorage.setItem('miniha_session_token', session.token || '');
  localStorage.setItem('miniha_session_user', session.user || '');
  localStorage.setItem('miniha_session_role', session.role || 'guest');
}

function clearUserSession() {
  localStorage.removeItem('miniha_session_token');
  localStorage.removeItem('miniha_session_user');
  localStorage.removeItem('miniha_session_role');
}

function clearAllHomeData() {
  localStorage.clear();
}

// =========================================================================
// UI VIEW CONTROLLER (3 MUTUALLY EXCLUSIVE SCREENS)
// =========================================================================

function updateView() {
  const home = getHomeConfig();
  const session = getUserSession();

  const emptyHome = document.getElementById('emptyHomeState');
  const userLogin = document.getElementById('userLoginCard');
  const dashboard = document.getElementById('nodesGrid');
  const userBadge = document.getElementById('userBadge');
  const userBadgeName = document.getElementById('userBadgeName');

  // Screen 1: No Home Configured
  if (!home.brokerUrl) {
    if (emptyHome) emptyHome.style.display = 'block';
    if (userLogin) userLogin.style.display = 'none';
    if (dashboard) dashboard.style.display = 'none';
    if (userBadge) userBadge.style.display = 'none';
    setStatus('No Home', 'offline');
    return;
  }

  // Screen 2: Home Connected, but No Active User Logged In
  if (!session.token) {
    if (emptyHome) emptyHome.style.display = 'none';
    if (userLogin) userLogin.style.display = 'block';
    if (dashboard) dashboard.style.display = 'none';
    if (userBadge) userBadge.style.display = 'none';
    const tag = document.getElementById('loginHomeTag');
    if (tag) tag.textContent = `Home: ${home.homeId}`;
    return;
  }

  // Screen 3: User Logged In & Home Connected -> Show Live Dashboard
  if (emptyHome) emptyHome.style.display = 'none';
  if (userLogin) userLogin.style.display = 'none';
  if (dashboard) dashboard.style.display = 'flex';
  if (userBadge) {
    userBadge.style.display = 'flex';
    if (userBadgeName) {
      userBadgeName.textContent = `👤 ${session.user} (${session.role})`;
    }
  }

  // Re-render if schema already loaded
  if (currentSchema) handleSchemaUpdate(currentSchema);
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

// =========================================================================
// MQTT CLIENT & TRANSPORT
// =========================================================================

function connectMqtt() {
  const home = getHomeConfig();
  if (!home.brokerUrl) {
    updateView();
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
    username: home.user || undefined,
    password: home.pass || undefined
  };

  try {
    mqttClient = mqtt.connect(home.brokerUrl, options);

    mqttClient.on('connect', () => {
      console.log('[MQTT] Connected to broker');
      setStatus('Online', 'online');

      const schemaTopic = `miniha/${home.homeId}/schema`;
      const stateTopic = `miniha/${home.homeId}/state`;
      const authReplyWildcard = `miniha/${home.homeId}/auth/reply/+`;

      mqttClient.subscribe([schemaTopic, stateTopic, authReplyWildcard], (err) => {
        if (!err) {
          console.log(`[MQTT] Subscribed to ${home.homeId} topics`);
        } else {
          console.error('[MQTT] Subscription error:', err);
        }
      });
    });

    mqttClient.on('message', (topic, payload) => {
      try {
        const data = JSON.parse(payload.toString());
        const home = getHomeConfig();

        if (topic === `miniha/${home.homeId}/schema`) {
          handleSchemaUpdate(data);
        } else if (topic === `miniha/${home.homeId}/state`) {
          handleStateUpdate(data);
        } else if (topic.startsWith(`miniha/${home.homeId}/auth/reply/`)) {
          if (authReplyCallback) {
            authReplyCallback(data);
          }
        }
      } catch (err) {
        console.error('[MQTT Payload Error]', err);
      }
    });

    mqttClient.on('reconnect', () => setStatus('Reconnecting...', 'connecting'));
    mqttClient.on('close', () => setStatus('Disconnected', 'offline'));
    mqttClient.on('error', (err) => {
      console.error('[MQTT Error]', err);
      setStatus('Conn Error', 'offline');
    });
  } catch (err) {
    console.error('[MQTT Init Failed]', err);
    setStatus('Conn Failed', 'offline');
  }
}

// =========================================================================
// LEVEL 2: USER LOGIN & SWITCH USER
// =========================================================================

function submitUserLogin() {
  const username = document.getElementById('loginUser').value.trim();
  const password = document.getElementById('loginPass').value;
  const loginBtn = document.getElementById('loginBtn');

  if (!username || !password) {
    showToast('Enter username and password', 'error');
    return;
  }

  if (loginBtn) {
    loginBtn.textContent = 'Verifying...';
    loginBtn.disabled = true;
  }

  const home = getHomeConfig();

  // Route 1: Over MQTT
  if (mqttClient && mqttClient.connected) {
    const clientReqId = 'pwa_' + Math.random().toString(16).substr(2, 6);
    const loginTopic = `miniha/${home.homeId}/auth/login`;

    let resolved = false;
    authReplyCallback = (reply) => {
      resolved = true;
      authReplyCallback = null;
      if (loginBtn) {
        loginBtn.textContent = 'Log In';
        loginBtn.disabled = false;
      }

      if (reply.status === 'ok' && reply.token) {
        saveUserSession({
          token: reply.token,
          user: reply.user,
          role: reply.role
        });
        showToast(`Welcome, ${reply.user}!`, 'success');
        document.getElementById('loginUser').value = '';
        document.getElementById('loginPass').value = '';
        updateView();
      } else {
        showToast(reply.error || 'Invalid credentials', 'error');
      }
    };

    // Timeout safety
    setTimeout(() => {
      if (!resolved) {
        authReplyCallback = null;
        if (loginBtn) {
          loginBtn.textContent = 'Log In';
          loginBtn.disabled = false;
        }
        showToast('Login timed out. Check Master Hub.', 'error');
      }
    }, 6000);

    mqttClient.publish(loginTopic, JSON.stringify({
      client: clientReqId,
      user: username,
      pass: password
    }));
  }
  // Route 2: Over Local LAN HTTP
  else if (home.localIp) {
    fetch(`${home.localIp}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: username, pass: password })
    })
    .then(r => r.json())
    .then(reply => {
      if (loginBtn) {
        loginBtn.textContent = 'Log In';
        loginBtn.disabled = false;
      }
      if (reply.status === 'ok' && reply.token) {
        saveUserSession({
          token: reply.token,
          user: reply.user,
          role: reply.role
        });
        showToast(`Welcome, ${reply.user}!`, 'success');
        updateView();
      } else {
        showToast(reply.error || 'Invalid credentials', 'error');
      }
    })
    .catch(err => {
      if (loginBtn) {
        loginBtn.textContent = 'Log In';
        loginBtn.disabled = false;
      }
      showToast('Connection error', 'error');
    });
  } else {
    if (loginBtn) {
      loginBtn.textContent = 'Log In';
      loginBtn.disabled = false;
    }
    showToast('Not connected to Home yet. Please wait.', 'error');
  }
}

// Switch User (Logs out user, keeps Home connection!)
function switchUser() {
  clearUserSession();
  closeUserMenuModal();
  showToast('Logged out. Please log in as another user.', 'info');
  updateView();
  const input = document.getElementById('loginUser');
  if (input) input.focus();
}

// Unlink Home (Logs out user AND unlinks Home config)
function unlinkHome() {
  if (confirm('Unlink this phone from this Home? You will need an invite link to reconnect.')) {
    clearAllHomeData();
    closeUserMenuModal();
    if (mqttClient) {
      try { mqttClient.end(true); } catch(e) {}
    }
    showToast('Home unlinked.', 'info');
    updateView();
  }
}

// User Menu Modal
function openUserMenuModal() {
  const session = getUserSession();
  const home = getHomeConfig();
  document.getElementById('menuUserName').textContent = session.user || 'Unknown';
  document.getElementById('menuUserRole').textContent = `Role: ${session.role || 'Guest'}`;
  document.getElementById('menuHomeId').textContent = `Home: ${home.homeId}`;
  const modal = document.getElementById('userMenuModal');
  if (modal) modal.style.display = 'flex';
}

function closeUserMenuModal() {
  const modal = document.getElementById('userMenuModal');
  if (modal) modal.style.display = 'none';
}

// =========================================================================
// DYNAMIC SCHEMA & DASHBOARD RENDERING
// =========================================================================

function handleSchemaUpdate(schema) {
  currentSchema = schema;
  const session = getUserSession();
  if (!session.token) return; // Do not render dashboard if not logged in

  const container = document.getElementById('nodesGrid');
  if (!container) return;

  if (!schema.nodes || schema.nodes.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-sub);">No devices bound to this Home yet.</div>';
    return;
  }

  const isGuest = (session.role === 'guest');

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
          ${renderSlots(node, isGuest)}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  if (currentState) {
    handleStateUpdate(currentState);
  }
}

function renderSlots(node, isGuest) {
  if (!node.slots || node.slots.length === 0) {
    return `<div style="color:var(--text-sub); font-size:12px;">No slots configured</div>`;
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
          <button class="toggle-btn" id="btn_${node.id}_${slotNum}" ${isGuest ? 'disabled title="Guests cannot toggle controls"' : ''} onclick="toggleRelay('${node.id}', ${slotNum})">
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

    const statusEl = document.getElementById(`status_${nodeId}`);
    if (statusEl) {
      if (n.online) {
        statusEl.innerHTML = `<span class="status-indicator-dot dot-online"></span><span class="status-indicator-text">Online</span>`;
      } else {
        statusEl.innerHTML = `<span class="status-indicator-dot dot-offline"></span><span class="status-indicator-text">Offline</span>`;
      }
    }

    const tempEl = document.getElementById(`temp_${nodeId}`);
    const humEl = document.getElementById(`hum_${nodeId}`);
    if (tempEl && n.temp !== undefined && n.temp > -50) tempEl.textContent = n.temp.toFixed(1);
    if (humEl && n.hum !== undefined && n.hum >= 0) humEl.textContent = n.hum.toFixed(0);

    const distEl = document.getElementById(`dist_${nodeId}`);
    const tankFillEl = document.getElementById(`tank_fill_${nodeId}`);
    if (distEl && n.dist !== undefined) {
      distEl.textContent = `${n.dist} cm`;
      let pct = Math.max(0, Math.min(100, Math.round(((200 - n.dist) / 200) * 100)));
      if (tankFillEl) tankFillEl.style.width = `${pct}%`;
    }

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

// User Action: Toggle Relay (Sends Command with Token to Master)
function toggleRelay(nodeId, slot) {
  const session = getUserSession();
  if (!session.token) {
    showToast('Please log in first', 'error');
    updateView();
    return;
  }
  if (session.role === 'guest') {
    showToast('Guests have read-only access', 'error');
    return;
  }

  const btn = document.getElementById(`btn_${nodeId}_${slot}`);
  const isCurrentlyActive = btn ? btn.classList.contains('active') : false;
  const targetState = isCurrentlyActive ? 0 : 1;

  // Optimistic UI update
  if (btn) {
    btn.classList.toggle('active');
    const text = document.getElementById(`relay_text_${nodeId}_${slot}`);
    if (text) text.textContent = targetState === 1 ? 'ON' : 'OFF';
  }

  const home = getHomeConfig();
  if (mqttClient && mqttClient.connected) {
    const cmdTopic = `miniha/${home.homeId}/set`;
    const payload = JSON.stringify({
      token: session.token,
      target: nodeId,
      slot: parseInt(slot),
      state: targetState
    });
    mqttClient.publish(cmdTopic, payload);
  } else if (home.localIp) {
    fetch(`${home.localIp}/api/control`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Token': session.token
      },
      body: JSON.stringify({ target: nodeId, slot: parseInt(slot), val: targetState })
    }).catch(err => console.error('[Local Control Error]', err));
  } else {
    showToast('Not connected. Check internet.', 'error');
  }
}

// =========================================================================
// INVITES & SHARING
// =========================================================================

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
        saveHomeConfig(parsed);
        history.replaceState(null, '', window.location.pathname);
        showToast('Connected to Home! Please log in.', 'success');
        return true;
      }
    } catch (e) {
      console.error('[Invite Parse Failed]', e);
    }
  }
  return false;
}

function openShareModal() {
  const home = getHomeConfig();
  if (!home.brokerUrl) {
    showToast('Configure home connection first', 'error');
    openSettingsModal();
    return;
  }

  const encoded = btoa(JSON.stringify({
    brokerUrl: home.brokerUrl,
    homeId: home.homeId,
    user: home.user,
    pass: home.pass,
    localIp: home.localIp
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
    .then(() => showToast('Home Invite link copied! Send via WhatsApp.', 'success'))
    .catch(() => showToast('Link selected. Press Copy.', 'info'));
}

function promptPasteLink() {
  const input = prompt('Paste your Home Invite Link or Code:');
  if (input && input.trim()) {
    const val = input.trim();
    let raw = val.includes('cfg=') ? val.split('cfg=')[1].split('&')[0] : val;
    try {
      const decoded = JSON.parse(atob(raw));
      if (decoded.brokerUrl) {
        saveHomeConfig(decoded);
        showToast('Home connected! Please log in.', 'success');
        connectMqtt();
        updateView();
        return;
      }
    } catch (e) {
      alert('Invalid home invite link.');
    }
  }
}

// Settings Modal Controls (Admin)
function openSettingsModal() {
  const home = getHomeConfig();
  document.getElementById('modalBroker').value = home.brokerUrl;
  document.getElementById('modalHomeId').value = home.homeId;
  document.getElementById('modalUser').value = home.user;
  document.getElementById('modalPass').value = home.pass;
  document.getElementById('modalLocalIp').value = home.localIp;

  const modal = document.getElementById('settingsModal');
  if (modal) modal.style.display = 'flex';
}

function closeSettingsModal() {
  const modal = document.getElementById('settingsModal');
  if (modal) modal.style.display = 'none';
}

function saveHomeAndConnect() {
  saveHomeConfig({
    brokerUrl: document.getElementById('modalBroker').value.trim(),
    homeId: document.getElementById('modalHomeId').value.trim() || 'home_1',
    user: document.getElementById('modalUser').value.trim(),
    pass: document.getElementById('modalPass').value,
    localIp: document.getElementById('modalLocalIp').value.trim()
  });

  closeSettingsModal();
  showToast('Home settings saved. Connecting...', 'info');
  connectMqtt();
  updateView();
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
  checkUrlInvite();
  updateView();
  const home = getHomeConfig();
  if (home.brokerUrl) {
    connectMqtt();
  }
});
