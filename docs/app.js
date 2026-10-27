// Mini-HA PWA: Architecture & Fallback Engine
let mqttClient = null;
let currentSchema = null;
let currentState = null;
let authReplyCallback = null;
let isHubOnline = false;
let activeTransport = 'none'; // 'cloud' | 'local' | 'none'
let localPollTimer = null;

// Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then(reg => console.log('[PWA] SW registered:', reg.scope))
      .catch(err => console.warn('[PWA] SW registration failed:', err));
  });
}

// =========================================================================
// STORAGE: LEVEL 1 (HOME CONFIG) & LEVEL 2 (USER SESSION)
// =========================================================================

function getHomeConfig() {
  return {
    brokerUrl: localStorage.getItem('miniha_broker') || '',
    homeId: localStorage.getItem('miniha_home_id') || '',
    user: localStorage.getItem('miniha_user') || '',
    pass: localStorage.getItem('miniha_pass') || '',
    localIp: localStorage.getItem('miniha_local_ip') || ''
  };
}

function saveHomeConfig(cfg) {
  localStorage.setItem('miniha_broker', (cfg.brokerUrl || '').trim());
  localStorage.setItem('miniha_home_id', (cfg.homeId || '').trim());
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
// UI VIEW CONTROLLER (3 SCREENS: ONBOARD -> LOGIN -> DASHBOARD)
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
  if (!home.brokerUrl && !home.localIp) {
    if (emptyHome) emptyHome.style.display = 'block';
    if (userLogin) userLogin.style.display = 'none';
    if (dashboard) dashboard.style.display = 'none';
    if (userBadge) userBadge.style.display = 'none';
    setStatus('No Gateway', 'offline');
    return;
  }

  // Screen 2: Gateway Configured, but No User Session
  if (!session.token) {
    if (emptyHome) emptyHome.style.display = 'none';
    if (userLogin) userLogin.style.display = 'block';
    if (dashboard) dashboard.style.display = 'none';
    if (userBadge) userBadge.style.display = 'none';
    const tag = document.getElementById('loginHomeTag');
    if (tag) tag.textContent = `Home: ${home.homeId || 'Default'}`;
    return;
  }

  // Screen 3: User Logged In -> Show Live Dashboard
  if (emptyHome) emptyHome.style.display = 'none';
  if (userLogin) userLogin.style.display = 'none';
  if (dashboard) dashboard.style.display = 'grid';
  if (userBadge) {
    userBadge.style.display = 'flex';
    if (userBadgeName) {
      userBadgeName.textContent = `${session.user} (${session.role})`;
    }
  }

  if (currentSchema) handleSchemaUpdate(currentSchema);
}

// Status Indicator Controller
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

function updateHubOfflineBanner() {
  const banner = document.getElementById('hubOfflineBanner');
  if (banner) {
    banner.style.display = isHubOnline ? 'none' : 'flex';
  }
  const session = getUserSession();
  const isGuest = (session.role === 'guest');
  const cannotToggle = (!isHubOnline || isGuest);
  const disabledTitle = !isHubOnline ? 'Master Hub is offline' : (isGuest ? 'Guests cannot toggle controls' : '');

  document.querySelectorAll('.toggle-btn').forEach(btn => {
    btn.disabled = cannotToggle;
    btn.title = disabledTitle;
  });
}

// =========================================================================
// UNIFIED TRANSPORT ENGINE: CLOUD MQTT WITH AUTOMATIC LAN FALLBACK
// =========================================================================

function connectGateway() {
  const home = getHomeConfig();

  if (localPollTimer) {
    clearInterval(localPollTimer);
    localPollTimer = null;
  }

  // If no Home Gateway is configured at all, stay on Screen 1 and do not probe anything
  if (!home.brokerUrl && !home.localIp) {
    updateView();
    return;
  }

  // 1. If Cloud Broker is configured, attempt MQTT connection first
  if (home.brokerUrl) {
    connectMqtt();
  } else if (home.localIp) {
    // Only start local polling if user explicitly provided a local IP address
    startLocalFallback();
  } else {
    updateView();
  }
}

function connectMqtt() {
  const home = getHomeConfig();
  if (!home.brokerUrl) return;

  if (mqttClient) {
    try { mqttClient.end(true); } catch (e) {}
  }

  setStatus('Connecting...', 'connecting');

  const clientId = 'miniha_pwa_' + Math.random().toString(16).substr(2, 8);
  const options = {
    clientId: clientId,
    clean: true,
    connectTimeout: 7000,
    reconnectPeriod: 5000,
    username: home.user || undefined,
    password: home.pass || undefined
  };

  try {
    mqttClient = mqtt.connect(home.brokerUrl, options);

    mqttClient.on('connect', () => {
      console.log('[MQTT] Connected to cloud broker');
      activeTransport = 'cloud';
      if (isHubOnline) {
        setStatus('Cloud Online', 'online');
      } else {
        setStatus('Broker Connected (Hub Offline)', 'offline');
      }

      // Stop redundant local LAN polling when cloud is healthy
      if (localPollTimer) {
        clearInterval(localPollTimer);
        localPollTimer = null;
      }

      const schemaTopic = `miniha/${home.homeId}/schema`;
      const stateTopic = `miniha/${home.homeId}/state`;
      const statusTopic = `miniha/${home.homeId}/status`;
      const notifyTopic = `miniha/${home.homeId}/notify`;
      const authReplyWildcard = `miniha/${home.homeId}/auth/reply/+`;

      mqttClient.subscribe([schemaTopic, stateTopic, statusTopic, notifyTopic, authReplyWildcard], (err) => {
        if (!err) {
          console.log(`[MQTT] Subscribed to ${home.homeId}`);
        } else {
          console.error('[MQTT] Subscribe error:', err);
        }
      });
    });

    mqttClient.on('message', (topic, payload) => {
      try {
        const data = JSON.parse(payload.toString());
        const home = getHomeConfig();

        if (topic === `miniha/${home.homeId}/status`) {
          handleHubStatusUpdate(data);
        } else if (topic === `miniha/${home.homeId}/notify`) {
          handleNotification(data);
        } else if (topic === `miniha/${home.homeId}/schema`) {
          handleSchemaUpdate(data);
        } else if (topic === `miniha/${home.homeId}/state`) {
          handleStateUpdate(data);
        } else if (topic.startsWith(`miniha/${home.homeId}/auth/reply/`)) {
          if (authReplyCallback) {
            authReplyCallback(data);
          }
        }
      } catch (err) {
        console.error('[MQTT Parse Error]', err);
      }
    });

    mqttClient.on('reconnect', () => {
      if (activeTransport !== 'local') {
        setStatus('Reconnecting...', 'connecting');
      }
    });

    mqttClient.on('close', () => {
      console.warn('[MQTT] Disconnected from cloud broker. Activating local fallback...');
      triggerFailoverToLocal();
    });

    mqttClient.on('error', (err) => {
      console.warn('[MQTT Error]', err);
      triggerFailoverToLocal();
    });
  } catch (err) {
    console.error('[MQTT Init Failed]', err);
    triggerFailoverToLocal();
  }
}

function triggerFailoverToLocal() {
  const home = getHomeConfig();
  if (home.localIp) {
    startLocalFallback();
  } else {
    activeTransport = 'none';
    setStatus('Offline', 'offline');
  }
}

// Local LAN Fallback Polling Engine
function startLocalFallback() {
  const home = getHomeConfig();
  if (!home.localIp) {
    activeTransport = 'none';
    setStatus('Offline', 'offline');
    return;
  }
  if (localPollTimer) return; // Already active

  console.log('[LAN Fallback] Starting local HTTP polling against:', home.localIp);
  pollLocalState();
  localPollTimer = setInterval(pollLocalState, 4000);
}

async function pollLocalState() {
  const home = getHomeConfig();
  if (!home.localIp) return;

  const session = getUserSession();
  const headers = { 'Accept': 'application/json' };
  if (session.token) {
    headers['X-Auth-Token'] = session.token;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2800);

    // Fetch schema and state concurrently
    const [nodesRes, stateRes] = await Promise.all([
      fetch(`${home.localIp}/api/nodes`, { headers, signal: controller.signal }),
      fetch(`${home.localIp}/api/state`, { headers, signal: controller.signal })
    ]);
    clearTimeout(timeoutId);

    if (nodesRes.ok && stateRes.ok) {
      const nodesData = await nodesRes.json();
      const stateData = await stateRes.json();

      activeTransport = 'local';
      setStatus('LAN Fallback', 'online');
      isHubOnline = true;
      updateHubOfflineBanner();

      if (nodesData && nodesData.nodes) {
        handleSchemaUpdate(nodesData);
      }
      if (stateData) {
        handleStateUpdate(stateData);
      }
    } else {
      throw new Error(`HTTP ${nodesRes.status}`);
    }
  } catch (err) {
    // If MQTT is also down and local HTTP fails, mark as offline
    if (!mqttClient || !mqttClient.connected) {
      activeTransport = 'none';
      setStatus('Offline', 'offline');
      isHubOnline = false;
      updateHubOfflineBanner();
    }
  }
}

// =========================================================================
// LEVEL 2: USER LOGIN & AUTHENTICATION
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

  // Route A: Over Cloud MQTT (if connected)
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

    setTimeout(() => {
      if (!resolved) {
        authReplyCallback = null;
        // Fall back to local HTTP attempt if available
        if (home.localIp) {
          submitLocalHttpLogin(username, password, loginBtn);
        } else {
          if (loginBtn) {
            loginBtn.textContent = 'Log In';
            loginBtn.disabled = false;
          }
          showToast('Login timed out. Check Master Hub.', 'error');
        }
      }
    }, 4500);

    mqttClient.publish(loginTopic, JSON.stringify({
      client: clientReqId,
      user: username,
      pass: password
    }));
  }
  // Route B: Over Local LAN HTTP
  else if (home.localIp) {
    submitLocalHttpLogin(username, password, loginBtn);
  } else {
    if (loginBtn) {
      loginBtn.textContent = 'Log In';
      loginBtn.disabled = false;
    }
    showToast('Gateway not reachable. Check network.', 'error');
  }
}

function submitLocalHttpLogin(username, password, loginBtn) {
  const home = getHomeConfig();
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
      document.getElementById('loginUser').value = '';
      document.getElementById('loginPass').value = '';
      updateView();
      // Kick off immediate state sync over local LAN
      pollLocalState();
    } else {
      showToast(reply.error || 'Invalid credentials', 'error');
    }
  })
  .catch(err => {
    if (loginBtn) {
      loginBtn.textContent = 'Log In';
      loginBtn.disabled = false;
    }
    showToast('Could not reach Master Hub over LAN', 'error');
  });
}

function switchUser() {
  clearUserSession();
  closeUserMenuModal();
  showToast('Logged out. Please log in as another user.', 'info');
  updateView();
  const input = document.getElementById('loginUser');
  if (input) input.focus();
}

function unlinkHome() {
  if (confirm('Unlink this device from this Home? You will need an invite link or manual setup to reconnect.')) {
    clearAllHomeData();
    closeUserMenuModal();
    if (mqttClient) {
      try { mqttClient.end(true); } catch(e) {}
    }
    if (localPollTimer) {
      clearInterval(localPollTimer);
      localPollTimer = null;
    }
    showToast('Home unlinked.', 'info');
    updateView();
  }
}

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
// DASHBOARD RENDERING & CONTROL DISPATCH
// =========================================================================

function handleSchemaUpdate(schema) {
  currentSchema = schema;
  const session = getUserSession();
  if (!session.token) return;

  const container = document.getElementById('nodesGrid');
  if (!container) return;

  if (!schema.nodes || schema.nodes.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:32px; color:var(--text-dim); grid-column:1/-1;">No hardware nodes bound to this Home yet.</div>';
    return;
  }

  const isGuest = (session.role === 'guest');

  let html = '';
  schema.nodes.forEach(node => {
    html += `
      <div class="node-card" id="card_${node.id}">
        <div class="node-header">
          <div class="node-title-group">
            <span class="node-name">${escapeHtml(node.name || node.id)}</span>
            <span class="node-id-chip">${escapeHtml(node.id)}</span>
          </div>
          <div class="node-status" id="status_${node.id}">
            <span class="status-dot dot-offline"></span>
            <span>Syncing</span>
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
    return `<div style="color:var(--text-dim); font-size:12px; padding:6px 0;">No active slots configured</div>`;
  }

  let out = '';
  node.slots.forEach(s => {
    const slotNum = s.slot;
    const type = s.type;
    const name = s.name || `Slot ${slotNum}`;

    if (type === 1) { // Relay Actuator
      const cannotToggle = (!isHubOnline || isGuest);
      const disabledTitle = !isHubOnline ? 'Master Hub is offline' : (isGuest ? 'Guests cannot toggle controls' : '');
      out += `
        <div class="slot-relay">
          <div class="slot-info">
            <span class="slot-label">${escapeHtml(name)}</span>
            <span class="slot-state-text" id="relay_text_${node.id}_${slotNum}">OFF</span>
          </div>
          <button class="toggle-btn" id="btn_${node.id}_${slotNum}" ${cannotToggle ? `disabled title="${disabledTitle}"` : ''} onclick="toggleRelay('${node.id}', ${slotNum})">
            <span class="toggle-slider"></span>
          </button>
        </div>
      `;
    } else if (type === 6 || type === 7) { // DHT Sensor
      out += `
        <div class="slot-dht">
          <div class="sensor-readings">
            <div class="sensor-pill">
              <span class="pill-label">TEMP</span>
              <div class="pill-value-group">
                <span class="pill-val" id="temp_${node.id}">--</span>
                <span class="pill-unit">&deg;C</span>
              </div>
            </div>
            <div class="sensor-pill">
              <span class="pill-label">HUMIDITY</span>
              <div class="pill-value-group">
                <span class="pill-val" id="hum_${node.id}">--</span>
                <span class="pill-unit">%</span>
              </div>
            </div>
          </div>
        </div>
      `;
    } else if (type === 4 || type === 5) { // Ultrasonic Sensor
      if (type === 4) {
        out += `
          <div class="slot-tank">
            <div class="tank-header-row">
              <span class="slot-label">${escapeHtml(name)}</span>
              <span class="pill-val" style="font-size:13px;" id="dist_${node.id}">-- cm</span>
            </div>
            <div class="tank-bar-track">
              <div class="tank-bar-fluid" id="tank_fill_${node.id}" style="width: 0%"></div>
            </div>
          </div>
        `;
      }
    }
  });

  return out;
}

function handleStateUpdate(stateMsg) {
  currentState = stateMsg;
  if (!stateMsg || !stateMsg.nodes) return;

  Object.keys(stateMsg.nodes).forEach(nodeId => {
    const n = stateMsg.nodes[nodeId];

    const statusEl = document.getElementById(`status_${nodeId}`);
    if (statusEl) {
      if (n.online) {
        statusEl.innerHTML = `<span class="status-dot dot-online"></span><span style="color:var(--text-muted);">Online</span>`;
      } else {
        statusEl.innerHTML = `<span class="status-dot dot-offline"></span><span style="color:var(--danger);">Offline</span>`;
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

function toggleRelay(nodeId, slot) {
  if (!isHubOnline) {
    showToast('Master Hub is offline. Controls locked.', 'error');
    return;
  }
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

  // Dispatch over Cloud MQTT if connected
  if (activeTransport === 'cloud' && mqttClient && mqttClient.connected) {
    const cmdTopic = `miniha/${home.homeId}/set`;
    const payload = JSON.stringify({
      token: session.token,
      target: nodeId,
      slot: parseInt(slot),
      state: targetState
    });
    mqttClient.publish(cmdTopic, payload);
  }
  // Dispatch over Local LAN Fallback if reachable
  else if (home.localIp) {
    fetch(`${home.localIp}/api/control`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Token': session.token
      },
      body: JSON.stringify({ target: nodeId, slot: parseInt(slot), val: targetState })
    })
    .then(r => r.json())
    .then(res => {
      if (res && res.status === 'ok') {
        // Success
      } else {
        // Revert toggle
        if (btn) btn.classList.toggle('active');
        showToast(res.error || 'Control rejected', 'error');
      }
    })
    .catch(err => {
      if (btn) btn.classList.toggle('active');
      showToast('Local control failed. Check hub.', 'error');
    });
  } else {
    if (btn) btn.classList.toggle('active');
    showToast('No connection to Hub.', 'error');
  }
}

// =========================================================================
// ONBOARDING & SHARING
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
      if (parsed.brokerUrl || parsed.localIp) {
        saveHomeConfig(parsed);
        history.replaceState(null, '', window.location.pathname);
        showToast('Gateway configured via invite! Please log in.', 'success');
        return true;
      }
    } catch (e) {
      console.error('[Invite Parse Failed]', e);
    }
  }
  return false;
}

function switchOnboardTab(tab) {
  const inv = document.getElementById('onboardInviteSection');
  const man = document.getElementById('onboardManualSection');
  if (inv) inv.style.display = (tab === 'invite') ? 'block' : 'none';
  if (man) man.style.display = (tab === 'manual') ? 'block' : 'none';
  
  const bInv = document.getElementById('tabBtnInvite');
  const bMan = document.getElementById('tabBtnManual');
  if (bInv) bInv.className = 'segment-tab ' + (tab === 'invite' ? 'active' : '');
  if (bMan) bMan.className = 'segment-tab ' + (tab === 'manual' ? 'active' : '');
}

function applyPastedLink() {
  const input = document.getElementById('pasteLinkInput').value.trim();
  if (!input) return showToast('Paste an invite link first', 'error');
  try {
    let raw = input;
    if (input.includes('cfg=')) {
      raw = input.split('cfg=')[1].split('&')[0];
    }
    const parsed = JSON.parse(atob(decodeURIComponent(raw)));
    if (parsed.brokerUrl || parsed.localIp) {
      saveHomeConfig(parsed);
      showToast('Gateway connected! Please log in.', 'success');
      connectGateway();
      updateView();
    } else {
      throw new Error('Invalid config');
    }
  } catch (e) {
    showToast('Invalid invite link format', 'error');
  }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById('pasteLinkInput').value = text;
    applyPastedLink();
  } catch (e) {
    showToast('Could not access clipboard. Paste manually.', 'error');
  }
}

function saveQuickGatewayConfig() {
  const homeId = document.getElementById('quickHomeId').value.trim();
  const broker = document.getElementById('quickBrokerUrl').value.trim();
  const user = document.getElementById('quickBrokerUser').value.trim();
  const pass = document.getElementById('quickBrokerPass').value;
  const localIp = document.getElementById('quickLocalIp').value.trim();

  if (!broker && !localIp) {
    showToast('Please enter a Cloud Broker URL or Local Address', 'error');
    return;
  }
  if (broker && !homeId) {
    showToast('Please enter a Home ID for your cloud setup', 'error');
    return;
  }

  saveHomeConfig({
    brokerUrl: broker,
    homeId: homeId,
    user: user,
    pass: pass,
    localIp: localIp
  });

  showToast('Gateway settings saved. Connecting...', 'info');
  connectGateway();
  updateView();
}

function openShareModal() {
  const home = getHomeConfig();
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
    .then(() => showToast('Invite link copied to clipboard', 'success'))
    .catch(() => showToast('Link selected. Press Copy.', 'info'));
}

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
  const broker = document.getElementById('modalBroker').value.trim();
  const homeId = document.getElementById('modalHomeId').value.trim();
  const localIp = document.getElementById('modalLocalIp').value.trim();

  if (!broker && !localIp) {
    showToast('Please enter a Cloud Broker URL or Local Address', 'error');
    return;
  }

  saveHomeConfig({
    brokerUrl: broker,
    homeId: homeId,
    user: document.getElementById('modalUser').value.trim(),
    pass: document.getElementById('modalPass').value,
    localIp: localIp
  });

  closeSettingsModal();
  showToast('Settings saved. Connecting...', 'info');
  connectGateway();
  updateView();
}

// =========================================================================
// HUB STATUS & NOTIFICATIONS
// =========================================================================

function handleHubStatusUpdate(data) {
  isHubOnline = (data && data.online === true);
  updateHubOfflineBanner();
  if (isHubOnline) {
    if (activeTransport === 'cloud') setStatus('Cloud Online', 'online');
  } else {
    setStatus('Hub Offline', 'offline');
  }
}

function handleNotification(data) {
  const title = data.title || 'Mini-HA Alert';
  const msg = data.msg || 'Automation alert triggered';

  if ('vibrate' in navigator) {
    try { navigator.vibrate([120, 80, 120]); } catch (e) {}
  }

  playNotificationChime();

  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.controller) {
        navigator.serviceWorker.ready.then(reg => {
          reg.showNotification(title, {
            body: msg,
            icon: './icon.svg',
            badge: './icon.svg',
            vibrate: [120, 80, 120],
            tag: 'miniha-alert'
          });
        });
      } else {
        new Notification(title, { body: msg, icon: './icon.svg' });
      }
    } catch (e) {
      console.warn('Native notification failed:', e);
    }
  }

  showToast(`${title}: ${msg}`, 'warning');
}

function playNotificationChime() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
    osc.start();
    osc.stop(ctx.currentTime + 0.35);
  } catch (e) {}
}

function toggleNativeNotifications() {
  if (!('Notification' in window)) {
    showToast('Notifications are not supported by this browser', 'error');
    return;
  }
  if (Notification.permission === 'granted') {
    showToast('Notifications are enabled', 'info');
  } else if (Notification.permission === 'denied') {
    showToast('Notifications are blocked in site settings', 'error');
  } else {
    Notification.requestPermission().then(permission => {
      if (permission === 'granted') {
        showToast('Notifications enabled!', 'success');
        updateNotifButtonState();
      } else {
        showToast('Permission not granted', 'info');
      }
    });
  }
}

function updateNotifButtonState() {
  const btn = document.getElementById('notifBellBtn');
  if (!btn) return;
  if ('Notification' in window && Notification.permission === 'granted') {
    btn.style.color = 'var(--text-main)';
  } else {
    btn.style.color = 'var(--text-dim)';
  }
}

// =========================================================================
// UTILITIES
// =========================================================================

function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  if (!toast) return;

  toast.textContent = msg;
  toast.style.display = 'block';

  if (type === 'error') {
    toast.style.borderColor = 'var(--danger-border)';
    toast.style.color = '#fca5a5';
  } else if (type === 'success') {
    toast.style.borderColor = 'var(--success-border)';
    toast.style.color = '#6ee7b7';
  } else if (type === 'warning') {
    toast.style.borderColor = 'var(--warning-border)';
    toast.style.color = '#fcd34d';
  } else {
    toast.style.borderColor = 'var(--card-border)';
    toast.style.color = 'var(--text-main)';
  }

  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// =========================================================================
// INITIALIZATION
// =========================================================================

window.addEventListener('DOMContentLoaded', () => {
  checkUrlInvite();
  updateView();
  updateNotifButtonState();
  connectGateway();
});
