#pragma once
#include <Arduino.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "storage_manager.h"
#include "rules_engine.h"

// =========================================================================
// MASTER ONBOARD WEB DASHBOARD & REST API WITH AUTHENTICATION
// =========================================================================

extern WebServer webServer;
void triggerProvisionNode(const String& mac, const String& newId, const String& name);

#ifndef SYSTEM_CONFIG_PATH
  #define SYSTEM_CONFIG_PATH "/config/system.json"
#endif

struct SystemSecurityConfig {
  String apSsid = "Mini-HA-Master";
  String apPass = "12345678";
  String staSsid = "";
  String staPass = "";
  bool staEnabled = false;
  String adminUser = "admin";
  String adminPass = "admin123";
  String memberUser = "member";
  String memberPass = "member123";
  String guestUser = "guest";
  String guestPass = "guest123";

  // Supla Cloud Bridge
  bool suplaEnabled = false;
  String suplaServer = "";
  String suplaEmail = "";
  String suplaGuid = "";
  String suplaAuthKey = "";
};

extern SystemSecurityConfig sysSecurity;

enum UserRole { ROLE_NONE = 0, ROLE_GUEST, ROLE_MEMBER, ROLE_ADMIN };

inline UserRole getAuthenticatedRole() {
  if (webServer.authenticate(sysSecurity.adminUser.c_str(), sysSecurity.adminPass.c_str())) return ROLE_ADMIN;
  if (webServer.authenticate(sysSecurity.memberUser.c_str(), sysSecurity.memberPass.c_str())) return ROLE_MEMBER;
  if (webServer.authenticate(sysSecurity.guestUser.c_str(), sysSecurity.guestPass.c_str())) return ROLE_GUEST;
  return ROLE_NONE;
}

inline bool requireRole(UserRole minRole) {
  UserRole r = getAuthenticatedRole();
  if (r >= minRole) return true;
  webServer.requestAuthentication(DIGEST_AUTH, "Mini-HA Realm", "Login Required");
  return false;
}

inline void setupWebEndpoints() {
  // 1. Pending Discovered Nodes API (Admin only)
  webServer.on("/api/pending", HTTP_GET, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    DynamicJsonDocument doc(1024);
    JsonArray arr = doc.createNestedArray("pending");
    for (uint8_t i = 0; i < numPendingNodes; i++) {
      JsonObject obj = arr.createNestedObject();
      obj["mac"] = pendingNodes[i].mac;
      obj["chip"] = pendingNodes[i].chip;
      obj["gpios"] = pendingNodes[i].gpios;
      obj["slots"] = pendingNodes[i].slots;
    }
    String json;
    serializeJson(doc, json);
    webServer.send(200, "application/json", json);
  });

  // 2. Read Configured Nodes
  webServer.on("/api/nodes", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(200, "application/json", "{\"nodes\":[]}");
      return;
    }
    webServer.streamFile(f, "application/json");
    f.close();
  });

  // 3. Read Live Telemetry & States
  webServer.on("/api/state", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    DynamicJsonDocument doc(2048);
    JsonArray arr = doc.createNestedArray("nodes");
    for (uint8_t i = 0; i < numTrackedNodes; i++) {
      JsonObject n = arr.createNestedObject();
      n["id"] = nodeStates[i].nodeId;
      n["dist"] = nodeStates[i].distance;
      n["temp"] = nodeStates[i].temp;
      n["hum"] = nodeStates[i].hum;
      n["lastSeen"] = (millis() - nodeStates[i].lastSeen) / 1000;
      JsonArray relays = n.createNestedArray("relays");
      for (int s = 0; s < MAX_GPIO_SLOTS; s++) {
        relays.add(nodeStates[i].relayStates[s] ? 1 : 0);
      }
    }
    String json;
    serializeJson(doc, json);
    webServer.send(200, "application/json", json);
  });

  // 4. Member Offline Direct Control API
  webServer.on("/api/control", HTTP_POST, []() {
    if (!requireRole(ROLE_MEMBER)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String target = doc["target"].as<String>();
    int slot = doc["slot"].as<int>();
    int val = doc["val"].as<int>();
    executeAction(target, slot, val, "Web UI Control");
    webServer.send(200, "application/json", "{\"status\":\"Command dispatched\"}");
  });

  // 5. Read System & Cloud Configuration
  webServer.on("/api/system", HTTP_GET, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    DynamicJsonDocument doc(512);
    doc["ap_ssid"] = sysSecurity.apSsid;
    doc["sta_ssid"] = sysSecurity.staSsid;
    doc["sta_enabled"] = sysSecurity.staEnabled;
    doc["supla_enabled"] = sysSecurity.suplaEnabled;
    doc["supla_server"] = sysSecurity.suplaServer;
    doc["supla_email"] = sysSecurity.suplaEmail;
    doc["supla_guid"] = sysSecurity.suplaGuid;
    doc["supla_authkey"] = sysSecurity.suplaAuthKey;
    String json;
    serializeJson(doc, json);
    webServer.send(200, "application/json", json);
  });

  // 6. Save System & Cloud Settings
  webServer.on("/api/system", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, webServer.arg("plain"));

    if (doc.containsKey("sta_ssid")) sysSecurity.staSsid = doc["sta_ssid"].as<String>();
    if (doc.containsKey("sta_pass") && doc["sta_pass"].as<String>().length() > 0) {
      sysSecurity.staPass = doc["sta_pass"].as<String>();
    }
    if (doc.containsKey("sta_enabled")) sysSecurity.staEnabled = doc["sta_enabled"].as<bool>();

    if (doc.containsKey("supla_enabled")) sysSecurity.suplaEnabled = doc["supla_enabled"].as<bool>();
    if (doc.containsKey("supla_server")) sysSecurity.suplaServer = doc["supla_server"].as<String>();
    if (doc.containsKey("supla_email")) sysSecurity.suplaEmail = doc["supla_email"].as<String>();
    if (doc.containsKey("supla_guid")) sysSecurity.suplaGuid = doc["supla_guid"].as<String>();
    if (doc.containsKey("supla_authkey")) sysSecurity.suplaAuthKey = doc["supla_authkey"].as<String>();

    File f = LittleFS.open(SYSTEM_CONFIG_PATH, "w");
    if (f) {
      DynamicJsonDocument outDoc(1024);
      outDoc["ap_ssid"] = sysSecurity.apSsid;
      outDoc["ap_pass"] = sysSecurity.apPass;
      outDoc["sta_ssid"] = sysSecurity.staSsid;
      outDoc["sta_pass"] = sysSecurity.staPass;
      outDoc["sta_enabled"] = sysSecurity.staEnabled;
      outDoc["admin_user"] = sysSecurity.adminUser;
      outDoc["admin_pass"] = sysSecurity.adminPass;
      outDoc["member_user"] = sysSecurity.memberUser;
      outDoc["member_pass"] = sysSecurity.memberPass;
      outDoc["guest_user"] = sysSecurity.guestUser;
      outDoc["guest_pass"] = sysSecurity.guestPass;
      outDoc["supla_enabled"] = sysSecurity.suplaEnabled;
      outDoc["supla_server"] = sysSecurity.suplaServer;
      outDoc["supla_email"] = sysSecurity.suplaEmail;
      outDoc["supla_guid"] = sysSecurity.suplaGuid;
      outDoc["supla_authkey"] = sysSecurity.suplaAuthKey;
      serializeJson(outDoc, f);
      f.close();
    }
    webServer.send(200, "application/json", "{\"status\":\"Saved. Rebooting...\"}");
    delay(500);
    ESP.restart();
  });

  // 7. Bind & Provision Node API
  webServer.on("/api/bind", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String mac = doc["mac"].as<String>();
    String newId = doc["id"].as<String>();
    String name = doc.containsKey("name") ? doc["name"].as<String>() : newId;
    triggerProvisionNode(mac, newId, name);
    webServer.send(200, "application/json", "{\"status\":\"Provisioning triggered\"}");
  });

  // 8. Embedded Dynamic Web Dashboard
  webServer.on("/", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    UserRole currentRole = getAuthenticatedRole();
    bool canControl = (currentRole >= ROLE_MEMBER);
    bool canAdmin = (currentRole >= ROLE_ADMIN);

    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <title>Mini-HomeAssistant Hub</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #f8fafc; margin: 0; padding: 16px; }
    h1 { font-size: 20px; color: #38bdf8; margin: 0 0 16px 0; display: flex; justify-content: space-between; align-items: center; }
    .badge { font-size: 11px; padding: 4px 10px; border-radius: 99px; text-transform: uppercase; font-weight: bold; background: #1e293b; color: #38bdf8; border: 1px solid #334155; }
    .card { background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); border: 1px solid #334155; }
    h2 { font-size: 15px; margin-top: 0; margin-bottom: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .btn { background: #0284c7; color: #fff; border: none; padding: 9px 16px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; }
    .btn:hover { background: #38bdf8; color: #0b1120; }
    .btn-off { background: #334155; color: #94a3b8; }
    .btn-off:hover { background: #475569; color: #fff; }
    .btn-secondary { background: #475569; color: #f8fafc; }
    .btn-secondary:hover { background: #64748b; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }
    .node-card { background: #0f172a; padding: 14px; border-radius: 10px; border: 1px solid #1e293b; }
    .node-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }
    .node-title { font-weight: bold; color: #e2e8f0; font-size: 14px; }
    .node-seen { font-size: 11px; color: #64748b; }
    .slot-row { display: flex; justify-content: space-between; align-items: center; margin: 8px 0; font-size: 13px; }
    .sensor-val { font-family: monospace; font-size: 13px; color: #38bdf8; background: #1e293b; padding: 4px 8px; border-radius: 6px; }
    .empty-msg { color: #64748b; font-size: 13px; font-style: italic; padding: 12px 0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-weight: 600; }
    input, select { background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 8px 10px; border-radius: 6px; width: 100%; box-sizing: border-box; margin: 4px 0 10px 0; font-size: 13px; }
    .checkbox-row { display: flex; align-items: center; gap: 8px; margin: 8px 0 12px 0; font-size: 13px; }
    .checkbox-row input { width: auto; margin: 0; }
    .hint { font-size: 12px; color: #94a3b8; margin-top: -6px; margin-bottom: 10px; line-height: 1.4; }
  </style>
</head>
<body>
  <h1>
    <span>🏠 Mini-HA Hub</span>
    <span class="badge" id="roleBadge">ROLE</span>
  </h1>

  <!-- 1. DYNAMIC MESH ENTITIES & LIVE TELEMETRY -->
  <div class="card">
    <h2>⚡ Connected Mesh Nodes & Entities</h2>
    <div id="entitiesContainer" class="grid">
      <div class="empty-msg">Scanning configured nodes...</div>
    </div>
  </div>

  <!-- 2. DISCOVERED UNBOUND SLAVES (ADMIN ONLY) -->
  <div class="card" id="discoveryCard" style="display:none;">
    <h2>🔍 Discovered Unbound Slaves</h2>
    <div id="pendingTable"><div class="empty-msg">No unconfigured devices detected on bus.</div></div>
  </div>

  <!-- 3. NETWORK & CLOUD BRIDGE CONFIGURATION (ADMIN ONLY) -->
  <div class="card" id="configCard" style="display:none;">
    <h2>⚙️ Network & Cloud Configuration</h2>
    
    <h3 style="font-size:13px; color:#38bdf8; margin: 12px 0 6px 0;">Home Wi-Fi (Station Mode)</h3>
    <input type="text" id="wifiSsid" placeholder="Home Wi-Fi SSID">
    <input type="password" id="wifiPass" placeholder="Home Wi-Fi Password">

    <h3 style="font-size:13px; color:#38bdf8; margin: 18px 0 6px 0;">Supla Cloud Bridge (Optional Mobile App Access)</h3>
    <div class="checkbox-row">
      <input type="checkbox" id="suplaEnabled">
      <label for="suplaEnabled">Enable Supla Cloud Mobile App Integration</label>
    </div>
    <div class="hint">
      1. Log in to <a href="https://cloud.supla.org" target="_blank" style="color:#38bdf8;">cloud.supla.org</a><br>
      2. Under the <strong>My SUPLA</strong> tab (plug icon), click <strong>"Device registration: CLICK TO ENABLE"</strong> in the top right.<br>
      3. Enter your assigned Server and Email below, and click Save. The Master generates its own keys and pairs automatically!
    </div>

    <input type="text" id="suplaServer" placeholder="Supla Server (e.g. svr12.supla.org)">
    <input type="email" id="suplaEmail" placeholder="Supla Account Email">
    
    <div style="margin-top:8px;">
      <button class="btn" type="button" onclick="saveSystemConfig()">💾 Save Settings & Restart</button>
    </div>
  </div>

  <script>
    const canControl = )rawliteral" + String(canControl ? "true" : "false") + R"rawliteral(;
    const canAdmin = )rawliteral" + String(canAdmin ? "true" : "false") + R"rawliteral(;

    document.getElementById('roleBadge').innerText = canAdmin ? "ADMIN" : (canControl ? "MEMBER" : "GUEST");
    if (canAdmin) {
      document.getElementById('discoveryCard').style.display = 'block';
      document.getElementById('configCard').style.display = 'block';
      loadSystemConfig();
    }

    let configuredNodes = [];
    let liveStates = {};

    async function loadSystemConfig() {
      try {
        const res = await fetch('/api/system');
        const data = await res.json();
        document.getElementById('wifiSsid').value = data.sta_ssid || '';
        document.getElementById('suplaEnabled').checked = !!data.supla_enabled;
        document.getElementById('suplaServer').value = data.supla_server || '';
        document.getElementById('suplaEmail').value = data.supla_email || '';
      } catch (e) {
        console.error(e);
      }
    }

    async function saveSystemConfig() {
      const payload = {
        sta_ssid: document.getElementById('wifiSsid').value,
        sta_pass: document.getElementById('wifiPass').value,
        sta_enabled: document.getElementById('wifiSsid').value.length > 0,
        supla_enabled: document.getElementById('suplaEnabled').checked,
        supla_server: document.getElementById('suplaServer').value,
        supla_email: document.getElementById('suplaEmail').value
      };
      await fetch('/api/system', { method: 'POST', body: JSON.stringify(payload) });
      alert('Settings saved. Master Hub is restarting...');
    }

    async function toggleRelay(nodeId, slot, curState) {
      if (!canControl) return;
      const targetState = curState ? 0 : 1;
      await fetch('/api/control', {
        method: 'POST',
        body: JSON.stringify({ target: nodeId, slot: slot, val: targetState })
      });
      refreshData();
    }

    async function refreshData() {
      try {
        // 1. Fetch Configured Nodes
        const nRes = await fetch('/api/nodes');
        const nData = await nRes.json();
        configuredNodes = nData.nodes || [];

        // 2. Fetch Live States
        const sRes = await fetch('/api/state');
        const sData = await sRes.json();
        liveStates = {};
        if (sData.nodes) {
          sData.nodes.forEach(n => { liveStates[n.id] = n; });
        }

        renderEntities();

        // 3. Fetch Pending Unbound Devices (Admin)
        if (canAdmin) {
          const pRes = await fetch('/api/pending');
          const pData = await pRes.json();
          renderPending(pData.pending || []);
        }
      } catch (e) {
        console.error(e);
      }
    }

    function renderEntities() {
      const c = document.getElementById('entitiesContainer');
      if (configuredNodes.length === 0) {
        c.innerHTML = '<div class="empty-msg">No devices configured yet. Power on a slave device; when detected on RS-422 bus or Wi-Fi, it will appear in the Discovered Slaves panel below.</div>';
        return;
      }

      let html = '';
      configuredNodes.forEach(node => {
        const state = liveStates[node.id] || { relays: [], dist: -1, temp: 0, hum: 0, lastSeen: 999 };
        const seenText = state.lastSeen < 10 ? 'online' : `${state.lastSeen}s ago`;

        html += `<div class="node-card">
          <div class="node-header">
            <span class="node-title">${node.name || node.id} (${node.id})</span>
            <span class="node-seen">${seenText}</span>
          </div>`;

        if (node.slots && node.slots.length > 0) {
          node.slots.forEach(slot => {
            const slotName = slot.name || `Slot ${slot.slot}`;
            if (slot.type === 1) { // Relay
              const isRelayOn = (state.relays && state.relays[slot.slot] === 1);
              const btnClass = isRelayOn ? 'btn' : 'btn btn-off';
              const btnText = isRelayOn ? 'ON' : 'OFF';
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <button class="${btnClass}" ${canControl ? '' : 'disabled'} onclick="toggleRelay('${node.id}', ${slot.slot}, ${isRelayOn})">${btnText}</button>
              </div>`;
            } else if (slot.type === 6 || slot.type === 7) { // DHT
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <span class="sensor-val">${state.temp.toFixed(1)}°C | ${state.hum.toFixed(1)}%</span>
              </div>`;
            } else if (slot.type === 4 || slot.type === 5) { // Ultrasonic
              const distTxt = state.dist >= 0 ? `${state.dist} cm` : '--';
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <span class="sensor-val">${distTxt}</span>
              </div>`;
            }
          });
        } else {
          html += '<div class="empty-msg">No slots configured.</div>';
        }
        html += `</div>`;
      });
      c.innerHTML = html;
    }

    function renderPending(pending) {
      const c = document.getElementById('pendingTable');
      if (pending.length === 0) {
        c.innerHTML = '<div class="empty-msg">No unconfigured devices detected on bus.</div>';
        return;
      }
      let html = '<table><tr><th>MAC</th><th>Chip</th><th>GPIOs</th><th>Action</th></tr>';
      pending.forEach(d => {
        html += `<tr>
          <td><code>${d.mac}</code></td>
          <td>${d.chip}</td>
          <td>${d.gpios}</td>
          <td><button class="btn" onclick="bindDevice('${d.mac}')">Bind Node</button></td>
        </tr>`;
      });
      c.innerHTML = html + '</table>';
    }

    async function bindDevice(mac) {
      const id = prompt('Assign Node ID (e.g. N01, N02):', 'N01');
      if (!id) return;
      const name = prompt('Friendly Name (e.g. Living Room, Garden):', id);
      await fetch('/api/bind', {
        method: 'POST',
        body: JSON.stringify({ mac: mac, id: id, name: name || id })
      });
      alert('Node binding initiated!');
      refreshData();
    }

    refreshData();
    setInterval(refreshData, 3000);
  </script>
</body>
</html>
)rawliteral";
    webServer.send(200, "text/html", html);
  });
}
