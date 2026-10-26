#pragma once
#include <Arduino.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "storage_manager.h"

// =========================================================================
// MASTER ONBOARD WEB DASHBOARD & REST API WITH AUTHENTICATION
// =========================================================================

extern WebServer webServer;
void triggerProvisionNode(const String& mac, const String& newId);

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
};

extern SystemSecurityConfig sysSecurity;

// Role evaluation:
// 1. Admin: Full configuration (bind devices, change pins, edit rules, Wi-Fi config)
// 2. Member: Offline home control (toggle switches, start/stop pump, change schedules)
// 3. Guest: Read-only viewer (view tank level and sensor status)
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

  // 2. Read Configured Nodes & Live States (Guest, Member, or Admin)
  webServer.on("/api/nodes", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(500, "application/json", "{\"error\":\"File not found\"}");
      return;
    }
    webServer.streamFile(f, "application/json");
    f.close();
  });

  // 3. Member Offline Control API: Toggle switch / manual pump actuation
  webServer.on("/api/control", HTTP_POST, []() {
    if (!requireRole(ROLE_MEMBER)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String target = doc["target"].as<String>();
    String cmd = doc["cmd"].as<String>();
    int val = doc["val"].as<int>();
    executeAction(target, cmd, val, "Web UI Control");
    webServer.send(200, "application/json", "{\"status\":\"Command dispatched\"}");
  });

  // 4. Save Wi-Fi & Network Settings (Admin only)
  webServer.on("/api/wifi", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    sysSecurity.staSsid = doc["ssid"].as<String>();
    sysSecurity.staPass = doc["pass"].as<String>();
    sysSecurity.staEnabled = (sysSecurity.staSsid.length() > 0);

    File f = LittleFS.open(SYSTEM_CONFIG_PATH, "w");
    if (f) {
      serializeJson(doc, f);
      f.close();
    }
    webServer.send(200, "application/json", "{\"status\":\"Saved. Rebooting...\"}");
    delay(500);
    ESP.restart();
  });

  // 5. Bind & Provision Node API (Admin only)
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
    triggerProvisionNode(mac, newId);
    webServer.send(200, "application/json", "{\"status\":\"Provisioning triggered\"}");
  });

  // 6. Embedded Web Dashboard with Offline Manual Controls
  webServer.on("/", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    UserRole currentRole = getAuthenticatedRole();
    bool canControl = (currentRole >= ROLE_MEMBER);
    bool canAdmin = (currentRole >= ROLE_ADMIN);

    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <title>Mini-HA Embedded Master</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 18px; }
    h1 { font-size: 22px; color: #38bdf8; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }
    .role-badge { font-size: 11px; padding: 4px 10px; border-radius: 99px; text-transform: uppercase; font-weight: bold; background: #334155; }
    .card { background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
    h2 { font-size: 16px; margin-top: 0; color: #94a3b8; }
    .btn { background: #0284c7; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; font-weight: bold; cursor: pointer; transition: 0.2s; margin: 4px; }
    .btn:hover { background: #38bdf8; color: #0f172a; }
    .btn-off { background: #475569; }
    .btn-danger { background: #dc2626; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-top: 10px; }
    .switch-card { background: #0f172a; padding: 12px; border-radius: 8px; text-align: center; border: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #334155; }
    input { background: #0f172a; border: 1px solid #334155; color: #f8fafc; padding: 8px; border-radius: 6px; width: 100%; box-sizing: border-box; margin: 4px 0 10px 0; }
  </style>
</head>
<body>
  <h1>
    <span>🏠 Mini-HA Dashboard</span>
    <span class="role-badge" id="roleBadge">ROLE</span>
  </h1>

  <!-- 1. OFFLINE MANUAL CONTROL UI (MEMBER & ADMIN) -->
  <div class="card" id="controlPanel">
    <h2>⚡ Offline Direct Controls</h2>
    <div class="grid">
      <div class="switch-card">
        <div><strong>Main Pump</strong></div>
        <button class="btn btn-off" id="btnPump" onclick="togglePump()">PUMP: OFF</button>
      </div>
      <div class="switch-card">
        <div><strong>Switch 1</strong></div>
        <button class="btn btn-off" id="btnSw1" onclick="toggleSwitch('N02', 0)">SW 1</button>
      </div>
      <div class="switch-card">
        <div><strong>Switch 2</strong></div>
        <button class="btn btn-off" id="btnSw2" onclick="toggleSwitch('N02', 1)">SW 2</button>
      </div>
      <div class="switch-card">
        <div><strong>Switch 3</strong></div>
        <button class="btn btn-off" id="btnSw3" onclick="toggleSwitch('N02', 2)">SW 3</button>
      </div>
      <div class="switch-card">
        <div><strong>Switch 4</strong></div>
        <button class="btn btn-off" id="btnSw4" onclick="toggleSwitch('N02', 3)">SW 4</button>
      </div>
    </div>
  </div>

  <!-- 2. TELEMETRY & CONFIGURED NODES -->
  <div class="card">
    <h2>📋 Mesh Nodes & Live Telemetry</h2>
    <div id="nodesList">Loading nodes...</div>
  </div>

  <!-- 3. DISCOVERED UNBOUND NODES (ADMIN ONLY) -->
  <div class="card" id="adminDiscoveryCard" style="display:none;">
    <h2>🔍 Discovered Unbound Devices</h2>
    <div id="pendingList">Scanning bus...</div>
  </div>

  <!-- 4. NETWORK SETTINGS (ADMIN ONLY) -->
  <div class="card" id="adminWifiCard" style="display:none;">
    <h2>📶 Home Wi-Fi & Fallback Config</h2>
    <input type="text" id="wifiSsid" placeholder="Home Wi-Fi SSID">
    <input type="password" id="wifiPass" placeholder="Password">
    <button class="btn" onclick="saveWifi()">Save & Connect</button>
  </div>

  <script>
    const canControl = )rawliteral" + String(canControl ? "true" : "false") + R"rawliteral(;
    const canAdmin = )rawliteral" + String(canAdmin ? "true" : "false") + R"rawliteral(;

    document.getElementById('roleBadge').innerText = canAdmin ? "ADMIN" : (canControl ? "MEMBER" : "GUEST");
    if (!canControl) {
      document.querySelectorAll('#controlPanel button').forEach(b => b.disabled = true);
    }
    if (canAdmin) {
      document.getElementById('adminDiscoveryCard').style.display = 'block';
      document.getElementById('adminWifiCard').style.display = 'block';
    }

    let pumpState = false;
    let swStates = [false, false, false, false];

    async function togglePump() {
      pumpState = !pumpState;
      await fetch('/api/control', { method: 'POST', body: JSON.stringify({ target: 'LOCAL', cmd: 'SET_PUMP', val: pumpState ? 1 : 0 }) });
      document.getElementById('btnPump').className = pumpState ? 'btn' : 'btn btn-off';
      document.getElementById('btnPump').innerText = pumpState ? 'PUMP: ON' : 'PUMP: OFF';
    }

    async function toggleSwitch(node, slot) {
      swStates[slot] = !swStates[slot];
      await fetch('/api/control', { method: 'POST', body: JSON.stringify({ target: node, cmd: 'SET_SLOT', val: slot }) });
      const b = document.getElementById('btnSw' + (slot + 1));
      b.className = swStates[slot] ? 'btn' : 'btn btn-off';
    }

    async function loadData() {
      try {
        if (canAdmin) {
          const pRes = await fetch('/api/pending');
          const pData = await pRes.json();
          let pHtml = '<table><tr><th>MAC</th><th>Chip</th><th>Action</th></tr>';
          if (pData.pending && pData.pending.length > 0) {
            pData.pending.forEach(d => {
              pHtml += `<tr><td>${d.mac}</td><td>${d.chip}</td><td><button class="btn" onclick="bindNode('${d.mac}')">Bind</button></td></tr>`;
            });
            document.getElementById('pendingList').innerHTML = pHtml + '</table>';
          } else {
            document.getElementById('pendingList').innerHTML = '<p style="color:#64748b;">No new unbound devices discovered.</p>';
          }
        }

        const nRes = await fetch('/api/nodes');
        const nData = await nRes.json();
        let nHtml = '<table><tr><th>ID</th><th>Name</th><th>Chip</th><th>Slots</th></tr>';
        if (nData.nodes) {
          nData.nodes.forEach(n => {
            nHtml += `<tr><td><strong>${n.id}</strong></td><td>${n.name}</td><td>${n.chip}</td><td>${n.slots.length}</td></tr>`;
          });
          document.getElementById('nodesList').innerHTML = nHtml + '</table>';
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function bindNode(mac) {
      const id = prompt('Assign Node ID (e.g. N01, N02):', 'N01');
      if (id) {
        await fetch('/api/bind', { method: 'POST', body: JSON.stringify({ mac: mac, id: id }) });
        alert('Binding packet dispatched!');
        setTimeout(loadData, 1000);
      }
    }

    async function saveWifi() {
      const ssid = document.getElementById('wifiSsid').value;
      const pass = document.getElementById('wifiPass').value;
      if (!ssid) return alert('Enter SSID');
      await fetch('/api/wifi', { method: 'POST', body: JSON.stringify({ ssid: ssid, pass: pass }) });
      alert('Wi-Fi saved. Master rebooting...');
    }

    loadData();
    setInterval(loadData, 4000);
  </script>
</body>
</html>
)rawliteral";
    webServer.send(200, "text/html", html);
  });
}
