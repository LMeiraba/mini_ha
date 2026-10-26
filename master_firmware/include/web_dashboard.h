#pragma once
#include <Arduino.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "storage_manager.h"
#include "rules_engine.h"

// =========================================================================
// MINI-HOMEASSISTANT MODERN WEB DASHBOARD & REST API
// =========================================================================

extern WebServer webServer;
void triggerProvisionNode(const String& mac, const String& newId, const String& name);

#ifndef SYSTEM_CONFIG_PATH
  #define SYSTEM_CONFIG_PATH "/config/system.json"
#endif

#ifndef USERS_CONFIG_PATH
  #define USERS_CONFIG_PATH "/config/users.json"
#endif

struct SystemSecurityConfig {
  String apSsid = "Mini-HA-Master";
  String apPass = "12345678";
  String staSsid = "";
  String staPass = "";
  bool staEnabled = false;

  // Supla Cloud Bridge
  bool suplaEnabled = false;
  String suplaServer = "";
  String suplaEmail = "";
};

extern SystemSecurityConfig sysSecurity;

// =========================================================================
// SESSION & USER AUTHENTICATION MANAGER (NO BROWSER PROMPT, COOKIE/HEADER AUTH)
// =========================================================================

enum UserRole { ROLE_NONE = 0, ROLE_GUEST = 1, ROLE_MEMBER = 2, ROLE_ADMIN = 3 };

struct ActiveSession {
  String token;
  String username;
  UserRole role;
  unsigned long lastActive;
};

#define MAX_SESSIONS 6
ActiveSession activeSessions[MAX_SESSIONS];

inline String generateRandomToken() {
  String t = "";
  for (int i = 0; i < 4; i++) {
    uint32_t r = esp_random();
    char buf[9];
    sprintf(buf, "%08x", r);
    t += String(buf);
  }
  return t; // 32 hex chars
}

inline String getRequestToken() {
  if (webServer.hasHeader("X-Auth-Token")) {
    String t = webServer.header("X-Auth-Token");
    if (t.length() > 0) return t;
  }
  if (webServer.hasHeader("Cookie")) {
    String c = webServer.header("Cookie");
    int idx = c.indexOf("mini_ha_session=");
    if (idx != -1) {
      int end = c.indexOf(';', idx);
      if (end == -1) end = c.length();
      return c.substring(idx + 16, end);
    }
  }
  return "";
}

inline UserRole getAuthenticatedRole(String* outUsername = nullptr) {
  String token = getRequestToken();
  if (token.length() == 0) return ROLE_NONE;

  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (activeSessions[i].token.length() > 0 && activeSessions[i].token == token) {
      if (millis() - activeSessions[i].lastActive < 86400000UL) { // 24 hours
        activeSessions[i].lastActive = millis();
        if (outUsername) *outUsername = activeSessions[i].username;
        return activeSessions[i].role;
      } else {
        activeSessions[i].token = ""; // Expired
      }
    }
  }
  return ROLE_NONE;
}

inline bool requireRole(UserRole minRole, String* outUsername = nullptr) {
  UserRole r = getAuthenticatedRole(outUsername);
  if (r >= minRole) return true;
  webServer.send(401, "application/json; charset=utf-8", "{\"error\":\"Unauthorized\",\"loginRequired\":true}");
  return false;
}

inline UserRole roleNameToEnum(const String& r) {
  if (r == "admin") return ROLE_ADMIN;
  if (r == "member") return ROLE_MEMBER;
  return ROLE_GUEST;
}

inline String roleEnumToName(UserRole r) {
  if (r == ROLE_ADMIN) return "admin";
  if (r == ROLE_MEMBER) return "member";
  return "guest";
}

// =========================================================================
// REST API ENDPOINTS
// =========================================================================

inline void setupWebEndpoints() {
  // 1. Session Status API
  webServer.on("/api/session", HTTP_GET, []() {
    String username = "";
    UserRole r = getAuthenticatedRole(&username);
    if (r == ROLE_NONE) {
      webServer.send(200, "application/json; charset=utf-8", "{\"loggedIn\":false}");
      return;
    }

    bool isDefault = false;
    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    if (f) {
      DynamicJsonDocument doc(2048);
      deserializeJson(doc, f);
      f.close();
      for (JsonObject u : doc["users"].as<JsonArray>()) {
        if (u["user"].as<String>() == username) {
          if (username == "admin" && u["pass"].as<String>() == "admin123") {
            isDefault = true;
          }
          break;
        }
      }
    }

    DynamicJsonDocument res(256);
    res["loggedIn"] = true;
    res["user"] = username;
    res["role"] = roleEnumToName(r);
    res["isDefault"] = isDefault;
    String out;
    serializeJson(res, out);
    webServer.send(200, "application/json; charset=utf-8", out);
  });

  // 2. Modern Login API
  webServer.on("/api/login", HTTP_POST, []() {
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Missing body\"}");
      return;
    }
    DynamicJsonDocument req(512);
    deserializeJson(req, webServer.arg("plain"));
    String user = req["user"].as<String>();
    String pass = req["pass"].as<String>();

    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(500, "application/json; charset=utf-8", "{\"error\":\"Storage error\"}");
      return;
    }
    DynamicJsonDocument doc(2048);
    deserializeJson(doc, f);
    f.close();

    bool matched = false;
    String userRoleStr = "guest";
    bool isDefault = false;

    for (JsonObject u : doc["users"].as<JsonArray>()) {
      if (u["user"].as<String>() == user && u["pass"].as<String>() == pass) {
        matched = true;
        userRoleStr = u["role"].as<String>();
        if (user == "admin" && pass == "admin123") isDefault = true;
        break;
      }
    }

    if (!matched) {
      webServer.send(401, "application/json; charset=utf-8", "{\"error\":\"Invalid username or password\"}");
      return;
    }

    String token = generateRandomToken();
    UserRole uRole = roleNameToEnum(userRoleStr);

    // Save session in slot
    int slot = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (activeSessions[i].token.length() == 0 || millis() - activeSessions[i].lastActive > 86400000UL) {
        slot = i;
        break;
      }
    }
    if (slot == -1) slot = 0; // Overwrite oldest

    activeSessions[slot].token = token;
    activeSessions[slot].username = user;
    activeSessions[slot].role = uRole;
    activeSessions[slot].lastActive = millis();

    webServer.sendHeader("Set-Cookie", "mini_ha_session=" + token + "; Path=/; SameSite=Strict; Max-Age=86400");
    DynamicJsonDocument res(256);
    res["status"] = "ok";
    res["token"] = token;
    res["user"] = user;
    res["role"] = userRoleStr;
    res["isDefault"] = isDefault;
    String out;
    serializeJson(res, out);
    webServer.send(200, "application/json; charset=utf-8", out);
  });

  // 3. Logout API
  webServer.on("/api/logout", HTTP_POST, []() {
    String token = getRequestToken();
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (activeSessions[i].token == token) activeSessions[i].token = "";
    }
    webServer.sendHeader("Set-Cookie", "mini_ha_session=; Path=/; Max-Age=0");
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"logged_out\"}");
  });

  // 4. User Management: List Users (Admin only)
  webServer.on("/api/users", HTTP_GET, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(200, "application/json; charset=utf-8", "{\"users\":[]}");
      return;
    }
    DynamicJsonDocument doc(2048);
    deserializeJson(doc, f);
    f.close();

    DynamicJsonDocument res(2048);
    JsonArray arr = res.createNestedArray("users");
    for (JsonObject u : doc["users"].as<JsonArray>()) {
      JsonObject o = arr.createNestedObject();
      o["user"] = u["user"].as<String>();
      o["role"] = u["role"].as<String>();
      o["isDefault"] = (u["user"].as<String>() == "admin" && u["pass"].as<String>() == "admin123");
    }
    String out;
    serializeJson(res, out);
    webServer.send(200, "application/json; charset=utf-8", out);
  });

  // 5. User Management: Add User (Admin only)
  webServer.on("/api/users/add", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Missing body\"}");
      return;
    }
    DynamicJsonDocument req(512);
    deserializeJson(req, webServer.arg("plain"));
    String newUser = req["user"].as<String>();
    String newPass = req["pass"].as<String>();
    String newRole = req["role"].as<String>();

    if (newUser.length() == 0 || newPass.length() == 0) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Username and password required\"}");
      return;
    }

    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    DynamicJsonDocument doc(2048);
    if (f) {
      deserializeJson(doc, f);
      f.close();
    }
    JsonArray users = doc["users"].as<JsonArray>();
    for (JsonObject u : users) {
      if (u["user"].as<String>() == newUser) {
        webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"User already exists\"}");
        return;
      }
    }

    JsonObject nu = users.createNestedObject();
    nu["user"] = newUser;
    nu["pass"] = newPass;
    nu["role"] = (newRole == "admin" || newRole == "member") ? newRole : "guest";

    File outF = LittleFS.open(USERS_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(doc, outF);
      outF.close();
    }
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"User added\"}");
  });

  // 6. User Management: Edit User / Change Password
  webServer.on("/api/users/edit", HTTP_POST, []() {
    String currentUsername = "";
    UserRole currentRole = getAuthenticatedRole(&currentUsername);
    if (currentRole == ROLE_NONE) {
      webServer.send(401, "application/json; charset=utf-8", "{\"error\":\"Unauthorized\"}");
      return;
    }

    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Missing body\"}");
      return;
    }
    DynamicJsonDocument req(512);
    deserializeJson(req, webServer.arg("plain"));
    String targetUser = req["user"].as<String>();
    String newPass = req.containsKey("pass") ? req["pass"].as<String>() : "";
    String newRole = req.containsKey("role") ? req["role"].as<String>() : "";

    // Non-admin can only change their own password
    if (currentRole < ROLE_ADMIN && targetUser != currentUsername) {
      webServer.send(403, "application/json; charset=utf-8", "{\"error\":\"Forbidden\"}");
      return;
    }

    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    DynamicJsonDocument doc(2048);
    if (f) {
      deserializeJson(doc, f);
      f.close();
    }
    bool found = false;
    for (JsonObject u : doc["users"].as<JsonArray>()) {
      if (u["user"].as<String>() == targetUser) {
        found = true;
        if (newPass.length() > 0) u["pass"] = newPass;
        if (newRole.length() > 0 && currentRole == ROLE_ADMIN) u["role"] = newRole;
        break;
      }
    }
    if (!found) {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"User not found\"}");
      return;
    }

    File outF = LittleFS.open(USERS_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(doc, outF);
      outF.close();
    }
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"User updated\"}");
  });

  // 7. User Management: Delete User (Admin only)
  webServer.on("/api/users/delete", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Missing body\"}");
      return;
    }
    DynamicJsonDocument req(256);
    deserializeJson(req, webServer.arg("plain"));
    String delUser = req["user"].as<String>();

    File f = LittleFS.open(USERS_CONFIG_PATH, "r");
    DynamicJsonDocument doc(2048);
    if (f) {
      deserializeJson(doc, f);
      f.close();
    }

    JsonArray users = doc["users"].as<JsonArray>();
    int adminCount = 0;
    for (JsonObject u : users) {
      if (u["role"].as<String>() == "admin") adminCount++;
    }

    int delIdx = -1;
    for (size_t i = 0; i < users.size(); i++) {
      if (users[i]["user"].as<String>() == delUser) {
        if (users[i]["role"].as<String>() == "admin" && adminCount <= 1) {
          webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Cannot delete last admin account\"}");
          return;
        }
        delIdx = i;
        break;
      }
    }

    if (delIdx != -1) {
      users.remove(delIdx);
      File outF = LittleFS.open(USERS_CONFIG_PATH, "w");
      if (outF) {
        serializeJson(doc, outF);
        outF.close();
      }
      webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"User deleted\"}");
    } else {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"User not found\"}");
    }
  });

  // 8. Pending Discovered Nodes API (Admin only)
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
    webServer.send(200, "application/json; charset=utf-8", json);
  });

  // 9. Read Configured Nodes
  webServer.on("/api/nodes", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(200, "application/json; charset=utf-8", "{\"nodes\":[]}");
      return;
    }
    webServer.streamFile(f, "application/json; charset=utf-8");
    f.close();
  });

  // 10. Read Live Telemetry & States
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
    webServer.send(200, "application/json; charset=utf-8", json);
  });

  // 11. Member Offline Direct Control API
  webServer.on("/api/control", HTTP_POST, []() {
    if (!requireRole(ROLE_MEMBER)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String target = doc["target"].as<String>();
    int slot = doc["slot"].as<int>();
    int val = doc["val"].as<int>();
    executeAction(target, slot, val, "Web UI Control");
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Command dispatched\"}");
  });

  // 12. Read System & Cloud Configuration
  webServer.on("/api/system", HTTP_GET, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    DynamicJsonDocument doc(512);
    doc["ap_ssid"] = sysSecurity.apSsid;
    doc["sta_ssid"] = sysSecurity.staSsid;
    doc["sta_enabled"] = sysSecurity.staEnabled;
    doc["supla_enabled"] = sysSecurity.suplaEnabled;
    doc["supla_server"] = sysSecurity.suplaServer;
    doc["supla_email"] = sysSecurity.suplaEmail;
    String json;
    serializeJson(doc, json);
    webServer.send(200, "application/json; charset=utf-8", json);
  });

  // 13. Save System & Cloud Settings
  webServer.on("/api/system", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
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

    File f = LittleFS.open(SYSTEM_CONFIG_PATH, "w");
    if (f) {
      DynamicJsonDocument outDoc(512);
      outDoc["ap_ssid"] = sysSecurity.apSsid;
      outDoc["ap_pass"] = sysSecurity.apPass;
      outDoc["sta_ssid"] = sysSecurity.staSsid;
      outDoc["sta_pass"] = sysSecurity.staPass;
      outDoc["sta_enabled"] = sysSecurity.staEnabled;
      outDoc["supla_enabled"] = sysSecurity.suplaEnabled;
      outDoc["supla_server"] = sysSecurity.suplaServer;
      outDoc["supla_email"] = sysSecurity.suplaEmail;
      serializeJson(outDoc, f);
      f.close();
    }
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Saved. Restarting...\"}");
    delay(500);
    ESP.restart();
  });

  // 14. Bind & Provision Node API
  webServer.on("/api/bind", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String mac = doc["mac"].as<String>();
    String newId = doc["id"].as<String>();
    String name = doc.containsKey("name") ? doc["name"].as<String>() : newId;
    triggerProvisionNode(mac, newId, name);
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Provisioning triggered\"}");
  });

  // 15. Modern Single Page Application (Dashboard + Login)
  webServer.on("/", HTTP_GET, []() {
    String html = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini-HA Supervisor</title>
  <style>
    :root {
      --bg: #0f1117;
      --card: #161922;
      --border: #232734;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --input-bg: #11131a;
      --input-border: #2e3446;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 18px; font-size: 14px; }
    
    /* Top Bar */
    .topbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 18px; }
    .brand { font-size: 17px; font-weight: 700; letter-spacing: -0.3px; display: flex; align-items: center; gap: 8px; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); display: inline-block; }
    .nav-actions { display: flex; align-items: center; gap: 8px; }
    
    /* Buttons & Badges */
    .badge { font-size: 11px; font-weight: 600; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; background: #1e2433; color: #60a5fa; border: 1px solid #2b354d; }
    .btn { background: var(--primary); color: #fff; border: 1px solid transparent; padding: 7px 14px; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; transition: 0.15s; }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary { background: #1f2430; color: var(--text); border: 1px solid var(--border); }
    .btn-secondary:hover { background: #282f40; }
    .btn-danger { background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
    .btn-danger:hover { background: #991b1b; color: #fff; }
    .btn-off { background: #232734; color: var(--text-muted); }
    .btn-off:hover { background: #2e3446; color: var(--text); }
    .btn-sm { padding: 4px 10px; font-size: 12px; }

    /* Cards & Layout */
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 18px; }
    .card-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
    .node-box { background: #11131a; border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
    .node-header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 10px; border-bottom: 1px solid #1a1e29; margin-bottom: 10px; }
    .slot-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; font-size: 13px; }
    .sensor-badge { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: #1c202d; color: #93c5fd; padding: 3px 8px; border-radius: 4px; border: 1px solid #283044; }

    /* Alert Banner */
    .alert-banner { background: #451a03; border: 1px solid #78350f; color: #fde68a; padding: 12px 16px; border-radius: 6px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; font-size: 13px; }

    /* Tables & Inputs */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-weight: 500; font-size: 12px; text-transform: uppercase; }
    input, select { background: var(--input-bg); border: 1px solid var(--input-border); color: var(--text); padding: 8px 12px; border-radius: 6px; width: 100%; font-size: 13px; margin: 4px 0 12px 0; outline: none; }
    input:focus, select:focus { border-color: var(--primary); }
    label { font-size: 12px; color: var(--text-muted); font-weight: 500; }
    .checkbox-line { display: flex; align-items: center; gap: 8px; margin: 8px 0 12px 0; }
    .checkbox-line input { width: auto; margin: 0; }

    /* Modal */
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: none; align-items: center; justify-content: center; z-index: 100; }
    .modal { background: var(--card); border: 1px solid var(--border); border-radius: 8px; width: 90%; max-width: 420px; padding: 22px; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }

    /* Login Screen Container */
    .login-container { min-height: 80vh; display: flex; align-items: center; justify-content: center; }
    .login-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; width: 100%; max-width: 360px; padding: 26px; }

    /* Toast */
    #toast { position: fixed; bottom: 20px; right: 20px; background: #1f2430; border: 1px solid var(--border); color: var(--text); padding: 10px 18px; border-radius: 6px; font-size: 13px; transform: translateY(100px); opacity: 0; transition: 0.2s; z-index: 200; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }
    #toast.show { transform: translateY(0); opacity: 1; }
    #toast.success { border-color: var(--success); }
    #toast.error { border-color: var(--danger); }
  </style>
</head>
<body>

  <!-- 1. LOGIN SCREEN (RENDERED WHEN NOT AUTHENTICATED) -->
  <div id="loginView" class="login-container" style="display:none;">
    <div class="login-card">
      <div style="font-size:16px; font-weight:700; margin-bottom:4px;">Mini-HA Supervisor</div>
      <div style="color:var(--text-muted); font-size:13px; margin-bottom:18px;">Sign in to access your local hub</div>
      <form onsubmit="handleLogin(event)">
        <label>Username</label>
        <input type="text" id="loginUser" required autocomplete="username" autofocus>
        <label>Password</label>
        <input type="password" id="loginPass" required autocomplete="current-password">
        <button type="submit" class="btn" style="width:100%; margin-top:6px;">Sign In</button>
      </form>
    </div>
  </div>

  <!-- 2. MAIN HUB INTERFACE -->
  <div id="hubView" style="display:none;">
    <!-- Topbar Navigation -->
    <div class="topbar">
      <div class="brand">
        <span class="status-dot"></span>
        <span>Mini-HA Hub</span>
      </div>
      <div class="nav-actions">
        <span class="badge" id="roleBadge">ROLE</span>
        <button class="btn btn-secondary btn-sm" onclick="showTab('nodes')">Overview</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('users')">Users</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('settings')">Settings</button>
        <button class="btn btn-secondary btn-sm" onclick="openPassModal()">Account</button>
        <button class="btn btn-secondary btn-sm" onclick="handleLogout()">Sign Out</button>
      </div>
    </div>

    <!-- Default Password Warning Banner -->
    <div id="defaultPassBanner" class="alert-banner" style="display:none;">
      <div>
        <strong>Default Password Active:</strong> Your hub is using default credentials (<code>admin / admin123</code>). Change your password now to secure your system.
      </div>
      <button class="btn btn-sm" onclick="openPassModal()">Change Password</button>
    </div>

    <!-- TAB 1: OVERVIEW & ENTITIES -->
    <div id="tabNodes">
      <div class="card">
        <div class="card-title">Connected Mesh Nodes & Live Entities</div>
        <div id="entitiesGrid" class="grid">
          <div style="color:var(--text-muted);">Loading mesh entities...</div>
        </div>
      </div>

      <div class="card admin-only" id="discoveryCard">
        <div class="card-title">Discovered Unbound Slaves</div>
        <div id="pendingTable">
          <div style="color:var(--text-muted);">No unconfigured devices detected on bus.</div>
        </div>
      </div>
    </div>

    <!-- TAB 2: USER MANAGEMENT (ADMIN ONLY) -->
    <div id="tabUsers" style="display:none;">
      <div class="card">
        <div class="card-title">
          <span>User Accounts</span>
          <button class="btn btn-sm" onclick="openAddUserModal()">+ Add User</button>
        </div>
        <div id="usersTable">Loading users...</div>
      </div>
    </div>

    <!-- TAB 3: NETWORK & CLOUD SETTINGS (ADMIN ONLY) -->
    <div id="tabSettings" style="display:none;">
      <div class="card">
        <div class="card-title">Home Wi-Fi (Station Connection)</div>
        <label>Wi-Fi Network Name (SSID)</label>
        <input type="text" id="cfgStaSSID" placeholder="e.g. MyHomeNetwork">
        <label>Wi-Fi Password</label>
        <input type="password" id="cfgStaPass" placeholder="Leave blank to keep existing">
      </div>

      <div class="card">
        <div class="card-title">Supla Cloud Bridge</div>
        <div class="checkbox-line">
          <input type="checkbox" id="cfgSuplaEn">
          <label for="cfgSuplaEn" style="cursor:pointer; color:var(--text);">Enable Supla Cloud Mobile Integration</label>
        </div>
        <div style="font-size:12px; color:var(--text-muted); line-height:1.4; margin-bottom:12px;">
          1. Log into <a href="https://cloud.supla.org" target="_blank" style="color:#60a5fa;">cloud.supla.org</a>.<br>
          2. Under the <strong>My SUPLA</strong> tab (plug icon), click <strong>"Device registration: CLICK TO ENABLE"</strong> in the top right.<br>
          3. Enter your assigned Server and Email below and click Save. The Master pairs automatically with on-chip generated keys!
        </div>
        <label>Supla Server</label>
        <input type="text" id="cfgSuplaServer" placeholder="e.g. svr12.supla.org">
        <label>Supla Account Email</label>
        <input type="email" id="cfgSuplaEmail" placeholder="your_email@domain.com">
      </div>

      <button class="btn" onclick="saveSystemSettings()">Save Settings & Restart</button>
    </div>
  </div>

  <!-- MODAL: CHANGE PASSWORD -->
  <div id="passModal" class="modal-overlay">
    <div class="modal">
      <div style="font-size:15px; font-weight:600; margin-bottom:12px;" id="passModalTitle">Change Password</div>
      <label>New Password</label>
      <input type="password" id="modalNewPass" required>
      <label>Confirm Password</label>
      <input type="password" id="modalConfirmPass" required>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('passModal')">Cancel</button>
        <button class="btn btn-sm" onclick="submitPassChange()">Save</button>
      </div>
    </div>
  </div>

  <!-- MODAL: ADD USER -->
  <div id="addUserModal" class="modal-overlay">
    <div class="modal">
      <div style="font-size:15px; font-weight:600; margin-bottom:12px;">Add User Account</div>
      <label>Username</label>
      <input type="text" id="addUserName" required>
      <label>Password</label>
      <input type="password" id="addUserPass" required>
      <label>Role</label>
      <select id="addUserRole">
        <option value="guest">Guest (View only)</option>
        <option value="member">Member (Controls allowed)</option>
        <option value="admin">Admin (Full settings & users)</option>
      </select>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('addUserModal')">Cancel</button>
        <button class="btn btn-sm" onclick="submitAddUser()">Create User</button>
      </div>
    </div>
  </div>

  <!-- MODAL: BIND NODE -->
  <div id="bindModal" class="modal-overlay">
    <div class="modal">
      <div style="font-size:15px; font-weight:600; margin-bottom:12px;">Bind Mesh Slave</div>
      <div style="font-size:12px; color:var(--text-muted); margin-bottom:10px;" id="bindMacLabel">MAC: --</div>
      <label>Assign Node ID (e.g. N01, N02)</label>
      <input type="text" id="bindNodeId" value="N01" required>
      <label>Friendly Name (e.g. Living Room, Tank)</label>
      <input type="text" id="bindNodeName" placeholder="Friendly Name" required>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('bindModal')">Cancel</button>
        <button class="btn btn-sm" onclick="submitBindNode()">Bind Node</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification Element -->
  <div id="toast">Notification</div>

  <script>
    let currentSession = { loggedIn: false, user: '', role: 'guest', isDefault: false };
    let configuredNodes = [];
    let liveStates = {};
    let activeBindMac = '';

    function showToast(msg, type = 'normal') {
      const t = document.getElementById('toast');
      t.innerText = msg;
      t.className = type + ' show';
      setTimeout(() => { t.className = ''; }, 3200);
    }

    function closeModal(id) {
      document.getElementById(id).style.display = 'none';
    }

    function showTab(tab) {
      document.getElementById('tabNodes').style.display = (tab === 'nodes') ? 'block' : 'none';
      document.getElementById('tabUsers').style.display = (tab === 'users') ? 'block' : 'none';
      document.getElementById('tabSettings').style.display = (tab === 'settings') ? 'block' : 'none';
      if (tab === 'users') loadUsers();
      if (tab === 'settings') loadSettings();
    }

    async function checkSession() {
      try {
        const res = await fetch('/api/session');
        const data = await res.json();
        currentSession = data;
        if (data.loggedIn) {
          document.getElementById('loginView').style.display = 'none';
          document.getElementById('hubView').style.display = 'block';
          document.getElementById('roleBadge').innerText = data.user + ' (' + data.role.toUpperCase() + ')';
          
          const isAdmin = (data.role === 'admin');
          document.querySelectorAll('.admin-only').forEach(el => el.style.display = isAdmin ? 'block' : 'none');
          document.getElementById('defaultPassBanner').style.display = (isAdmin && data.isDefault) ? 'flex' : 'none';

          refreshData();
        } else {
          document.getElementById('loginView').style.display = 'flex';
          document.getElementById('hubView').style.display = 'none';
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function handleLogin(e) {
      e.preventDefault();
      const u = document.getElementById('loginUser').value.trim();
      const p = document.getElementById('loginPass').value;
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user: u, pass: p })
        });
        const data = await res.json();
        if (res.ok) {
          showToast('Signed in successfully', 'success');
          checkSession();
        } else {
          showToast(data.error || 'Login failed', 'error');
        }
      } catch (e) {
        showToast('Connection failed', 'error');
      }
    }

    async function handleLogout() {
      await fetch('/api/logout', { method: 'POST' });
      showToast('Signed out');
      checkSession();
    }

    // Nodes & Live Telemetry
    async function refreshData() {
      if (!currentSession.loggedIn) return;
      try {
        const [nRes, sRes] = await Promise.all([fetch('/api/nodes'), fetch('/api/state')]);
        const nData = await nRes.json();
        const sData = await sRes.json();

        configuredNodes = nData.nodes || [];
        liveStates = {};
        if (sData.nodes) {
          sData.nodes.forEach(n => { liveStates[n.id] = n; });
        }
        renderEntities();

        if (currentSession.role === 'admin') {
          const pRes = await fetch('/api/pending');
          const pData = await pRes.json();
          renderPending(pData.pending || []);
        }
      } catch (e) {
        console.error(e);
      }
    }

    function renderEntities() {
      const c = document.getElementById('entitiesGrid');
      if (configuredNodes.length === 0) {
        c.innerHTML = '<div style="color:var(--text-muted); padding:10px 0;">No nodes configured yet. Connect a slave node to the RS-422 bus or Wi-Fi to bind it.</div>';
        return;
      }

      let html = '';
      configuredNodes.forEach(node => {
        const state = liveStates[node.id] || { relays: [], dist: -1, temp: 0, hum: 0, lastSeen: 999 };
        const seen = state.lastSeen < 10 ? '<span style="color:var(--success);">online</span>' : `${state.lastSeen}s ago`;

        html += `<div class="node-box">
          <div class="node-header">
            <strong>${node.name || node.id} (${node.id})</strong>
            <span style="font-size:12px; color:var(--text-muted);">${seen}</span>
          </div>`;

        if (node.slots && node.slots.length > 0) {
          node.slots.forEach(slot => {
            const slotName = slot.name || `Slot ${slot.slot}`;
            if (slot.type === 1) { // Relay
              const isRelayOn = (state.relays && state.relays[slot.slot] === 1);
              const btnClass = isRelayOn ? 'btn' : 'btn btn-off';
              const canControl = (currentSession.role === 'admin' || currentSession.role === 'member');
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <button class="${btnClass} btn-sm" ${canControl ? '' : 'disabled'} onclick="toggleRelay('${node.id}', ${slot.slot}, ${isRelayOn})">${isRelayOn ? 'ON' : 'OFF'}</button>
              </div>`;
            } else if (slot.type === 6 || slot.type === 7) { // DHT
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <span class="sensor-badge">${state.temp.toFixed(1)} °C | ${state.hum.toFixed(1)} %</span>
              </div>`;
            } else if (slot.type === 4 || slot.type === 5) { // Ultrasonic
              const dist = state.dist >= 0 ? `${state.dist} cm` : '--';
              html += `<div class="slot-row">
                <span>${slotName}</span>
                <span class="sensor-badge">${dist}</span>
              </div>`;
            }
          });
        } else {
          html += '<div style="color:var(--text-muted); font-size:12px;">No slots configured.</div>';
        }
        html += `</div>`;
      });
      c.innerHTML = html;
    }

    async function toggleRelay(nodeId, slot, curState) {
      const val = curState ? 0 : 1;
      await fetch('/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: nodeId, slot: slot, val: val })
      });
      refreshData();
    }

    function renderPending(pending) {
      const c = document.getElementById('pendingTable');
      if (pending.length === 0) {
        c.innerHTML = '<div style="color:var(--text-muted); padding:6px 0;">No unconfigured devices detected on bus.</div>';
        return;
      }
      let html = '<table><tr><th>MAC</th><th>Chip</th><th>GPIOs</th><th>Action</th></tr>';
      pending.forEach(d => {
        html += `<tr>
          <td><code>${d.mac}</code></td>
          <td>${d.chip}</td>
          <td>${d.gpios}</td>
          <td><button class="btn btn-sm" onclick="openBindModal('${d.mac}')">Bind</button></td>
        </tr>`;
      });
      c.innerHTML = html + '</table>';
    }

    function openBindModal(mac) {
      activeBindMac = mac;
      document.getElementById('bindMacLabel').innerText = 'Device MAC: ' + mac;
      document.getElementById('bindModal').style.display = 'flex';
    }

    async function submitBindNode() {
      const id = document.getElementById('bindNodeId').value.trim();
      const name = document.getElementById('bindNodeName').value.trim();
      if (!id || !name) return showToast('Fill all fields', 'error');

      await fetch('/api/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac: activeBindMac, id: id, name: name })
      });
      closeModal('bindModal');
      showToast('Node binding dispatched', 'success');
      refreshData();
    }

    // User Management
    async function loadUsers() {
      try {
        const res = await fetch('/api/users');
        const data = await res.json();
        let html = '<table><tr><th>Username</th><th>Role</th><th>Status</th><th>Actions</th></tr>';
        (data.users || []).forEach(u => {
          const status = u.isDefault ? '<span style="color:var(--warning);">Default Pass</span>' : '<span style="color:var(--success);">Active</span>';
          html += `<tr>
            <td><strong>${u.user}</strong></td>
            <td><span class="badge">${u.role}</span></td>
            <td>${status}</td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="openPassModal('${u.user}')">Password</button>
              ${u.user !== 'admin' ? `<button class="btn btn-danger btn-sm" onclick="deleteUser('${u.user}')">Delete</button>` : ''}
            </td>
          </tr>`;
        });
        document.getElementById('usersTable').innerHTML = html + '</table>';
      } catch (e) {
        console.error(e);
      }
    }

    let activePassUser = '';
    function openPassModal(targetUser = null) {
      activePassUser = targetUser || currentSession.user;
      document.getElementById('passModalTitle').innerText = 'Change Password: ' + activePassUser;
      document.getElementById('modalNewPass').value = '';
      document.getElementById('modalConfirmPass').value = '';
      document.getElementById('passModal').style.display = 'flex';
    }

    async function submitPassChange() {
      const p1 = document.getElementById('modalNewPass').value;
      const p2 = document.getElementById('modalConfirmPass').value;
      if (!p1 || p1 !== p2) return showToast('Passwords must match and cannot be empty', 'error');

      const res = await fetch('/api/users/edit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: activePassUser, pass: p1 })
      });
      if (res.ok) {
        closeModal('passModal');
        showToast('Password updated successfully', 'success');
        checkSession();
      } else {
        showToast('Failed to update password', 'error');
      }
    }

    function openAddUserModal() {
      document.getElementById('addUserName').value = '';
      document.getElementById('addUserPass').value = '';
      document.getElementById('addUserModal').style.display = 'flex';
    }

    async function submitAddUser() {
      const u = document.getElementById('addUserName').value.trim();
      const p = document.getElementById('addUserPass').value;
      const r = document.getElementById('addUserRole').value;
      if (!u || !p) return showToast('Username and password required', 'error');

      const res = await fetch('/api/users/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: u, pass: p, role: r })
      });
      const data = await res.json();
      if (res.ok) {
        closeModal('addUserModal');
        showToast('User created successfully', 'success');
        loadUsers();
      } else {
        showToast(data.error || 'Failed to add user', 'error');
      }
    }

    async function deleteUser(u) {
      if (!confirm(`Delete user '${u}'?`)) return;
      const res = await fetch('/api/users/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: u })
      });
      const data = await res.json();
      if (res.ok) {
        showToast('User deleted', 'success');
        loadUsers();
      } else {
        showToast(data.error || 'Error deleting user', 'error');
      }
    }

    // Settings
    async function loadSettings() {
      try {
        const res = await fetch('/api/system');
        const data = await res.json();
        document.getElementById('cfgStaSSID').value = data.sta_ssid || '';
        document.getElementById('cfgStaPass').value = '';
        document.getElementById('cfgSuplaEn').checked = !!data.supla_enabled;
        document.getElementById('cfgSuplaServer').value = data.supla_server || '';
        document.getElementById('cfgSuplaEmail').value = data.supla_email || '';
      } catch (e) {
        console.error(e);
      }
    }

    async function saveSystemSettings() {
      const payload = {
        sta_ssid: document.getElementById('cfgStaSSID').value.trim(),
        sta_pass: document.getElementById('cfgStaPass').value,
        sta_enabled: document.getElementById('cfgStaSSID').value.trim().length > 0,
        supla_enabled: document.getElementById('cfgSuplaEn').checked,
        supla_server: document.getElementById('cfgSuplaServer').value.trim(),
        supla_email: document.getElementById('cfgSuplaEmail').value.trim()
      };
      await fetch('/api/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast('Settings saved. Hub is rebooting...', 'success');
    }

    // Init
    checkSession();
    setInterval(refreshData, 3000);
  </script>
</body>
</html>
)rawliteral";
    webServer.send(200, "text/html; charset=utf-8", html);
  });
}
