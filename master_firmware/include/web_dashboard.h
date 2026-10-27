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

  // Cloud MQTT Bridge (EMQX / Custom Broker)
  bool mqttEnabled = false;
  String mqttBroker = "";
  uint16_t mqttPort = 8883;
  String mqttUser = "";
  String mqttPass = "";
  String mqttHomeId = "home_1";
};

extern SystemSecurityConfig sysSecurity;
extern void publishMqttState();

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

inline UserRole validateToken(const String& token, String* outUsername = nullptr) {
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

inline UserRole getAuthenticatedRole(String* outUsername = nullptr) {
  String token = getRequestToken();
  return validateToken(token, outUsername);
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

inline String createSessionForUser(const String& user, const String& pass, UserRole* outRole = nullptr, String* outRoleStr = nullptr) {
  File f = LittleFS.open(USERS_CONFIG_PATH, "r");
  if (!f) return "";
  DynamicJsonDocument doc(2048);
  deserializeJson(doc, f);
  f.close();

  bool matched = false;
  String roleStr = "guest";
  for (JsonObject u : doc["users"].as<JsonArray>()) {
    if (u["user"].as<String>() == user && u["pass"].as<String>() == pass) {
      matched = true;
      roleStr = u["role"].as<String>();
      break;
    }
  }

  if (!matched) return "";

  String token = generateRandomToken();
  UserRole uRole = roleNameToEnum(roleStr);
  if (outRole) *outRole = uRole;
  if (outRoleStr) *outRoleStr = roleStr;

  int slot = -1;
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (activeSessions[i].token.length() == 0 || millis() - activeSessions[i].lastActive > 86400000UL) {
      slot = i;
      break;
    }
  }
  if (slot == -1) slot = 0;

  activeSessions[slot].token = token;
  activeSessions[slot].username = user;
  activeSessions[slot].role = uRole;
  activeSessions[slot].lastActive = millis();

  return token;
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

    UserRole uRole = ROLE_NONE;
    String userRoleStr = "";
    String token = createSessionForUser(user, pass, &uRole, &userRoleStr);

    if (token.length() == 0) {
      webServer.send(401, "application/json; charset=utf-8", "{\"error\":\"Invalid username or password\"}");
      return;
    }

    bool isDefault = (user == "admin" && pass == "admin123");
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
    GenericNodeTelemetry* ns = getOrCreateNodeState(target);
    if (ns && slot >= 1 && slot <= MAX_GPIO_SLOTS) {
      ns->relayStates[slot - 1] = (val == 1);
    }
    publishMqttState();
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Command dispatched\"}");
  });

  // 12. Read System & Cloud Configuration
  webServer.on("/api/system", HTTP_GET, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    DynamicJsonDocument doc(512);
    doc["ap_ssid"] = sysSecurity.apSsid;
    doc["sta_ssid"] = sysSecurity.staSsid;
    doc["sta_enabled"] = sysSecurity.staEnabled;
    doc["mqtt_enabled"] = sysSecurity.mqttEnabled;
    doc["mqtt_broker"] = sysSecurity.mqttBroker;
    doc["mqtt_port"] = sysSecurity.mqttPort;
    doc["mqtt_user"] = sysSecurity.mqttUser;
    doc["mqtt_home_id"] = sysSecurity.mqttHomeId;
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

    if (doc.containsKey("mqtt_enabled")) sysSecurity.mqttEnabled = doc["mqtt_enabled"].as<bool>();
    if (doc.containsKey("mqtt_broker")) sysSecurity.mqttBroker = doc["mqtt_broker"].as<String>();
    if (doc.containsKey("mqtt_port")) sysSecurity.mqttPort = doc["mqtt_port"].as<uint16_t>();
    if (doc.containsKey("mqtt_user")) sysSecurity.mqttUser = doc["mqtt_user"].as<String>();
    if (doc.containsKey("mqtt_pass") && doc["mqtt_pass"].as<String>().length() > 0) {
      sysSecurity.mqttPass = doc["mqtt_pass"].as<String>();
    }
    if (doc.containsKey("mqtt_home_id")) sysSecurity.mqttHomeId = doc["mqtt_home_id"].as<String>();

    File f = LittleFS.open(SYSTEM_CONFIG_PATH, "w");
    if (f) {
      DynamicJsonDocument outDoc(1024);
      outDoc["ap_ssid"] = sysSecurity.apSsid;
      outDoc["ap_pass"] = sysSecurity.apPass;
      outDoc["sta_ssid"] = sysSecurity.staSsid;
      outDoc["sta_pass"] = sysSecurity.staPass;
      outDoc["sta_enabled"] = sysSecurity.staEnabled;
      outDoc["mqtt_enabled"] = sysSecurity.mqttEnabled;
      outDoc["mqtt_broker"] = sysSecurity.mqttBroker;
      outDoc["mqtt_port"] = sysSecurity.mqttPort;
      outDoc["mqtt_user"] = sysSecurity.mqttUser;
      outDoc["mqtt_pass"] = sysSecurity.mqttPass;
      outDoc["mqtt_home_id"] = sysSecurity.mqttHomeId;
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

  // 15. Dynamic Rules API
  webServer.on("/api/rules", HTTP_GET, []() {
    if (!requireRole(ROLE_GUEST)) return;
    File f = LittleFS.open(RULES_CONFIG_PATH, "r");
    if (!f) {
      webServer.send(200, "application/json; charset=utf-8", "{\"rules\":[]}");
      return;
    }
    webServer.streamFile(f, "application/json; charset=utf-8");
    f.close();
  });

  webServer.on("/api/rules", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(4096);
    DeserializationError err = deserializeJson(doc, webServer.arg("plain"));
    if (err) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"Invalid JSON\"}");
      return;
    }
    File f = LittleFS.open(RULES_CONFIG_PATH, "w");
    if (!f) {
      webServer.send(500, "application/json; charset=utf-8", "{\"error\":\"Storage error\"}");
      return;
    }
    serializeJson(doc, f);
    f.close();
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Rules updated\"}");
  });

  // 16. Captive Portal Detection Handlers
  auto handleCaptiveRedirect = []() {
    webServer.sendHeader("Location", "http://192.168.4.1/", true);
    webServer.send(302, "text/plain", "");
  };
  webServer.on("/generate_204", handleCaptiveRedirect);
  webServer.on("/gen_204", handleCaptiveRedirect);
  webServer.on("/hotspot-detect.html", handleCaptiveRedirect);
  webServer.on("/ncsi.txt", handleCaptiveRedirect);
  webServer.on("/connecttest.txt", handleCaptiveRedirect);
  webServer.onNotFound([]() {
    String host = webServer.hostHeader();
    if (host.indexOf("192.168.4.1") == -1 && host.indexOf("miniha.local") == -1) {
      webServer.sendHeader("Location", "http://192.168.4.1/", true);
      webServer.send(302, "text/plain", "");
      return;
    }
    webServer.send(404, "text/plain", "Not Found");
  });

  // 17. Modern Single Page Application (Dashboard + Login)
  webServer.on("/", HTTP_GET, []() {
    String html = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini-HA Supervisor Console</title>
  
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">

  <style>
    :root {
      --bg: #0a0d14;
      --card-bg: #111625;
      --card-bg-elevated: #161e31;
      --card-border: rgba(255, 255, 255, 0.08);
      --card-border-focus: rgba(59, 130, 246, 0.5);
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --primary-glow: rgba(37, 99, 235, 0.35);
      --success: #10b981;
      --success-glow: rgba(16, 185, 129, 0.25);
      --warning: #f59e0b;
      --danger: #ef4444;
      --input-bg: #0c101c;
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 18px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      background-image: 
        radial-gradient(ellipse 70% 40% at 50% -10%, rgba(37, 99, 235, 0.12), transparent),
        radial-gradient(circle at 90% 90%, rgba(16, 185, 129, 0.03), transparent 35%);
      color: var(--text);
      min-height: 100vh;
      padding: 0;
      font-size: 14px;
      -webkit-font-smoothing: antialiased;
    }

    .icon {
      display: inline-block;
      width: 16px;
      height: 16px;
      stroke-width: 2;
      stroke: currentColor;
      fill: none;
      stroke-linecap: round;
      stroke-linejoin: round;
      vertical-align: middle;
      flex-shrink: 0;
    }

    /* Top Bar */
    .topbar {
      background: rgba(11, 15, 23, 0.85);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 14px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-badge {
      width: 36px;
      height: 36px;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, #1e293b, #0f172a);
      border: 1px solid rgba(255, 255, 255, 0.1);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #60a5fa;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }
    .brand-title-wrap {
      display: flex;
      flex-direction: column;
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.3px;
      color: var(--text);
      line-height: 1.2;
    }
    .brand-subtitle {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-dim);
    }

    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success-glow);
      display: inline-block;
    }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Buttons & Badges */
    .badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 20px;
      background: rgba(37, 99, 235, 0.15);
      color: #93c5fd;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }
    .btn {
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.12);
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
      transition: all 0.2s;
    }
    .btn:hover {
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
    }
    .btn:active { transform: scale(0.98); }
    .btn-secondary {
      background: rgba(22, 30, 49, 0.7);
      color: var(--text);
      border: 1px solid var(--card-border);
      box-shadow: none;
    }
    .btn-secondary:hover {
      background: #1e293b;
      border-color: rgba(255, 255, 255, 0.15);
    }
    .btn-danger {
      background: rgba(127, 29, 29, 0.6);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.3);
      box-shadow: none;
    }
    .btn-danger:hover {
      background: #991b1b;
      color: #fff;
    }
    .btn-sm { padding: 5px 12px; font-size: 12px; }

    /* App Shell Container */
    .app-container {
      max-width: 1240px;
      margin: 0 auto;
      padding: 24px 20px 48px;
      width: 100%;
    }

    /* Cards & Bento Grid */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-lg);
      padding: 22px;
      margin-bottom: 20px;
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.35);
    }
    .card-title {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-dim);
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
      gap: 16px;
    }
    .node-box {
      background: #0d121f;
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: var(--radius-md);
      padding: 16px;
      transition: border-color 0.2s;
    }
    .node-box:hover {
      border-color: rgba(255, 255, 255, 0.12);
    }
    .node-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      margin-bottom: 12px;
    }
    .slot-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      font-size: 13px;
    }

    /* Tactile Toggle Switch (Apple-style) */
    .toggle-btn {
      position: relative;
      width: 52px;
      height: 28px;
      background: #1e293b;
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      cursor: pointer;
      transition: background 0.25s, box-shadow 0.25s;
      flex-shrink: 0;
    }
    .toggle-slider {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 22px;
      height: 22px;
      background: #fff;
      border-radius: 50%;
      box-shadow: 0 2px 4px rgba(0,0,0,0.4);
      transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .toggle-btn.active {
      background: var(--primary);
      box-shadow: 0 0 12px var(--primary-glow);
    }
    .toggle-btn.active .toggle-slider {
      transform: translateX(24px);
    }
    .toggle-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    /* Sensor Pills */
    .sensor-readings { display: flex; gap: 8px; }
    .sensor-pill {
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: var(--radius-sm);
      padding: 4px 9px;
      display: flex;
      align-items: center;
      gap: 5px;
    }
    .pill-label {
      font-size: 9px;
      font-weight: 700;
      color: var(--text-dim);
      text-transform: uppercase;
    }
    .pill-val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      font-weight: 600;
      color: #93c5fa;
    }
    .pill-unit { font-size: 10px; color: var(--text-dim); }

    /* Tank Bar */
    .tank-header { display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 6px; }
    .tank-bar-container {
      width: 100%;
      height: 9px;
      background: #172033;
      border-radius: 5px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .tank-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #0284c7, #38bdf8);
      border-radius: 5px;
      transition: width 0.5s ease;
    }

    /* Alert Banner */
    .alert-banner {
      background: linear-gradient(135deg, rgba(120, 53, 15, 0.4), rgba(69, 26, 3, 0.5));
      border: 1px solid rgba(245, 158, 11, 0.3);
      color: #fde68a;
      padding: 14px 18px;
      border-radius: var(--radius-md);
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
    }

    /* Tables & Inputs */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--card-border); }
    th { color: var(--text-dim); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
    
    input, select {
      background: var(--input-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 10px 14px;
      border-radius: var(--radius-md);
      width: 100%;
      font-size: 13px;
      font-family: inherit;
      margin: 4px 0 14px 0;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus, select:focus {
      border-color: var(--card-border-focus);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }
    label { font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
    .checkbox-line { display: flex; align-items: center; gap: 10px; margin: 8px 0 14px 0; }
    .checkbox-line input { width: auto; margin: 0; }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
    }
    .modal {
      background: #131a2b;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: var(--radius-lg);
      width: 90%;
      max-width: 440px;
      padding: 24px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
    }
    .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 16px; }

    /* High-End Hardware Supervisor Login Screen */
    .login-container {
      min-height: 85vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .login-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      width: 100%;
      max-width: 420px;
      padding: 34px 28px;
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
      position: relative;
    }
    .login-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 15%;
      right: 15%;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.5), transparent);
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1e293b;
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text);
      padding: 12px 20px;
      border-radius: 30px;
      font-size: 13px;
      font-weight: 600;
      transform: translateY(100px);
      opacity: 0;
      transition: 0.3s;
      z-index: 200;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }
    #toast.show { transform: translateY(0); opacity: 1; }
    #toast.success { background: #064e3b; border-color: #059669; }
    #toast.error { background: #7f1d1d; border-color: #dc2626; }
  </style>
</head>
<body>

  <!-- 1. LOGIN SCREEN (HARDWARE SUPERVISOR APPLIANCE) -->
  <div id="loginView" class="login-container" style="display:none;">
    <div class="login-card">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:16px;">
        <div class="brand-badge">
          <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
          </svg>
        </div>
        <div>
          <div style="font-size:17px; font-weight:800; letter-spacing:-0.3px;">Mini-HA Supervisor</div>
          <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--text-dim); letter-spacing:0.5px;">Master Hardware Console</div>
        </div>
      </div>

      <div style="font-size:13px; color:var(--text-muted); line-height:1.5; margin-bottom:20px;">
        Sign in to manage isolated RS-422 bus nodes, star-mesh wireless slaves, and cloud bridge routing.
      </div>

      <form onsubmit="handleLogin(event)">
        <label>Username</label>
        <div style="position:relative; display:flex; align-items:center;">
          <input type="text" id="loginUser" required autocomplete="username" autofocus placeholder="admin">
        </div>

        <label>Password</label>
        <div style="position:relative; display:flex; align-items:center;">
          <input type="password" id="loginPass" required autocomplete="current-password" placeholder="Password">
          <button type="button" onclick="togglePassVisibilityLocal()" style="position:absolute; right:12px; top:12px; background:none; border:none; color:var(--text-muted); cursor:pointer;">
            <svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>

        <button type="submit" class="btn" style="width:100%; margin-top:8px;">Sign In to Console</button>
      </form>

      <div style="margin-top:20px; padding-top:14px; border-top:1px solid rgba(255,255,255,0.06); display:flex; justify-content:space-between; align-items:center; font-size:11px; color:var(--text-dim);">
        <span>Local Host: miniha.local</span>
        <span style="font-family:'JetBrains Mono', monospace;">Firmware v2.4</span>
      </div>
    </div>
  </div>

  <!-- 2. MAIN HUB INTERFACE -->
  <div id="hubView" style="display:none;">
    <!-- Topbar Navigation -->
    <div class="topbar">
      <div class="brand">
        <div class="brand-badge">
          <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24">
            <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
            <polyline points="9 22 9 12 15 12 15 22"/>
          </svg>
        </div>
        <div class="brand-title-wrap">
          <span class="brand-title">Mini-HA Hub</span>
          <span class="brand-subtitle">Supervisor Active</span>
        </div>
      </div>
      <div class="nav-actions">
        <span class="badge" id="roleBadge">ROLE</span>
        <button class="btn btn-secondary btn-sm" onclick="showTab('nodes')">Overview</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('rules')">Rules</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('users')">Users</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('settings')">Settings</button>
        <button class="btn btn-secondary btn-sm" onclick="openPassModal()">Account</button>
        <button class="btn btn-secondary btn-sm" onclick="handleLogout()">Sign Out</button>
      </div>
    </div>

    <div class="app-container">
      <!-- Default Password Warning Banner -->
      <div id="defaultPassBanner" class="alert-banner" style="display:none;">
        <div>
          <strong>Security Notice:</strong> Your hub is currently using the factory default credentials (<code>admin / admin123</code>). Change your password now.
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

    <!-- TAB: AUTOMATION RULES & NOTIFICATIONS (ADMIN ONLY) -->
    <div id="tabRules" style="display:none;">
      <div class="card">
        <div class="card-title">
          <span>Automation Rules & Push Notifications</span>
          <button class="btn btn-sm" onclick="saveRulesConfig()">Save Rules</button>
        </div>
        <div id="rulesList"><div style="color:var(--text-muted);">Loading automation rules...</div></div>
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
        <div class="card-title">Cloud MQTT Bridge (EMQX / Custom Broker)</div>
        <div class="checkbox-line">
          <input type="checkbox" id="cfgMqttEn">
          <label for="cfgMqttEn" style="cursor:pointer; color:var(--text);">Enable Cloud MQTT Integration (for PWA / Remote Access)</label>
        </div>
        <div style="font-size:12px; color:var(--text-muted); line-height:1.4; margin-bottom:12px;">
          Connects to your free EMQX Serverless broker (Port 8883 TLS). Allows your PWA to securely control and monitor your smart home remotely without port forwarding or servers.
        </div>
        <label>Broker Host (TLS)</label>
        <input type="text" id="cfgMqttBroker" placeholder="e.g. xxxxxx.emqx.cloud">
        <div style="display:flex; gap:10px;">
          <div style="flex:1;">
            <label>Port</label>
            <input type="number" id="cfgMqttPort" placeholder="8883" value="8883">
          </div>
          <div style="flex:2;">
            <label>Home ID</label>
            <input type="text" id="cfgMqttHomeId" placeholder="e.g. home_1">
          </div>
        </div>
        <label>Broker Username</label>
        <input type="text" id="cfgMqttUser" placeholder="Client Username">
        <label>Broker Password</label>
        <input type="password" id="cfgMqttPass" placeholder="Leave empty to keep existing password">
      </div>

      <button class="btn" onclick="saveSystemSettings()">Save Settings & Restart</button>
    </div>
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
      document.getElementById('tabRules').style.display = (tab === 'rules') ? 'block' : 'none';
      document.getElementById('tabUsers').style.display = (tab === 'users') ? 'block' : 'none';
      document.getElementById('tabSettings').style.display = (tab === 'settings') ? 'block' : 'none';
      if (tab === 'rules') loadRules();
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
        c.innerHTML = '<div style="color:var(--text-dim); padding:12px 0;">No nodes configured yet. Connect a slave node to the RS-422 bus or Wi-Fi to bind it.</div>';
        return;
      }

      let html = '';
      configuredNodes.forEach(node => {
        const state = liveStates[node.id] || { relays: [], dist: -1, temp: 0, hum: 0, lastSeen: 999 };
        const seen = state.lastSeen < 10 ? '<span style="color:var(--success);">online</span>' : `${state.lastSeen}s ago`;

        html += `<div class="node-box">
          <div class="node-header">
            <div>
              <strong style="font-size:14px;">${node.name || node.id}</strong>
              <span style="font-family:\'JetBrains Mono\', monospace; font-size:11px; color:#60a5fa; margin-left:6px;">(${node.id})</span>
            </div>
            <span style="font-size:11px; color:var(--text-dim);">${seen}</span>
          </div>`;

        if (node.slots && node.slots.length > 0) {
          node.slots.forEach(slot => {
            const slotName = slot.name || `Slot ${slot.slot}`;
            if (slot.type === 1) { // Relay
              const isRelayOn = (state.relays && state.relays[slot.slot] === 1);
              const canControl = (currentSession.role === 'admin' || currentSession.role === 'member');
              html += `<div class="slot-row">
                <span style="font-weight:600;">${slotName}</span>
                <button class="toggle-btn ${isRelayOn ? 'active' : ''}" ${canControl ? '' : 'disabled'} onclick="toggleRelay('${node.id}', ${slot.slot}, ${isRelayOn})">
                  <span class="toggle-slider">
                    <svg style="width:10px; height:10px; color:#1e293b;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.02"/></svg>
                  </span>
                </button>
              </div>`;
            } else if (slot.type === 6 || slot.type === 7) { // DHT
              html += `<div class="slot-row">
                <span style="font-weight:600;">${slotName}</span>
                <div class="sensor-readings">
                  <div class="sensor-pill">
                    <svg class="icon" style="width:12px; height:12px; color:#60a5fa;" viewBox="0 0 24 24"><path d="M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z"/></svg>
                    <span class="pill-label">TEMP</span>
                    <span class="pill-val">${state.temp.toFixed(1)}</span>
                    <span class="pill-unit">&deg;C</span>
                  </div>
                  <div class="sensor-pill">
                    <svg class="icon" style="width:12px; height:12px; color:#60a5fa;" viewBox="0 0 24 24"><path d="M12 22a7 7 0 0 0 7-7c0-2-1-3.9-3-5.5s-3.5-4-4-6.5c-.5 2.5-2 4.9-4 6.5C6 11.1 5 13 5 15a7 7 0 0 0 7 7z"/></svg>
                    <span class="pill-label">HUM</span>
                    <span class="pill-val">${state.hum.toFixed(0)}</span>
                    <span class="pill-unit">%</span>
                  </div>
                </div>
              </div>`;
            } else if (slot.type === 4 || slot.type === 5) { // Ultrasonic
              if (slot.type === 4) {
                const distText = state.dist >= 0 ? `${state.dist} cm` : '--';
                const pct = state.dist >= 0 ? Math.max(0, Math.min(100, Math.round(((200 - state.dist) / 200) * 100))) : 0;
                html += `<div class="slot-row" style="flex-direction:column; align-items:stretch; gap:6px;">
                  <div class="tank-header">
                    <span style="font-weight:600; display:flex; align-items:center; gap:6px;">
                      <svg class="icon" style="width:13px; height:13px; color:#38bdf8;" viewBox="0 0 24 24"><path d="M2 12h20"/><path d="M20 12v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8"/><path d="M4 8V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/></svg>
                      ${slotName}
                    </span>
                    <span style="font-family:\'JetBrains Mono\', monospace; font-size:12px; font-weight:600; color:#38bdf8;">${distText} (${pct}%)</span>
                  </div>
                  <div class="tank-bar-container"><div class="tank-bar-fill" style="width:${pct}%"></div></div>
                </div>`;
              }
            }
          });
        } else {
          html += '<div style="color:var(--text-dim); font-size:12px;">No slots configured.</div>';
        }
        html += `</div>`;
      });
      c.innerHTML = html;
    }

    async function toggleRelay(nodeId, slot, curState) {
      const val = curState ? 0 : 1;
      if (!liveStates[nodeId]) liveStates[nodeId] = { relays: [] };
      if (!liveStates[nodeId].relays) liveStates[nodeId].relays = [];
      liveStates[nodeId].relays[slot] = val;
      renderEntities();

      await fetch('/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: nodeId, slot: slot, val: val })
      });
      setTimeout(refreshData, 300);
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

    // Automation Rules & Notifications
    let currentRules = [];

    async function loadRules() {
      try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        currentRules = data.rules || [];
        const container = document.getElementById('rulesList');
        if (currentRules.length === 0) {
          container.innerHTML = '<div style="color:var(--text-muted); padding:10px 0;">No automation rules configured. Default rule files can be defined in /config/rules.json.</div>';
          return;
        }

        let html = '';
        currentRules.forEach((rule, idx) => {
          const condSummary = (rule.conditions || []).map(c => `${c.node} ${c.type} ${c.op} ${c.val}`).join(' AND ');
          const actSummary = (rule.actions || []).map(a => `${a.target} Slot ${a.slot} -> ${a.val === 1 ? 'ON' : 'OFF'}`).join(', ');
          const isEnabled = rule.enabled ? 'checked' : '';
          const isNotify = rule.notify ? 'checked' : '';
          const nTitle = rule.notify_title || rule.name || '';
          const nMsg = rule.notify_msg || 'Automation rule triggered!';

          html += `<div class="node-box" style="margin-bottom:14px;">
            <div class="node-header">
              <strong style="font-size:14px;">${rule.name || ('Rule #' + (idx + 1))}</strong>
              <label class="checkbox-line" style="margin:0;">
                <input type="checkbox" id="ruleEn_${idx}" ${isEnabled}>
                <span>Enabled</span>
              </label>
            </div>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
              <strong>Condition:</strong> ${condSummary || 'None'} <br>
              <strong>Action:</strong> ${actSummary || 'None'}
            </div>
            <div style="background:#161922; border:1px solid #283044; border-radius:6px; padding:10px; margin-top:8px;">
              <label class="checkbox-line" style="margin:0 0 8px 0;">
                <input type="checkbox" id="ruleNotif_${idx}" ${isNotify}>
                <span style="font-weight:700; color:#93c5fd;">Push Notification Alert (Option A)</span>
              </label>
              <label>Alert Title</label>
              <input type="text" id="ruleTitle_${idx}" value="${nTitle}" placeholder="e.g. Tank Low Alert">
              <label>Alert Message</label>
              <input type="text" id="ruleMsg_${idx}" value="${nMsg}" placeholder="e.g. Overhead tank is below 20%">
            </div>
          </div>`;
        });
        container.innerHTML = html;
      } catch (e) {
        console.error(e);
      }
    }

    async function saveRulesConfig() {
      currentRules.forEach((rule, idx) => {
        const enEl = document.getElementById('ruleEn_' + idx);
        const notifEl = document.getElementById('ruleNotif_' + idx);
        const titleEl = document.getElementById('ruleTitle_' + idx);
        const msgEl = document.getElementById('ruleMsg_' + idx);
        if (enEl) rule.enabled = enEl.checked;
        if (notifEl) rule.notify = notifEl.checked;
        if (titleEl) rule.notify_title = titleEl.value.trim();
        if (msgEl) rule.notify_msg = msgEl.value.trim();
      });

      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: currentRules })
      });
      if (res.ok) {
        showToast('Rules & Notification settings saved!', 'success');
      } else {
        showToast('Failed to save rules', 'error');
      }
    }

    // Settings
    async function loadSettings() {
      try {
        const res = await fetch('/api/system');
        const data = await res.json();
        document.getElementById('cfgStaSSID').value = data.sta_ssid || '';
        document.getElementById('cfgStaPass').value = '';
        document.getElementById('cfgMqttEn').checked = !!data.mqtt_enabled;
        document.getElementById('cfgMqttBroker').value = data.mqtt_broker || '';
        document.getElementById('cfgMqttPort').value = data.mqtt_port || 8883;
        document.getElementById('cfgMqttHomeId').value = data.mqtt_home_id || 'home_1';
        document.getElementById('cfgMqttUser').value = data.mqtt_user || '';
        document.getElementById('cfgMqttPass').value = '';
      } catch (e) {
        console.error(e);
      }
    }

    async function saveSystemSettings() {
      const payload = {
        sta_ssid: document.getElementById('cfgStaSSID').value.trim(),
        sta_pass: document.getElementById('cfgStaPass').value,
        sta_enabled: document.getElementById('cfgStaSSID').value.trim().length > 0,
        mqtt_enabled: document.getElementById('cfgMqttEn').checked,
        mqtt_broker: document.getElementById('cfgMqttBroker').value.trim(),
        mqtt_port: parseInt(document.getElementById('cfgMqttPort').value) || 8883,
        mqtt_home_id: document.getElementById('cfgMqttHomeId').value.trim() || 'home_1',
        mqtt_user: document.getElementById('cfgMqttUser').value.trim(),
        mqtt_pass: document.getElementById('cfgMqttPass').value
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
