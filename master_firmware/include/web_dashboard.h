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

#include <mbedtls/sha256.h>

// =========================================================================
// SESSION & USER AUTHENTICATION MANAGER (PERMANENT SESSIONS, SHA-256 HASHING)
// =========================================================================

enum UserRole { ROLE_NONE = 0, ROLE_GUEST = 1, ROLE_MEMBER = 2, ROLE_ADMIN = 3 };

struct ActiveSession {
  String token;
  String username;
  UserRole role;
  unsigned long lastActive;
};

#define MAX_SESSIONS 12
ActiveSession activeSessions[MAX_SESSIONS];

inline String sha256Hex(const String& input) {
  byte output[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA-256
  mbedtls_sha256_update_ret(&ctx, (const unsigned char*)input.c_str(), input.length());
  mbedtls_sha256_finish_ret(&ctx, output);
  mbedtls_sha256_free(&ctx);

  char hexStr[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hexStr + (i * 2), "%02x", output[i]);
  }
  hexStr[64] = '\0';
  return String(hexStr);
}

inline bool verifyPassword(const String& stored, const String& provided) {
  if (stored.length() == 0) return false;
  if (stored == provided) return true; // Legacy plaintext compatibility
  if (stored == sha256Hex(provided)) return true; // SHA-256 hash match
  return false;
}

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

// Invariant: Tokens DO NOT expire based on time (permanent sessions for family/parents)
inline UserRole validateToken(const String& token, String* outUsername = nullptr) {
  if (token.length() == 0) return ROLE_NONE;
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (activeSessions[i].token.length() > 0 && activeSessions[i].token == token) {
      activeSessions[i].lastActive = millis();
      if (outUsername) *outUsername = activeSessions[i].username;
      return activeSessions[i].role;
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
    if (u["user"].as<String>() == user && verifyPassword(u["pass"].as<String>(), pass)) {
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
  // 1. Check if user already has an active session slot (refresh)
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (activeSessions[i].token.length() > 0 && activeSessions[i].username == user) {
      slot = i;
      break;
    }
  }
  // 2. Otherwise pick an empty slot
  if (slot == -1) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (activeSessions[i].token.length() == 0) {
        slot = i;
        break;
      }
    }
  }
  // 3. If all full, evict least recently active (LRU)
  if (slot == -1) {
    unsigned long oldest = 0xFFFFFFFFUL;
    slot = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (activeSessions[i].lastActive < oldest) {
        oldest = activeSessions[i].lastActive;
        slot = i;
      }
    }
  }

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
          if (username == "admin" && verifyPassword(u["pass"].as<String>(), "admin123")) {
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
    nu["pass"] = sha256Hex(newPass);
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
        if (newPass.length() > 0) u["pass"] = sha256Hex(newPass);
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
    doc["free_heap"] = ESP.getFreeHeap();
    doc["total_heap"] = ESP.getHeapSize();
    doc["uptime_sec"] = (uint32_t)(millis() / 1000);
    doc["chip_model"] = ESP.getChipModel();
    doc["chip_cores"] = ESP.getChipCores();
    doc["cpu_freq"] = ESP.getCpuFreqMHz();
    doc["littlefs_total"] = LittleFS.totalBytes();
    doc["littlefs_used"] = LittleFS.usedBytes();
    doc["port1_name"] = "UART1 (RX: GPIO 4, TX: GPIO 5)";
    doc["port2_name"] = "UART2 (RX: GPIO 16, TX: GPIO 17)";
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
    reloadRulesCache();
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Rules updated\"}");
  });

  // 16. OS Network Probes & Offline Handlers (No 302 Redirects, No Spoofing)
  // Respond with standard status codes without redirecting so OS knows it's a local network without internet
  webServer.on("/generate_204", HTTP_GET, []() { webServer.send(204, "text/plain", ""); });
  webServer.on("/gen_204", HTTP_GET, []() { webServer.send(204, "text/plain", ""); });
  webServer.on("/connecttest.txt", HTTP_GET, []() { webServer.send(404, "text/plain", "No Internet"); });
  webServer.on("/ncsi.txt", HTTP_GET, []() { webServer.send(404, "text/plain", "No Internet"); });
  webServer.on("/hotspot-detect.html", HTTP_GET, []() { webServer.send(404, "text/plain", "Not Found"); });

  webServer.onNotFound([]() {
    webServer.send(404, "text/plain", "Not Found");
  });

  // 17. Modern Single Page Application (Dashboard + Login)
  webServer.on("/", HTTP_GET, []() {
    String html = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mini-HA Supervisor</title>
  

  <style>
    :root {
      --bg: #09090b;
      --card-bg: #121215;
      --card-elevated: #18181b;
      --card-border: #27272a;
      --card-border-subtle: #1f1f23;
      --card-border-focus: #52525b;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      
      --text: #fafafa;
      --text-muted: #a1a1aa;
      --text-dim: #71717a;

      --btn-primary-bg: #fafafa;
      --btn-primary-text: #09090b;
      --btn-primary-hover: #e4e4e7;

      --btn-secondary-bg: #18181b;
      --btn-secondary-border: #27272a;
      --btn-secondary-text: #fafafa;
      --btn-secondary-hover: #27272a;

      --input-bg: #141417;

      --success: #10b981;
      --success-subtle: rgba(16, 185, 129, 0.12);
      --success-border: rgba(16, 185, 129, 0.25);

      --warning: #f59e0b;
      --warning-subtle: rgba(245, 158, 11, 0.12);
      --warning-border: rgba(245, 158, 11, 0.25);

      --danger: #ef4444;
      --danger-subtle: rgba(239, 68, 68, 0.12);
      --danger-border: rgba(239, 68, 68, 0.25);

      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font-sans);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 0;
      font-size: 13px;
      -webkit-font-smoothing: antialiased;
    }

    .icon {
      display: inline-block;
      width: 15px;
      height: 15px;
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
      background: rgba(9, 9, 11, 0.95);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      padding: 12px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      position: sticky;
      top: 0;
      z-index: 50;
      gap: 12px;
      flex-wrap: wrap;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand-badge {
      width: 32px;
      height: 32px;
      border-radius: var(--radius-sm);
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text);
    }
    .brand-title-wrap {
      display: flex;
      flex-direction: column;
    }
    .brand-title {
      font-size: 15px;
      font-weight: 700;
      letter-spacing: -0.2px;
      color: var(--text);
      line-height: 1.2;
    }
    .brand-subtitle {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }

    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--success);
      display: inline-block;
    }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    /* Buttons & Badges */
    .badge {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      padding: 4px 8px;
      border-radius: 4px;
      background: var(--card-elevated);
      color: var(--text);
      border: 1px solid var(--card-border);
    }
    .btn {
      background: var(--btn-primary-bg);
      color: var(--btn-primary-text);
      border: none;
      padding: 8px 14px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: background 0.15s;
    }
    .btn:hover {
      background: var(--btn-primary-hover);
    }
    .btn:active { transform: scale(0.98); }
    .btn-secondary {
      background: var(--btn-secondary-bg);
      border: 1px solid var(--btn-secondary-border);
      color: var(--btn-secondary-text);
    }
    .btn-secondary:hover {
      background: #222227;
      border-color: #3f3f46;
    }
    .btn-danger {
      background: var(--danger-subtle);
      color: #fca5a5;
      border: 1px solid var(--danger-border);
    }
    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.2);
    }
    .btn-sm { padding: 5px 10px; font-size: 11px; }

    /* App Shell Container */
    .app-container {
      max-width: 1300px;
      margin: 0 auto;
      padding: 20px 16px 40px;
      width: 100%;
    }

    /* Cards & Grid */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-md);
      padding: 20px;
      margin-bottom: 16px;
    }
    .card-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-dim);
      margin-bottom: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: var(--font-mono);
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
    }
    @media (min-width: 680px) {
      .grid { grid-template-columns: repeat(2, 1fr); gap: 16px; }
    }
    @media (min-width: 1080px) {
      .grid { grid-template-columns: repeat(3, 1fr); }
    }

    .node-box {
      background: var(--input-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-sm);
      padding: 14px;
    }
    .node-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--card-border-subtle);
      margin-bottom: 10px;
    }
    .slot-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 0;
      font-size: 13px;
    }

    /* Tactile Toggle Switch */
    .toggle-btn {
      position: relative;
      width: 50px;
      height: 28px;
      background: #27272a;
      border-radius: 14px;
      border: none;
      cursor: pointer;
      transition: background 0.2s ease;
      flex-shrink: 0;
      outline: none;
    }
    .toggle-slider {
      position: absolute;
      top: 3px;
      left: 3px;
      width: 22px;
      height: 22px;
      background: #fafafa;
      border-radius: 50%;
      transition: transform 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .toggle-btn.active {
      background: var(--success);
    }
    .toggle-btn.active .toggle-slider {
      transform: translateX(22px);
    }
    .toggle-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    /* Sensor Pills */
    .sensor-readings { display: flex; gap: 8px; }
    .sensor-pill {
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-sm);
      padding: 6px 10px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pill-label {
      font-size: 9px;
      font-weight: 700;
      color: var(--text-dim);
      text-transform: uppercase;
      font-family: var(--font-mono);
    }
    .pill-val {
      font-family: var(--font-mono);
      font-size: 13px;
      font-weight: 700;
      color: var(--text);
    }
    .pill-unit { font-size: 10px; color: var(--text-dim); }

    /* Tank Bar */
    .tank-header { display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 6px; }
    .tank-bar-container {
      width: 100%;
      height: 8px;
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      border-radius: 4px;
      overflow: hidden;
    }
    .tank-bar-fill {
      height: 100%;
      background: var(--text);
      border-radius: 4px;
      transition: width 0.4s ease;
    }

    /* Alert Banner */
    .alert-banner {
      background: var(--warning-subtle);
      border: 1px solid var(--warning-border);
      color: #fde68a;
      padding: 12px 16px;
      border-radius: var(--radius-sm);
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      gap: 12px;
    }

    /* Tables & Inputs */
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--card-border); }
    th { color: var(--text-dim); font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-family: var(--font-mono); }
    
    input, select {
      background: var(--input-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: var(--radius-sm);
      width: 100%;
      font-size: 12px;
      font-family: inherit;
      margin: 4px 0 12px 0;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus, select:focus {
      border-color: var(--card-border-focus);
    }
    label { font-size: 11px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
    .checkbox-line { display: flex; align-items: center; gap: 8px; margin: 8px 0 12px 0; }
    input[type="checkbox"] {
      appearance: none;
      -webkit-appearance: none;
      width: 18px;
      height: 18px;
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      border-radius: 4px;
      cursor: pointer;
      display: inline-grid;
      place-content: center;
      transition: background 0.15s, border-color 0.15s;
      vertical-align: middle;
      flex-shrink: 0;
      margin: 0;
    }
    input[type="checkbox"]:hover {
      border-color: #52525b;
    }
    input[type="checkbox"]:checked {
      background: var(--success);
      border-color: var(--success);
    }
    input[type="checkbox"]:checked::before {
      content: "";
      width: 9px;
      height: 5px;
      border-left: 2px solid #000;
      border-bottom: 2px solid #000;
      transform: rotate(-45deg) translate(1px, -1px);
    }
    .checkbox-line { display: flex; align-items: center; gap: 10px; margin: 8px 0 12px 0; font-size: 13px; font-weight: 500; cursor: pointer; }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 16px;
    }
    .modal {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-md);
      width: 100%;
      max-width: 420px;
      padding: 20px;
    }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }

    /* Hardware Supervisor Login Screen */
    .login-container {
      min-height: 80vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .login-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-md);
      width: 100%;
      max-width: 400px;
      padding: 24px;
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 10px 16px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      transform: translateY(100px);
      opacity: 0;
      transition: 0.25s;
      z-index: 200;
    }
    #toast.show { transform: translateY(0); opacity: 1; }
    #toast.success { border-color: var(--success-border); color: #6ee7b7; }
    #toast.error { border-color: var(--danger-border); color: #fca5a5; }
  </style>
</head>
<body>

  <!-- 1. LOGIN SCREEN -->
  <div id="loginView" class="login-container">
    <div class="login-card">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:16px;">
        <div class="brand-badge">
          <svg class="icon" style="width:18px; height:18px;" viewBox="0 0 24 24">
            <rect x="4" y="4" width="16" height="16" rx="2"/>
            <rect x="9" y="9" width="6" height="6"/>
            <line x1="9" y1="1" x2="9" y2="4"/>
            <line x1="15" y1="1" x2="15" y2="4"/>
          </svg>
        </div>
        <div>
          <div style="font-size:15px; font-weight:700;">Mini-HA Supervisor</div>
          <div style="font-size:10px; font-weight:600; text-transform:uppercase; color:var(--text-dim); font-family:var(--font-mono);">Hardware Console</div>
        </div>
      </div>

      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:18px;">
        Sign in to manage RS-422 bus nodes, wireless star-mesh slaves, and cloud bridge routing.
      </div>

      <form onsubmit="handleLogin(event)">
        <label>Username</label>
        <input type="text" id="loginUser" required autocomplete="username" autofocus placeholder="admin">

        <label>Password</label>
        <div style="position:relative; display:flex; align-items:center;">
          <input type="password" id="loginPass" required autocomplete="current-password" placeholder="Password">
          <button type="button" onclick="togglePassVisibilityLocal()" style="position:absolute; right:10px; top:8px; background:none; border:none; color:var(--text-dim); cursor:pointer;">
            <svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>

        <button type="submit" class="btn" style="width:100%; margin-top:6px;">Sign In</button>
      </form>

      <div style="margin-top:18px; padding-top:12px; border-top:1px solid var(--card-border-subtle); display:flex; justify-content:space-between; align-items:center; font-size:10px; color:var(--text-dim); font-family:var(--font-mono);">
        <span>miniha.local</span>
        <span>v2.4</span>
      </div>
    </div>
  </div>

  <!-- 2. MAIN HUB INTERFACE -->
  <div id="hubView" style="display:none;">
    <!-- Topbar Navigation -->
    <div class="topbar">
      <div class="brand">
        <div class="brand-badge">
          <svg class="icon" style="width:16px; height:16px;" viewBox="0 0 24 24">
            <rect x="4" y="4" width="16" height="16" rx="2"/>
            <rect x="9" y="9" width="6" height="6"/>
          </svg>
        </div>
        <div class="brand-title-wrap">
          <span class="brand-title">MINI-HA</span>
          <span class="brand-subtitle">LOCAL HUB</span>
        </div>
      </div>
      <div class="nav-actions">
        <span class="badge" id="roleBadge">ROLE</span>
        <button class="btn btn-secondary btn-sm" onclick="showTab('nodes')">Overview</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('rules')">Rules</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('users')">Users</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('settings')">Settings</button>
        <button class="btn btn-secondary btn-sm" onclick="showTab('account')">Account</button>
        <button class="btn btn-secondary btn-sm" onclick="handleLogout()">Sign Out</button>
      </div>
    </div>

    <div class="app-container">
      <!-- Default Password Warning Banner -->
      <div id="defaultPassBanner" class="alert-banner" style="display:none;">
        <div>
          <strong>Security Notice:</strong> Using factory default credentials (<code>admin / admin123</code>). Change password immediately.
        </div>
        <button class="btn btn-sm" onclick="openPassModal()">Change Password</button>
      </div>

      <!-- TAB 1: OVERVIEW & ENTITIES -->
      <div id="tabNodes">
        <div class="card">
          <div class="card-title">Live Hardware Nodes & Actuators</div>
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
            <span>Automation Rules & Notifications</span>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-secondary btn-sm" onclick="addNewRule()">+ Add Rule</button>
              <button class="btn btn-sm" onclick="saveRulesConfig()">Save Rules</button>
            </div>
          </div>
          <div id="rulesList"><div style="color:var(--text-muted);">Loading rules...</div></div>
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
            Connects to your free EMQX Serverless broker (Port 8883 TLS). Allows PWA remote access with automatic LAN fallback.
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


      <!-- TAB 4: ACCOUNT PROFILE & HARDWARE DIAGNOSTICS -->
      <div id="tabAccount" style="display:none;">
        <div class="card">
          <div class="card-title">
            <span>User Identity & Security</span>
            <span class="badge" id="accountRoleBadge" style="background:var(--success); color:#000;">ADMIN</span>
          </div>
          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-bottom:16px;">
            <div class="node-box">
              <label>Current Username</label>
              <div style="font-size:15px; font-weight:700; margin-top:4px;" id="accountUserDisplay">admin</div>
            </div>
            <div class="node-box">
              <label>Authorization & Scope</label>
              <div style="font-size:13px; font-weight:600; margin-top:4px; color:var(--success);">Permanent Session (No Expiry)</div>
            </div>
          </div>
          <div class="node-box">
            <strong style="display:block; margin-bottom:10px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim);">Update Password</strong>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:12px;">
              <div>
                <label>New Password</label>
                <input type="password" id="accountNewPass" placeholder="Enter new password">
              </div>
              <div>
                <label>Confirm Password</label>
                <input type="password" id="accountConfirmPass" placeholder="Confirm new password">
              </div>
            </div>
            <button class="btn btn-sm" onclick="submitAccountPassChange()">Update Password</button>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>Master Hub Hardware & Star Ports Diagnostics</span>
            <span style="font-size:11px; color:var(--text-dim); font-family:monospace;" id="diagUptime">Uptime: --</span>
          </div>
          <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px;">
            <div class="node-box">
              <label>Processor</label>
              <div style="font-size:13px; font-weight:700; margin-top:4px;" id="diagCpu">ESP32 Dual-Core @ 240MHz</div>
            </div>
            <div class="node-box">
              <label>RAM (Free Heap)</label>
              <div style="font-size:13px; font-weight:700; margin-top:4px; color:var(--success);" id="diagHeap">--</div>
            </div>
            <div class="node-box">
              <label>Storage (LittleFS)</label>
              <div style="font-size:13px; font-weight:700; margin-top:4px;" id="diagStorage">--</div>
            </div>
            <div class="node-box">
              <label>Star Port 1</label>
              <div style="font-size:12px; font-weight:600; margin-top:4px; color:var(--text-dim);" id="diagPort1">D4/D5 (UART1 Full-Duplex)</div>
            </div>
            <div class="node-box">
              <label>Star Port 2</label>
              <div style="font-size:12px; font-weight:600; margin-top:4px; color:var(--text-dim);" id="diagPort2">D16/D17 (UART2 Full-Duplex)</div>
            </div>
            <div class="node-box">
              <label>Local AP Gateway</label>
              <div style="font-size:13px; font-weight:700; margin-top:4px; font-family:monospace;">192.168.4.1</div>
            </div>
          </div>
        </div>
      </div>

  <!-- MODAL: CHANGE PASSWORD -->
  <div id="passModal" class="modal-overlay">
    <div class="modal">
      <div style="font-size:14px; font-weight:700; margin-bottom:12px;" id="passModalTitle">Change Password</div>
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
      <div style="font-size:14px; font-weight:700; margin-bottom:12px;">Add User Account</div>
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
      <div style="font-size:14px; font-weight:700; margin-bottom:12px;">Bind Mesh Slave</div>
      <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px; font-family:var(--font-mono);" id="bindMacLabel">MAC: --</div>
      <label>Assign Node ID</label>
      <input type="text" id="bindNodeId" value="N01" required>
      <label>Friendly Name</label>
      <input type="text" id="bindNodeName" placeholder="e.g. Living Room, Tank" required>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('bindModal')">Cancel</button>
        <button class="btn btn-sm" onclick="submitBindNode()">Bind Node</button>
      </div>
    </div>
  </div>

  <!-- Toast Element -->
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

    function togglePassVisibilityLocal() {
      const p = document.getElementById('loginPass');
      if (p) p.type = (p.type === 'password') ? 'text' : 'password';
    }

    function showTab(tab) {
      document.getElementById('tabNodes').style.display = (tab === 'nodes') ? 'block' : 'none';
      document.getElementById('tabRules').style.display = (tab === 'rules') ? 'block' : 'none';
      document.getElementById('tabUsers').style.display = (tab === 'users') ? 'block' : 'none';
      document.getElementById('tabSettings').style.display = (tab === 'settings') ? 'block' : 'none';
      const tabAcc = document.getElementById('tabAccount');
      if (tabAcc) tabAcc.style.display = (tab === 'account') ? 'block' : 'none';
      if (tab === 'account') loadAccountDiagnostics();
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
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
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
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
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
              <strong style="font-size:13px;">${node.name || node.id}</strong>
              <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim); margin-left:6px;">(${node.id})</span>
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
                  <span class="toggle-slider"></span>
                </button>
              </div>`;
            } else if (slot.type === 6 || slot.type === 7) { // DHT
              html += `<div class="slot-row">
                <span style="font-weight:600;">${slotName}</span>
                <div class="sensor-readings">
                  <div class="sensor-pill">
                    <span class="pill-label">TEMP</span>
                    <span class="pill-val">${state.temp.toFixed(1)}</span>
                    <span class="pill-unit">&deg;C</span>
                  </div>
                  <div class="sensor-pill">
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
                    <span style="font-weight:600;">${slotName}</span>
                    <span style="font-family:var(--font-mono); font-size:11px; font-weight:700;">${distText} (${pct}%)</span>
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
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
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

    let currentRules = [];

    async function loadRules() {
      try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        currentRules = data.rules || [];
        renderRules();
      } catch (e) {
        console.error(e);
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
      }
    }

    function renderRules() {
      const container = document.getElementById('rulesList');
      if (!container) return;
      if (currentRules.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding:30px 10px; text-align:center;">No automation rules configured yet. Click <strong>+ Add Rule</strong> above to create event-driven automations.</div>';
        return;
      }

      let html = '';
      currentRules.forEach((rule, idx) => {
        const isEnabled = rule.enabled ? 'checked' : '';
        const isNotify = rule.notify ? 'checked' : '';
        const nTitle = rule.notify_title || rule.name || '';
        const nMsg = rule.notify_msg || 'Automation alert triggered!';
        const cond = (rule.conditions && rule.conditions[0]) ? rule.conditions[0] : { node: 'N01', key: 'LVL', op: '>=', val: 100 };
        const act = (rule.actions && rule.actions[0]) ? rule.actions[0] : { target: 'LOCAL', slot: 1, val: 1 };

        html += `<div class="node-box" style="margin-bottom:14px; border: 1px solid var(--card-border);">
          <div class="node-header" style="display:flex; justify-content:space-between; align-items:center;">
            <input type="text" id="ruleName_${idx}" value="${rule.name || ('Rule #' + (idx + 1))}" style="font-weight:700; font-size:13px; max-width:280px; margin:0; padding:4px 8px;" placeholder="Rule Name">
            <div style="display:flex; align-items:center; gap:12px;">
              <label class="checkbox-line" style="margin:0;">
                <input type="checkbox" id="ruleEn_${idx}" ${isEnabled}>
                <span>Enabled</span>
              </label>
              <button class="btn btn-danger btn-sm" onclick="deleteRule(${idx})" style="padding:4px 8px; font-size:11px;">Delete</button>
            </div>
          </div>

          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-top:10px;">
            <div style="background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px;">
              <div style="font-size:10px; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:6px;">Condition (When)</div>
              <div style="display:flex; gap:6px; flex-wrap:wrap;">
                <input type="text" id="ruleCondNode_${idx}" value="${cond.node || 'N01'}" style="width:70px; margin:0;" placeholder="Node">
                <input type="text" id="ruleCondKey_${idx}" value="${cond.key || 'LVL'}" style="width:75px; margin:0;" placeholder="Key (e.g. LVL)">
                <select id="ruleCondOp_${idx}" style="width:65px; margin:0;">
                  <option value=">=" ${cond.op === '>=' ? 'selected' : ''}>&gt;=</option>
                  <option value="<=" ${cond.op === '<=' ? 'selected' : ''}>&lt;=</option>
                  <option value="==" ${cond.op === '==' ? 'selected' : ''}>==</option>
                  <option value=">" ${cond.op === '>' ? 'selected' : ''}>&gt;</option>
                  <option value="<" ${cond.op === '<' ? 'selected' : ''}>&lt;</option>
                  <option value="!=" ${cond.op === '!=' ? 'selected' : ''}>!=</option>
                </select>
                <input type="number" id="ruleCondVal_${idx}" value="${cond.val !== undefined ? cond.val : 100}" style="width:70px; margin:0;" placeholder="Val">
              </div>
            </div>

            <div style="background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px;">
              <div style="font-size:10px; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:6px;">Action (Then)</div>
              <div style="display:flex; gap:6px; flex-wrap:wrap;">
                <input type="text" id="ruleActTarget_${idx}" value="${act.target || 'LOCAL'}" style="width:80px; margin:0;" placeholder="Target">
                <input type="number" id="ruleActSlot_${idx}" value="${act.slot || 1}" style="width:60px; margin:0;" placeholder="Slot">
                <select id="ruleActVal_${idx}" style="width:110px; margin:0;">
                  <option value="1" ${act.val === 1 ? 'selected' : ''}>Turn ON</option>
                  <option value="0" ${act.val === 0 ? 'selected' : ''}>Turn OFF</option>
                </select>
              </div>
            </div>
          </div>

          <div style="background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px; margin-top:10px;">
            <label class="checkbox-line" style="margin:0 0 8px 0;">
              <input type="checkbox" id="ruleNotif_${idx}" ${isNotify}>
              <span style="font-weight:700;">Send Rule-Based Push Notification Alert</span>
            </label>
            <div style="display:grid; grid-template-columns: 1fr 2fr; gap:10px;">
              <div>
                <label>Alert Title</label>
                <input type="text" id="ruleTitle_${idx}" value="${nTitle}" style="margin:4px 0 0;" placeholder="e.g. Tank Full Alert">
              </div>
              <div>
                <label>Alert Message</label>
                <input type="text" id="ruleMsg_${idx}" value="${nMsg}" style="margin:4px 0 0;" placeholder="e.g. Overhead tank is at 100%">
              </div>
            </div>
          </div>
        </div>`;
      });
      container.innerHTML = html;
    }

    function addNewRule() {
      currentRules.push({
        name: "Automation Rule #" + (currentRules.length + 1),
        enabled: true,
        conditions: [{ node: "N01", key: "LVL", op: ">=", val: 100 }],
        actions: [{ target: "LOCAL", slot: 1, val: 1, reason: "Rule Triggered" }],
        notify: true,
        notify_title: "Automation Alert",
        notify_msg: "Automation rule condition reached"
      });
      renderRules();
    }

    function deleteRule(idx) {
      currentRules.splice(idx, 1);
      renderRules();
    }

    async function saveRulesConfig() {
      currentRules.forEach((rule, idx) => {
        const nameEl = document.getElementById('ruleName_' + idx);
        const enEl = document.getElementById('ruleEn_' + idx);
        const notifEl = document.getElementById('ruleNotif_' + idx);
        const titleEl = document.getElementById('ruleTitle_' + idx);
        const msgEl = document.getElementById('ruleMsg_' + idx);
        const cNode = document.getElementById('ruleCondNode_' + idx);
        const cKey = document.getElementById('ruleCondKey_' + idx);
        const cOp = document.getElementById('ruleCondOp_' + idx);
        const cVal = document.getElementById('ruleCondVal_' + idx);
        const aTgt = document.getElementById('ruleActTarget_' + idx);
        const aSlot = document.getElementById('ruleActSlot_' + idx);
        const aVal = document.getElementById('ruleActVal_' + idx);

        if (nameEl) rule.name = nameEl.value.trim();
        if (enEl) rule.enabled = enEl.checked;
        if (notifEl) rule.notify = notifEl.checked;
        if (titleEl) rule.notify_title = titleEl.value.trim();
        if (msgEl) rule.notify_msg = msgEl.value.trim();

        rule.conditions = [{
          node: cNode ? cNode.value.trim() : 'N01',
          key: cKey ? cKey.value.trim() : 'LVL',
          op: cOp ? cOp.value : '>=',
          val: cVal ? parseFloat(cVal.value) : 0
        }];

        rule.actions = [{
          target: aTgt ? aTgt.value.trim() : 'LOCAL',
          slot: aSlot ? parseInt(aSlot.value) : 1,
          val: aVal ? parseInt(aVal.value) : 1,
          reason: rule.name
        }];
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

    async function loadAccountDiagnostics() {
      try {
        const u = localStorage.getItem('miniha_user') || 'admin';
        const r = localStorage.getItem('miniha_role') || 'ADMIN';
        document.getElementById('accountUserDisplay').textContent = u;
        document.getElementById('accountRoleBadge').textContent = r.toUpperCase();

        const res = await fetch('/api/system');
        const d = await res.json();
        if (d.chip_model) document.getElementById('diagCpu').textContent = d.chip_model + ' @ ' + (d.cpu_freq || 240) + 'MHz';
        if (d.free_heap) {
          const freeKb = Math.round(d.free_heap / 1024);
          const totalKb = Math.round((d.total_heap || d.free_heap) / 1024);
          document.getElementById('diagHeap').textContent = freeKb + ' KB Free / ' + totalKb + ' KB';
        }
        if (d.littlefs_total) {
          const usedKb = Math.round((d.littlefs_used || 0) / 1024);
          const totKb = Math.round(d.littlefs_total / 1024);
          document.getElementById('diagStorage').textContent = usedKb + ' KB / ' + totKb + ' KB';
        }
        if (d.uptime_sec !== undefined) {
          const sec = d.uptime_sec;
          const h = Math.floor(sec / 3600);
          const m = Math.floor((sec % 3600) / 60);
          const s = sec % 60;
          document.getElementById('diagUptime').textContent = 'Uptime: ' + h + 'h ' + m + 'm ' + s + 's';
        }
      } catch (e) {
        console.error(e);
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
      }
    }

    async function submitAccountPassChange() {
      const p1 = document.getElementById('accountNewPass').value;
      const p2 = document.getElementById('accountConfirmPass').value;
      if (!p1 || p1 !== p2) {
        showToast('Passwords do not match or empty', 'error');
        return;
      }
      const u = localStorage.getItem('miniha_user') || 'admin';
      const r = localStorage.getItem('miniha_role') || 'admin';
      const res = await fetch('/api/users/edit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: u, pass: p1, role: r })
      });
      if (res.ok) {
        showToast('Password updated successfully!', 'success');
        document.getElementById('accountNewPass').value = '';
        document.getElementById('accountConfirmPass').value = '';
      } else {
        showToast('Password change failed', 'error');
      }
    }

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
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubView').style.display = 'none';
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

    checkSession();
    setInterval(refreshData, 3000);
  </script>
</body>
</html>
)rawliteral";
    webServer.send(200, "text/html; charset=utf-8", html);
  });
}
