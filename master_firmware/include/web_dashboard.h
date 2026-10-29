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
void triggerProvisionNode(const String& mac, const String& newId, const String& name, bool apEnabled = false, const String& apSsid = "", const String& apPass = "");

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
extern bool mqttSchemaNeedsPublish;

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
    DynamicJsonDocument doc(4096);
    JsonArray arr = doc.createNestedArray("nodes");
    for (uint8_t i = 0; i < numTrackedNodes; i++) {
      JsonObject n = arr.createNestedObject();
      n["id"] = nodeStates[i].nodeId;
      n["dist"] = nodeStates[i].distance;
      n["temp"] = nodeStates[i].temp;
      n["hum"] = nodeStates[i].hum;
      n["lastSeen"] = (millis() - nodeStates[i].lastSeen) / 1000;
      JsonArray relays = n.createNestedArray("relays");
      for (int s = 0; s < MAX_COMPONENTS; s++) {
        relays.add(nodeStates[i].relayStates[s] ? 1 : 0);
      }
      JsonArray slotVals = n.createNestedArray("slotVals");
      JsonArray slotSec = n.createNestedArray("slotSec");
      for (int s = 0; s < MAX_COMPONENTS; s++) {
        slotVals.add(nodeStates[i].slotValues[s]);
        slotSec.add(nodeStates[i].slotSecondary[s]);
      }
      JsonObject compsObj = n.createNestedObject("components");
      for (uint8_t c = 0; c < nodeStates[i].numComps; c++) {
        JsonObject co = compsObj.createNestedObject(nodeStates[i].compKeys[c]);
        co["v1"] = nodeStates[i].compVal1[c];
        co["v2"] = nodeStates[i].compVal2[c];
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
    int val = doc["val"].as<int>();
    if (doc.containsKey("comp")) {
      String comp = doc["comp"].as<String>();
      executeAction(target, comp, val, "Web UI Control");
      GenericNodeTelemetry* ns = getOrCreateNodeState(target);
      if (ns) ns->setComponentData(comp, val);
    } else {
      int slot = doc["slot"].as<int>();
      executeAction(target, slot, val, "Web UI Control");
      GenericNodeTelemetry* ns = getOrCreateNodeState(target);
      if (ns && slot >= 0 && slot < MAX_COMPONENTS) {
        ns->relayStates[slot] = (val == 1);
      }
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
    bool apEn = doc.containsKey("ap_enabled") ? doc["ap_enabled"].as<bool>() : false;
    String apSsid = doc.containsKey("ap_ssid") ? doc["ap_ssid"].as<String>() : ("MiniHA_" + newId);
    String apPass = doc.containsKey("ap_pass") ? doc["ap_pass"].as<String>() : "";
    triggerProvisionNode(mac, newId, name, apEn, apSsid, apPass);
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Provisioning triggered\"}");
  });

  // 14f. Configure Downstream Wi-Fi SoftAP Bridge API
  webServer.on("/api/nodes/ap", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(512);
    deserializeJson(doc, webServer.arg("plain"));
    String targetId = doc["id"].as<String>();
    bool apEn = doc["ap_enabled"].as<bool>();
    String apSsid = doc.containsKey("ap_ssid") ? doc["ap_ssid"].as<String>() : ("MiniHA_" + targetId);
    String apPass = doc.containsKey("ap_pass") ? doc["ap_pass"].as<String>() : "";

    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    DynamicJsonDocument nodesDoc(4096);
    if (f) {
      deserializeJson(nodesDoc, f);
      f.close();
    }
    JsonArray nodes = nodesDoc["nodes"].as<JsonArray>();
    bool nodeFound = false;
    for (JsonObject node : nodes) {
      if (node["id"].as<String>() == targetId) {
        nodeFound = true;
        node["ap_enabled"] = apEn;
        node["ap_ssid"] = apSsid;
        node["ap_pass"] = apPass;
        break;
      }
    }
    if (!nodeFound) {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"Node not found\"}");
      return;
    }
    File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(nodesDoc, outF);
      outF.close();
    }

    extern void broadcastBusPacket(const String& pkt);
    String p = "AP:" + String(apEn ? 1 : 0) + ":" + apSsid + ":" + apPass;
    broadcastBusPacket(buildPacket(targetId, "M", "CFG", p));

    mqttSchemaNeedsPublish = true;
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"AP bridge configuration saved and dispatched\"}");
  });

  // 14b. Configure & Dispatch Node GPIO Slots API
  webServer.on("/api/nodes/slots", HTTP_POST, []() {
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

    String targetId = doc["id"].as<String>();
    JsonArray newSlots = doc["slots"].as<JsonArray>();

    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    DynamicJsonDocument nodesDoc(4096);
    if (f) {
      deserializeJson(nodesDoc, f);
      f.close();
    }

    JsonArray nodes = nodesDoc["nodes"].as<JsonArray>();
    bool nodeFound = false;
    for (JsonObject node : nodes) {
      if (node["id"].as<String>() == targetId) {
        nodeFound = true;
        node["slots"] = newSlots;
        break;
      }
    }

    if (!nodeFound) {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"Node not found\"}");
      return;
    }

    File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(nodesDoc, outF);
      outF.close();
    }

    // Dispatch hardware configuration packets over bus to the slave
    extern void broadcastBusPacket(const String& pkt);
    for (JsonObject slot : newSlots) {
      delay(30);
      String p = "SLOT:" + String(slot["slot"].as<int>()) +
                 ":GPIO:" + String(slot["gpio"].as<int>()) +
                 ":TYPE:" + String(slot["type"].as<int>()) +
                 ":INV:" + String(slot["activeLow"].as<int>());
      broadcastBusPacket(buildPacket(targetId, "M", "CFG", p));
    }

    mqttSchemaNeedsPublish = true;
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Slots saved and dispatched\"}");
  });

  // 14b-2. Configure & Dispatch Node Components API (Decoupled Peripheral Schema)
  webServer.on("/api/nodes/components", HTTP_POST, []() {
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

    String targetId = doc["id"].as<String>();
    JsonArray newComponents = doc["components"].as<JsonArray>();

    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    DynamicJsonDocument nodesDoc(4096);
    if (f) {
      deserializeJson(nodesDoc, f);
      f.close();
    }

    JsonArray nodes = nodesDoc["nodes"].as<JsonArray>();
    bool nodeFound = false;
    for (JsonObject node : nodes) {
      if (node["id"].as<String>() == targetId) {
        nodeFound = true;
        node["components"] = newComponents;
        break;
      }
    }

    if (!nodeFound) {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"Node not found\"}");
      return;
    }

    File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(nodesDoc, outF);
      outF.close();
    }

    // Dispatch hardware component packets over bus to the slave:
    // CFG:COMP:<idx>:<type>:<pin1>:<pin2>:<flags>:<param1>:<id>
    extern void broadcastBusPacket(const String& pkt);
    int idx = 0;
    for (JsonObject comp : newComponents) {
      if (idx >= MAX_COMPONENTS) break;
      delay(30);
      int type = comp["type"].as<int>();
      int pin1 = comp.containsKey("pin1") ? comp["pin1"].as<int>() : 255;
      int pin2 = comp.containsKey("pin2") ? comp["pin2"].as<int>() : 255;
      int flags = comp.containsKey("flags") ? comp["flags"].as<int>() : (comp.containsKey("activeLow") && comp["activeLow"].as<int>() ? 1 : 0);
      int param1 = comp.containsKey("param1") ? comp["param1"].as<int>() : 0;
      String compId = comp.containsKey("id") ? comp["id"].as<String>() : ("c" + String(idx));
      String p = "COMP:" + String(idx) + ":" + String(type) + ":" + String(pin1) + ":" + String(pin2) + ":" + String(flags) + ":" + String(param1) + ":" + compId;
      broadcastBusPacket(buildPacket(targetId, "M", "CFG", p));
      idx++;
    }

    mqttSchemaNeedsPublish = true;
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Components saved and dispatched\"}");
  });

  // 14d. Configure & Dispatch Node Standalone Schedules API (Downtime-Safe)
  webServer.on("/api/nodes/schedules", HTTP_POST, []() {
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

    String targetId = doc["id"].as<String>();
    JsonArray scheds = doc["schedules"].as<JsonArray>();

    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    DynamicJsonDocument nodesDoc(4096);
    if (f) {
      deserializeJson(nodesDoc, f);
      f.close();
    }

    JsonArray nodes = nodesDoc["nodes"].as<JsonArray>();
    bool nodeFound = false;
    for (JsonObject node : nodes) {
      if (node["id"].as<String>() == targetId) {
        nodeFound = true;
        node["schedules"] = scheds;
        break;
      }
    }

    if (!nodeFound) {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"Node not found\"}");
      return;
    }

    File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
    if (outF) {
      serializeJson(nodesDoc, outF);
      outF.close();
    }

    // Push each schedule over the wire directly into slave EEPROM
    extern void broadcastBusPacket(const String& pkt);
    for (size_t sIdx = 0; sIdx < scheds.size() && sIdx < 8; sIdx++) {
      JsonObject s = scheds[sIdx];
      delay(30);
      uint16_t mask = 0;
      if (s.containsKey("targetSlots") && s["targetSlots"].is<JsonArray>()) {
        for (int slotId : s["targetSlots"].as<JsonArray>()) {
          if (slotId >= 0 && slotId < 16) mask |= (1 << slotId);
        }
      } else if (s.containsKey("targetSlotsMask")) {
        mask = s["targetSlotsMask"].as<uint16_t>();
      } else if (s.containsKey("targetSlot")) {
        int ts = s["targetSlot"].as<int>();
        if (ts >= 0 && ts < 16) mask = (1 << ts);
      }

      String p = "SCHED:" + String(sIdx) +
                 ":" + String(s["enabled"].as<int>()) +
                 ":" + String(mask) +
                 ":" + String(s["action"].as<int>()) +
                 ":" + String(s["onHour"].as<int>()) +
                 ":" + String(s["onMinute"].as<int>()) +
                 ":" + String(s["offHour"].as<int>()) +
                 ":" + String(s["offMinute"].as<int>());
      broadcastBusPacket(buildPacket(targetId, "M", "CFG", p));
    }

    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Schedules pushed to slave EEPROM\"}");
  });

  // 14e. Time Sync API (Sync real-world clock from browser/phone even when offline!)
  webServer.on("/api/time", HTTP_POST, []() {
    if (webServer.hasArg("plain")) {
      uint32_t clientEpoch = webServer.arg("plain").toInt();
      if (clientEpoch > 1700000000) {
        struct timeval tv = { (time_t)clientEpoch, 0 };
        settimeofday(&tv, nullptr);
        extern void broadcastBusPacket(const String& pkt);
        broadcastBusPacket(buildPacket("ALL", "M", "TIME", String(clientEpoch)));
        Serial.printf("[TIME] Synced real-world epoch: %u\n", clientEpoch);
      }
    }
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Time synced\"}");
  });

  // 14c. Delete / Unbind Node API
  webServer.on("/api/nodes/delete", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    if (!webServer.hasArg("plain")) {
      webServer.send(400, "application/json; charset=utf-8", "{\"error\":\"No body\"}");
      return;
    }
    DynamicJsonDocument doc(256);
    deserializeJson(doc, webServer.arg("plain"));
    String targetId = doc["id"].as<String>();

    File f = LittleFS.open(NODES_CONFIG_PATH, "r");
    DynamicJsonDocument nodesDoc(4096);
    if (f) {
      deserializeJson(nodesDoc, f);
      f.close();
    }

    JsonArray nodes = nodesDoc["nodes"].as<JsonArray>();
    int delIdx = -1;
    for (size_t i = 0; i < nodes.size(); i++) {
      if (nodes[i]["id"].as<String>() == targetId) {
        delIdx = i;
        break;
      }
    }

    if (delIdx != -1) {
      nodes.remove(delIdx);
      File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
      if (outF) {
        serializeJson(nodesDoc, outF);
        outF.close();
      }
      mqttSchemaNeedsPublish = true;
      webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"Node deleted\"}");
    } else {
      webServer.send(404, "application/json; charset=utf-8", "{\"error\":\"Node not found\"}");
    }
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

  // 15b. Clear All Rules API
  webServer.on("/api/rules/clear", HTTP_POST, []() {
    if (!requireRole(ROLE_ADMIN)) return;
    File f = LittleFS.open(RULES_CONFIG_PATH, "w");
    if (f) {
      f.print(R"({"rules":[]})");
      f.close();
    }
    reloadRulesCache();
    webServer.send(200, "application/json; charset=utf-8", "{\"status\":\"All rules cleared\"}");
  });

  // 16. OS Network Probes & Offline Handlers (No 302 Redirects, No Spoofing)
  // Respond with standard status codes without redirecting so OS knows it's a local network without internet
  webServer.on("/generate_204", HTTP_GET, []() { webServer.send(204, "text/plain", ""); });
  webServer.on("/gen_204", HTTP_GET, []() { webServer.send(204, "text/plain", ""); });
  webServer.on("/connecttest.txt", HTTP_GET, []() { webServer.send(404, "text/plain", "No Internet"); });
  webServer.on("/ncsi.txt", HTTP_GET, []() { webServer.send(404, "text/plain", "No Internet"); });
  webServer.on("/hotspot-detect.html", HTTP_GET, []() { webServer.send(404, "text/plain", "Not Found"); });

  webServer.onNotFound([]() {
    if (webServer.method() == HTTP_OPTIONS) {
      webServer.sendHeader("Access-Control-Allow-Origin", "*");
      webServer.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD");
      webServer.sendHeader("Access-Control-Allow-Headers", "*");
      webServer.send(204);
      return;
    }
    webServer.send(404, "text/plain", "Not Found");
  });

  // 17. Modern Single Page Application (Dashboard + Login)
  static const char INDEX_HTML[] PROGMEM = R"rawliteral(<!DOCTYPE html>
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

    .admin-only { display: none !important; }
    body.role-admin .admin-only { display: inline-flex !important; }
    body.role-admin div.admin-only, body.role-admin .card.admin-only { display: block !important; }
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
        <span>v0.1.0-beta</span>
      </div>
    </div>
  </div>

  <!-- 2. MAIN HUB INTERFACE -->
  <div id="hubView" style="display:none;">
    <!-- Topbar Navigation -->
    <div class="topbar">
      <div class="brand" style="display:flex; align-items:center;">
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
        <div class="user-identity" style="display:flex; align-items:center; gap:6px; margin-left:14px; padding-left:14px; border-left:1px solid var(--card-border);">
          <svg class="icon" style="width:13px; height:13px; color:var(--text-dim);" viewBox="0 0 24 24"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <span style="font-size:11px; color:var(--text-dim);">User:</span>
          <span class="badge" id="roleBadge" style="margin:0;">ADMIN</span>
        </div>
      </div>
      <div class="nav-actions">
        <button class="btn btn-secondary btn-sm" onclick="showTab('nodes')">Overview</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('rules')">Rules</button>
        <button class="btn btn-secondary btn-sm admin-only" onclick="showTab('schedules')">Schedules</button>
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
          <div class="card-title" style="flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:15px; font-weight:700;">Automation Rules Engine</div>
              <div style="font-size:11px; color:var(--text-muted); font-weight:normal; margin-top:3px;">
                Event-driven logic evaluated locally by Master. When sensor criteria are met, Master triggers target actuators & push alerts.
              </div>
            </div>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-sm" onclick="openAddRuleModal()">+ Add Rule</button>
              <button class="btn btn-secondary btn-sm" onclick="clearAllRules()">Clear All Rules</button>
            </div>
          </div>
          <div id="rulesList"><div style="color:var(--text-muted);">Loading rules...</div></div>
        </div>
      </div>

      <!-- TAB: DOWNTIME-SAFE STANDALONE SCHEDULES (ADMIN ONLY) -->
      <div id="tabSchedules" style="display:none;">
        <div class="card">
          <div class="card-title" style="flex-wrap:wrap; gap:10px;">
            <div>
              <div style="font-size:15px; font-weight:700;">Downtime-Safe Standalone Schedules</div>
              <div style="font-size:11px; color:var(--text-muted); font-weight:normal; margin-top:3px;">
                Schedules run directly inside each slave microcontroller's on-chip EEPROM. If the Master hub is powered off or disconnected, all scheduled lights, pumps, and valves continue operating automatically.
              </div>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              <label style="margin:0; font-size:12px; color:var(--text-muted);">Target Node:</label>
              <select id="schedTabNodeSelect" onchange="onSchedNodeChange()" style="margin:0; padding:6px 10px; width:auto; font-size:12px;"></select>
            </div>
          </div>

          <div id="schedTabList" style="margin-top:14px; display:flex; flex-direction:column; gap:10px;"></div>

          <div style="margin-top:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; border-top:1px solid var(--card-border-subtle); padding-top:14px;">
            <button class="btn btn-secondary btn-sm" onclick="addScheduleToActiveNode()">+ Add Daily Schedule</button>
            <button class="btn btn-sm" onclick="saveActiveNodeSchedules()">Save &amp; Push to Slave EEPROM</button>
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
    <div class="modal" style="max-width:480px; width:95%;">
      <div style="font-size:14px; font-weight:700; margin-bottom:12px;">Bind Mesh Slave</div>
      <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px; font-family:var(--font-mono);" id="bindMacLabel">MAC: --</div>
      <label>Assign Node ID</label>
      <input type="text" id="bindNodeId" value="N01" required>
      <label>Friendly Name</label>
      <input type="text" id="bindNodeName" placeholder="e.g. Living Room, Tank" required>

      <div style="margin:12px 0 8px; padding:10px 12px; background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm);">
        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin:0; font-weight:600; font-size:12px;">
          <input type="checkbox" id="bindApEn" onchange="toggleBindApFields()" style="width:auto; margin:0;">
          <span>Provision as Wi-Fi AP Bridge (Allows wireless slaves to connect)</span>
        </label>
        <div id="bindApFields" style="display:none; margin-top:8px;">
          <label style="font-size:11px; margin:4px 0 2px;">Downstream Wi-Fi SSID</label>
          <input type="text" id="bindApSsid" placeholder="e.g. MiniHA-Repeater-01" style="margin:0 0 6px; padding:6px;">
          <label style="font-size:11px; margin:4px 0 2px;">Wi-Fi Password (leave empty for open)</label>
          <input type="password" id="bindApPass" placeholder="Min 8 characters (or blank for open)" style="margin:0; padding:6px;">
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('bindModal')">Cancel</button>
        <button class="btn btn-sm" onclick="submitBindNode()">Bind Node</button>
      </div>
    </div>
  </div>

  <!-- MODAL: CONFIGURE DOWNSTREAM WI-FI AP BRIDGE -->
  <div id="apModal" class="modal-overlay">
    <div class="modal" style="max-width:480px; width:95%;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="font-size:15px; font-weight:700;" id="apModalTitle">Configure Downstream Wi-Fi AP Bridge</div>
        <button onclick="closeModal('apModal')" style="background:none; border:none; color:var(--text-dim); font-size:18px; cursor:pointer;">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:12px; background:var(--card-elevated); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--card-border);">
        <strong>Wi-Fi Repeater / AP Bridge</strong>: When enabled, this wired slave broadcasts a local Wi-Fi Access Point. Nearby wireless slaves that cannot reach the Master hub directly can connect to this node's Wi-Fi network and communicate seamlessly with the Master over RS-422.
      </div>
      <label style="display:flex; align-items:center; gap:8px; cursor:pointer; margin:8px 0 12px; font-weight:600; font-size:13px;">
        <input type="checkbox" id="apModalEn" onchange="toggleApModalFields()" style="width:auto; margin:0;">
        <span>Enable Downstream SoftAP Bridge</span>
      </label>
      <div id="apModalFields">
        <label>Downstream Wi-Fi SSID</label>
        <input type="text" id="apModalSsid" placeholder="e.g. MiniHA-Repeater-N01">
        <label>Downstream Password</label>
        <input type="password" id="apModalPass" placeholder="Min 8 characters (or leave empty for open)">
      </div>
      <div class="modal-actions" style="margin-top:16px;">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('apModal')">Cancel</button>
        <button class="btn btn-sm" onclick="saveNodeApConfig()">Save &amp; Push to Slave</button>
      </div>
    </div>
  </div>

  <!-- MODAL: CONFIGURE PERIPHERAL HARDWARE COMPONENTS -->
  <div id="componentModal" class="modal-overlay">
    <div class="modal" style="max-width:700px; width:95%;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="font-size:15px; font-weight:700;" id="compModalTitle">Configure Peripheral Components</div>
        <button onclick="closeModal('componentModal')" style="background:none; border:none; color:var(--text-dim); font-size:18px; cursor:pointer;">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:12px; background:var(--card-elevated); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--card-border);">
        <strong>Peripheral Hardware Components</strong>: Map real physical devices (Relays, Ultrasonic sensors, DHT temperature/humidity sensors, buttons, ADC) to MCU pins. Each peripheral driver runs locally in silicon and generates friendly named metrics.
      </div>
      <div style="font-size:11px; color:var(--text-dim); margin-bottom:8px;" id="compSafeHint">Safe GPIO Pins: --</div>
      <div id="componentsList" style="max-height:340px; overflow-y:auto; margin-bottom:14px; display:flex; flex-direction:column; gap:10px;"></div>
      <button class="btn btn-secondary btn-sm" onclick="addComponentRow()" style="margin-bottom:14px;">+ Add Peripheral Component</button>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('componentModal')">Cancel</button>
        <button class="btn btn-sm" onclick="saveComponents()">Save & Push to Node</button>
      </div>
    </div>
  </div>

  <!-- MODAL: CONFIGURE HARDWARE GPIO SLOTS (LEGACY COMPAT) -->
  <div id="gpioModal" class="modal-overlay">
    <div class="modal" style="max-width:640px; width:95%;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="font-size:15px; font-weight:700;" id="gpioModalTitle">Configure Hardware GPIOs</div>
        <button onclick="closeModal('gpioModal')" style="background:none; border:none; color:var(--text-dim); font-size:18px; cursor:pointer;">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:12px; background:var(--card-elevated); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--card-border);">
        <strong>Hardware GPIO Mapping</strong>: Assign the physical pins on this slave board to relays, switches, or sensors. When saved, these pin settings are pushed over the wire and committed directly into the slave's EEPROM.
      </div>
      <div style="font-size:11px; color:var(--text-dim); margin-bottom:8px;" id="gpioSafeHint">Safe GPIO Pins: --</div>
      <div id="gpioSlotsList" style="max-height:280px; overflow-y:auto; margin-bottom:14px; display:flex; flex-direction:column; gap:8px;"></div>
      <button class="btn btn-secondary btn-sm" onclick="addGpioSlotRow()" style="margin-bottom:14px;">+ Add GPIO Slot</button>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('gpioModal')">Cancel</button>
        <button class="btn btn-sm" onclick="saveGpioSlots()">Save & Push to Node</button>
      </div>
    </div>
  </div>

  <!-- MODAL: AUTOMATION RULE BUILDER -->
  <div id="ruleModal" class="modal-overlay">
    <div class="modal" style="max-width:580px; width:95%;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="font-size:15px; font-weight:700;" id="ruleModalTitle">Add Automation Rule</div>
        <button onclick="closeModal('ruleModal')" style="background:none; border:none; color:var(--text-dim); font-size:18px; cursor:pointer;">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:12px; background:var(--card-elevated); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--card-border);">
        <strong>Automation Rule</strong>: When a sensor meets your condition (e.g. Tank Level &ge; 140cm), Master automatically triggers an action on a target node (e.g. Turn OFF Pump) and optionally sends a push alert.
      </div>

      <label>Rule Name</label>
      <input type="text" id="ruleModalName" placeholder="e.g. Auto Pump Shutoff" required>

      <div style="margin-top:10px; background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px;">
        <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:6px;">Condition (When)</div>
        <div style="display:grid; grid-template-columns: 2fr 1.5fr 1fr 1fr; gap:8px;">
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Source Node</label>
            <select id="ruleModalCondNode" onchange="onRuleCondNodeChange()"></select>
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Sensor / Metric</label>
            <select id="ruleModalCondKey" style="margin:0;"></select>
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Op</label>
            <select id="ruleModalCondOp">
              <option value=">=">&gt;=</option>
              <option value="<=">&lt;=</option>
              <option value="==">==</option>
              <option value=">">&gt;</option>
              <option value="<">&lt;</option>
              <option value="!=">!=</option>
            </select>
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Threshold</label>
            <input type="number" id="ruleModalCondVal" value="100">
          </div>
        </div>
      </div>

      <div style="margin-top:10px; background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px;">
        <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:6px;">Action (Then)</div>
        <div style="display:grid; grid-template-columns: 2fr 1.5fr 1.5fr; gap:8px;">
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Target Node</label>
            <select id="ruleModalActTarget" onchange="onRuleActTargetChange()"></select>
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Actuator Slot</label>
            <select id="ruleModalActSlot" style="margin:0;"></select>
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Command</label>
            <select id="ruleModalActVal">
              <option value="1">Turn ON</option>
              <option value="0">Turn OFF</option>
            </select>
          </div>
        </div>
      </div>

      <div style="margin-top:10px; background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px;">
        <label class="checkbox-line" style="margin:0 0 6px 0;">
          <input type="checkbox" id="ruleModalNotif" checked>
          <span style="font-weight:700; font-size:12px;">Send Rule-Based Push Notification Alert</span>
        </label>
        <div style="display:grid; grid-template-columns: 1fr 2fr; gap:8px;">
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Alert Title</label>
            <input type="text" id="ruleModalTitleText" placeholder="e.g. Tank Full">
          </div>
          <div>
            <label style="margin:0 0 4px; font-size:11px;">Alert Message</label>
            <input type="text" id="ruleModalMsgText" placeholder="e.g. Tank reached 100%">
          </div>
        </div>
      </div>

      <div class="modal-actions" style="margin-top:14px;">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('ruleModal')">Cancel</button>
        <button class="btn btn-sm" onclick="saveRuleFromModal()">Save Rule</button>
      </div>
    </div>
  </div>

  <!-- MODAL: DOWNTIME-SAFE STANDALONE SCHEDULES -->
  <div id="scheduleModal" class="modal-overlay">
    <div class="modal" style="max-width:620px; width:95%;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div style="font-size:15px; font-weight:700;" id="schedModalTitle">Standalone Node Schedules</div>
        <button onclick="closeModal('scheduleModal')" style="background:none; border:none; color:var(--text-dim); font-size:18px; cursor:pointer;">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:12px; background:var(--card-elevated); padding:10px 12px; border-radius:var(--radius-sm); border:1px solid var(--card-border);">
        <strong>Downtime-Safe Silicon Execution</strong>: These schedules are programmed directly into the slave's on-chip EEPROM. The slave executes them on its own internal clock even if the RS-422 bus is severed or the Master hub is powered off.
      </div>
      <div id="schedList" style="max-height:280px; overflow-y:auto; margin-bottom:14px; display:flex; flex-direction:column; gap:8px;"></div>
      <button class="btn btn-secondary btn-sm" onclick="addScheduleRow()" style="margin-bottom:14px;">+ Add Daily Schedule</button>
      <div class="modal-actions">
        <button class="btn btn-secondary btn-sm" onclick="closeModal('scheduleModal')">Cancel</button>
        <button class="btn btn-sm" onclick="saveNodeSchedules()">Save & Push to Slave EEPROM</button>
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
      document.getElementById('tabSchedules').style.display = (tab === 'schedules') ? 'block' : 'none';
      document.getElementById('tabUsers').style.display = (tab === 'users') ? 'block' : 'none';
      document.getElementById('tabSettings').style.display = (tab === 'settings') ? 'block' : 'none';
      const tabAcc = document.getElementById('tabAccount');
      if (tabAcc) tabAcc.style.display = (tab === 'account') ? 'block' : 'none';
      if (tab === 'account') loadAccountDiagnostics();
      if (tab === 'rules') loadRules();
      if (tab === 'schedules') loadSchedulesTab();
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
          if (isAdmin) {
            document.body.classList.add('role-admin');
          } else {
            document.body.classList.remove('role-admin');
          }
          document.querySelectorAll('.admin-only').forEach(el => el.style.display = isAdmin ? '' : 'none');
          document.getElementById('defaultPassBanner').style.display = (isAdmin && data.isDefault) ? 'flex' : 'none';

          // Sync browser real-world time to Master & Slaves (downtime-safe local RTC)
          fetch('/api/time', { method: 'POST', body: String(Math.floor(Date.now() / 1000)) }).catch(()=>{});

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
      const u = document.getElementById('loginUser');
      const p = document.getElementById('loginPass');
      if (u) u.value = '';
      if (p) p.value = '';
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
        c.innerHTML = '<div style="color:var(--text-dim); padding:16px 0; font-size:13px;">No hardware nodes configured yet. Connect a slave node to the RS-422 bus or Wi-Fi to bind it.</div>';
        return;
      }

      let html = '';
      configuredNodes.forEach(node => {
        const state = liveStates[node.id] || { relays: [], dist: -1, temp: 0, hum: 0, components: {}, lastSeen: 999 };
        
        let statusBadge = '<span style="color:var(--text-dim); display:inline-flex; align-items:center; gap:5px; font-size:11px;"><span class="status-dot"></span>Offline</span>';
        if (state.lastSeen <= 10) {
          statusBadge = '<span style="color:var(--success); font-weight:600; display:inline-flex; align-items:center; gap:5px; font-size:11px;"><span class="status-dot online"></span>Online</span>';
        } else if (state.lastSeen <= 60) {
          statusBadge = `<span style="color:var(--warning); display:inline-flex; align-items:center; gap:5px; font-size:11px;"><span class="status-dot warning"></span>${state.lastSeen}s ago</span>`;
        }

        const compCount = (node.components && node.components.length) ? node.components.length : 0;
        const slotCount = (node.slots && node.slots.length) ? node.slots.length : 0;
        const totalItems = compCount > 0 ? compCount : slotCount;

        html += `<div class="node-box" style="margin-bottom:14px;">
          <div class="node-header" style="flex-wrap:wrap; gap:8px;">
            <div>
              <strong style="font-size:14px;">${node.name || node.id}</strong>
              <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim); margin-left:6px;">(${node.id})</span>
            </div>
            <div style="display:flex; align-items:center; gap:10px;">
              ${statusBadge}
              <button class="btn btn-secondary btn-sm admin-only" onclick="openComponentModal('${node.id}')" style="padding:3px 8px; font-size:11px;">Configure Components</button>
              <button class="btn btn-secondary btn-sm admin-only" onclick="openApModal('${node.id}')" style="padding:3px 8px; font-size:11px;">Wi-Fi AP Bridge</button>
              <button class="btn btn-secondary btn-sm admin-only" onclick="openScheduleTabForNode('${node.id}')" style="padding:3px 8px; font-size:11px;">Schedules</button>
              <button class="btn btn-danger btn-sm admin-only" onclick="deleteNode('${node.id}')" style="padding:3px 8px; font-size:11px;">Delete</button>
            </div>
          </div>
          <div style="display:flex; gap:12px; font-size:11px; color:var(--text-dim); font-family:var(--font-mono); margin:4px 0 10px; border-bottom:1px solid var(--card-border-subtle); padding-bottom:6px;">
            <span>MAC: ${node.mac || '--'}</span>
            <span>Chip: ${node.chip || 'ESP32/ESP8266'}</span>
            <span>Peripherals: ${totalItems} active</span>
            <span>AP Bridge: ${node.ap_enabled ? ('<strong style="color:var(--success);">' + (node.ap_ssid || 'Active') + '</strong>') : 'Off'}</span>
          </div>`;

        if (compCount > 0) {
          node.components.forEach((c, idx) => {
            const compId = c.id || ('comp' + idx);
            const compName = c.name || compId;
            const cType = parseInt(c.type) || 1;
            const compState = (state.components && state.components[compId]) ? state.components[compId] : null;

            if (cType === 1) { // Relay Actuator
              let isRelayOn = false;
              if (compState && compState.v1 !== undefined) {
                isRelayOn = (compState.v1 == 1);
              } else if (state.relays && state.relays[idx] !== undefined) {
                isRelayOn = (state.relays[idx] == 1);
              }
              const canControl = (currentSession.role === 'admin' || currentSession.role === 'member');
              html += `<div class="slot-row">
                <span style="font-weight:600;">${compName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(Relay GPIO ${c.pin1}) [${compId}.state]</small></span>
                <button class="toggle-btn ${isRelayOn ? 'active' : ''}" ${canControl ? '' : 'disabled'} onclick="toggleComponent('${node.id}', '${compId}', ${isRelayOn})">
                  <span class="toggle-slider"></span>
                </button>
              </div>`;
            } else if (cType === 4) { // Ultrasonic Sensor (HC-SR04)
              let dist = -1;
              let pct = 0;
              const depth = (c.param1 > 0) ? c.param1 : 200;
              if (compState && compState.v1 !== undefined) {
                dist = compState.v1;
                pct = compState.v2 !== undefined ? compState.v2 : ((dist >= 0) ? Math.max(0, Math.min(100, Math.round(((depth - dist) / depth) * 100))) : 0);
              } else if (state.dist !== undefined) {
                dist = state.dist;
                pct = (dist >= 0) ? Math.max(0, Math.min(100, Math.round(((depth - dist) / depth) * 100))) : 0;
              }
              const distText = dist >= 0 ? `${Math.round(dist)} cm` : '--';
              html += `<div class="slot-row" style="flex-direction:column; align-items:stretch; gap:6px;">
                <div class="tank-header">
                  <span style="font-weight:600;">${compName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(HC-SR04 Trig:${c.pin1} Echo:${c.pin2}) [${compId}.dist]</small></span>
                  <span style="font-family:var(--font-mono); font-size:11px; font-weight:700;">${distText} (${pct}%)</span>
                </div>
                <div class="tank-bar-container"><div class="tank-bar-fill" style="width:${pct}%"></div></div>
              </div>`;
            } else if (cType === 5) { // DHT Sensor
              let curT = 0.0;
              let curH = 0.0;
              if (compState && compState.v1 !== undefined) {
                curT = compState.v1;
                curH = compState.v2 !== undefined ? compState.v2 : 0.0;
              } else {
                curT = state.temp || 0.0;
                curH = state.hum || 0.0;
              }
              html += `<div class="slot-row">
                <span style="font-weight:600;">${compName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(DHT on GPIO ${c.pin1}) [${compId}.temp / .hum]</small></span>
                <div class="sensor-readings">
                  <div class="sensor-pill">
                    <span class="pill-label">TEMP</span>
                    <span class="pill-val">${curT.toFixed(1)}</span>
                    <span class="pill-unit">&deg;C</span>
                  </div>
                  <div class="sensor-pill">
                    <span class="pill-label">HUM</span>
                    <span class="pill-val">${curH.toFixed(0)}</span>
                    <span class="pill-unit">%</span>
                  </div>
                </div>
              </div>`;
            } else if (cType === 2 || cType === 3) { // Wall Switch / Button
              const isInputActive = compState ? (compState.v1 == 1) : false;
              html += `<div class="slot-row">
                <span style="font-weight:600;">${compName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(${cType === 2 ? 'Touch' : 'Button'} GPIO ${c.pin1}) [${compId}.state]</small></span>
                <span class="badge" style="background:${isInputActive ? 'var(--success)' : 'var(--card-elevated)'}; color:${isInputActive ? '#000' : 'var(--text-dim)'}; font-size:10px; font-weight:700;">
                  ${isInputActive ? 'ACTIVE / PRESSED' : 'IDLE / OPEN'}
                </span>
              </div>`;
            } else if (cType === 7) { // ADC Sensor
              const adcVal = compState ? compState.v1 : 0;
              html += `<div class="slot-row">
                <span style="font-weight:600;">${compName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(ADC GPIO ${c.pin1}) [${compId}.raw]</small></span>
                <span style="font-family:var(--font-mono); font-size:12px; font-weight:700;">${adcVal}</span>
              </div>`;
            } else {
              html += `<div class="slot-row"><span style="font-weight:600;">${compName}</span><span style="font-size:11px; color:var(--text-dim);">GPIO ${c.pin1}</span></div>`;
            }
          });
        } else if (slotCount > 0) {
          node.slots.forEach(slot => {
            const slotName = slot.name || `Slot ${slot.slot}`;
            if (slot.type === 1) { // Relay
              const isRelayOn = (state.relays && state.relays[slot.slot] === 1);
              const canControl = (currentSession.role === 'admin' || currentSession.role === 'member');
              html += `<div class="slot-row">
                <span style="font-weight:600;">${slotName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(Relay GPIO ${slot.gpio})</small></span>
                <button class="toggle-btn ${isRelayOn ? 'active' : ''}" ${canControl ? '' : 'disabled'} onclick="toggleRelay('${node.id}', ${slot.slot}, ${isRelayOn})">
                  <span class="toggle-slider"></span>
                </button>
              </div>`;
            } else if (slot.type === 6 || slot.type === 7) { // DHT
              const curT = (state.slotVals && state.slotVals[slot.slot] !== undefined && state.slotVals[slot.slot] > 0) ? state.slotVals[slot.slot] : state.temp;
              const curH = (state.slotSec && state.slotSec[slot.slot] !== undefined && state.slotSec[slot.slot] > 0) ? state.slotSec[slot.slot] : state.hum;
              html += `<div class="slot-row">
                <span style="font-weight:600;">${slotName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(DHT GPIO ${slot.gpio})</small></span>
                <div class="sensor-readings">
                  <div class="sensor-pill">
                    <span class="pill-label">TEMP</span>
                    <span class="pill-val">${curT.toFixed(1)}</span>
                    <span class="pill-unit">&deg;C</span>
                  </div>
                  <div class="sensor-pill">
                    <span class="pill-label">HUM</span>
                    <span class="pill-val">${curH.toFixed(0)}</span>
                    <span class="pill-unit">%</span>
                  </div>
                </div>
              </div>`;
            } else if (slot.type === 4) { // Ultrasonic Trig
              const slotDist = (state.slotVals && state.slotVals[slot.slot] !== undefined && state.slotVals[slot.slot] >= 0) ? state.slotVals[slot.slot] : state.dist;
              const distText = slotDist >= 0 ? `${Math.round(slotDist)} cm` : '--';
              const pct = slotDist >= 0 ? Math.max(0, Math.min(100, Math.round(((200 - slotDist) / 200) * 100))) : 0;
              html += `<div class="slot-row" style="flex-direction:column; align-items:stretch; gap:6px;">
                <div class="tank-header">
                  <span style="font-weight:600;">${slotName} <small style="color:var(--text-dim); font-family:var(--font-mono); font-size:10px;">(Trig GPIO ${slot.gpio})</small></span>
                  <span style="font-family:var(--font-mono); font-size:11px; font-weight:700;">${distText} (${pct}%)</span>
                </div>
                <div class="tank-bar-container"><div class="tank-bar-fill" style="width:${pct}%"></div></div>
              </div>`;
            } else {
              html += `<div class="slot-row"><span style="font-weight:600;">${slotName}</span><span style="font-size:11px; color:var(--text-dim);">GPIO ${slot.gpio} (Active)</span></div>`;
            }
          });
        } else {
          html += '<div style="color:var(--text-dim); font-size:12px; padding:6px 0;">No peripheral components configured yet. Click <strong>Configure Components</strong> above to assign relays, sensors, and inputs.</div>';
        }
        html += `</div>`;
      });
      c.innerHTML = html;
    }

    async function toggleComponent(nodeId, compId, curState) {
      const val = curState ? 0 : 1;
      if (!liveStates[nodeId]) liveStates[nodeId] = { components: {} };
      if (!liveStates[nodeId].components) liveStates[nodeId].components = {};
      liveStates[nodeId].components[compId] = { v1: val, v2: 0 };
      renderEntities();

      await fetch('/api/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: nodeId, comp: compId, val: val })
      });
      setTimeout(refreshData, 300);
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

    // =========================================================================
    // PERIPHERAL HARDWARE COMPONENTS CONFIGURATION (DECOUPLED SCHEMA)
    // =========================================================================
    let activeCompNodeId = null;
    let currentComponents = [];

    function openComponentModal(nodeId) {
      activeCompNodeId = nodeId;
      const node = configuredNodes.find(n => n.id === nodeId);
      if (!node) return;

      document.getElementById('compModalTitle').innerText = `Configure Peripherals: ${node.name || nodeId} (${nodeId})`;
      const pendingMatch = (typeof pendingNodesCache !== 'undefined' ? pendingNodesCache : []).find(p => p.mac === node.mac);
      const safeGpios = (pendingMatch && pendingMatch.gpios) ? pendingMatch.gpios : '0, 1, 3, 4, 5, 6, 7, 8, 10, 20, 21';
      document.getElementById('compSafeHint').innerText = `Safe GPIO Pins on this chip (${node.chip || 'MCU'}): ${safeGpios}`;

      if (node.components && node.components.length > 0) {
        currentComponents = JSON.parse(JSON.stringify(node.components));
      } else if (node.slots && node.slots.length > 0) {
        currentComponents = node.slots.map((s, idx) => {
          let cType = s.type;
          if (cType === 6 || cType === 7) cType = 5;
          return {
            id: s.name ? s.name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) : ('comp' + idx),
            name: s.name || ('Slot ' + s.slot),
            type: cType,
            pin1: s.gpio,
            pin2: 255,
            flags: s.activeLow ? 1 : 0,
            param1: (s.type === 7 ? 22 : 11)
          };
        });
      } else {
        currentComponents = [];
      }

      renderComponentRows();
      document.getElementById('componentModal').style.display = 'flex';
    }

    function openGpioModal(nodeId) {
      openComponentModal(nodeId);
    }

    function renderComponentRows() {
      const list = document.getElementById('componentsList');
      if (currentComponents.length === 0) {
        list.innerHTML = '<div style="color:var(--text-dim); padding:10px; font-size:12px;">No components configured. Click <strong>+ Add Peripheral Component</strong> below.</div>';
        return;
      }

      let html = '';
      currentComponents.forEach((c, idx) => {
        const type = parseInt(c.type) || 1;
        html += `<div style="background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:10px 12px; display:flex; flex-direction:column; gap:8px;">
          <div style="display:grid; grid-template-columns: 1.2fr 2fr 2fr 36px; gap:8px; align-items:center;">
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Component ID</label>
              <input type="text" id="compCid_${idx}" value="${c.id || ('comp' + idx)}" maxlength="11" placeholder="e.g. pump" style="margin:0; padding:5px; font-family:var(--font-mono);">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Friendly Name</label>
              <input type="text" id="compName_${idx}" value="${c.name || ('Component ' + (idx + 1))}" placeholder="e.g. Water Pump" style="margin:0; padding:5px;">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Peripheral Device Type</label>
              <select id="compType_${idx}" onchange="onComponentTypeChange(${idx})" style="margin:0; padding:5px;">
                <option value="1" ${type === 1 ? 'selected' : ''}>Relay / Actuator (Output)</option>
                <option value="4" ${type === 4 ? 'selected' : ''}>Ultrasonic HC-SR04 (Trig+Echo)</option>
                <option value="5" ${type === 5 ? 'selected' : ''}>DHT Temp/Humidity Sensor</option>
                <option value="3" ${type === 3 ? 'selected' : ''}>Push Button (Input Pullup)</option>
                <option value="2" ${type === 2 ? 'selected' : ''}>Wall Switch / Touch (Input)</option>
                <option value="7" ${type === 7 ? 'selected' : ''}>Analog Sensor (ADC)</option>
              </select>
            </div>
            <div style="text-align:right;">
              <button class="btn btn-danger btn-sm" onclick="removeComponentRow(${idx})" style="padding:4px 6px; font-size:11px; margin-top:14px;">&times;</button>
            </div>
          </div>`;

        if (type === 1) { // Relay
          html += `<div style="display:flex; align-items:center; gap:14px; background:var(--card); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
            <div style="width:140px;">
              <label style="font-size:10px; margin:0 0 2px;">Relay Pin (GPIO)</label>
              <input type="number" id="compPin1_${idx}" value="${c.pin1 !== undefined ? c.pin1 : 4}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:11px; margin-top:14px;">
              <input type="checkbox" id="compFlags_${idx}" ${(c.flags & 1) ? 'checked' : ''} style="width:auto; margin:0;">
              <span>Active LOW (inverted trigger)</span>
            </label>
            <span style="font-size:11px; color:var(--text-dim); margin-left:auto; font-family:var(--font-mono);">Entity: <code>${c.id || 'comp'}.state</code></span>
          </div>`;
        } else if (type === 4) { // Ultrasonic HC-SR04
          html += `<div style="display:grid; grid-template-columns: 1fr 1fr 1fr 1.5fr; gap:10px; align-items:center; background:var(--card); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Trig Pin (GPIO)</label>
              <input type="number" id="compPin1_${idx}" value="${c.pin1 !== undefined ? c.pin1 : 5}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Echo Pin (GPIO)</label>
              <input type="number" id="compPin2_${idx}" value="${c.pin2 !== undefined ? c.pin2 : 18}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Tank Depth (cm)</label>
              <input type="number" id="compParam1_${idx}" value="${c.param1 > 0 ? c.param1 : 200}" min="10" max="500" style="margin:0; padding:4px;">
            </div>
            <div style="font-size:10px; color:var(--text-dim); font-family:var(--font-mono); text-align:right;">
              Entities: <code>${c.id || 'comp'}.dist</code> (cm)<br><code>${c.id || 'comp'}.level</code> (%)
            </div>
          </div>`;
        } else if (type === 5) { // DHT
          html += `<div style="display:grid; grid-template-columns: 1fr 1.2fr 1.5fr; gap:10px; align-items:center; background:var(--card); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Data Pin (GPIO)</label>
              <input type="number" id="compPin1_${idx}" value="${c.pin1 !== undefined ? c.pin1 : 4}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Sensor Model</label>
              <select id="compParam1_${idx}" style="margin:0; padding:4px;">
                <option value="11" ${c.param1 === 11 || !c.param1 ? 'selected' : ''}>DHT11 (Standard)</option>
                <option value="22" ${c.param1 === 22 ? 'selected' : ''}>DHT22 / AM2302 (Precision)</option>
              </select>
            </div>
            <div style="font-size:10px; color:var(--text-dim); font-family:var(--font-mono); text-align:right;">
              Entities: <code>${c.id || 'comp'}.temp</code> (&deg;C)<br><code>${c.id || 'comp'}.hum</code> (%)
            </div>
          </div>`;
        } else if (type === 2 || type === 3) { // Button or Switch
          html += `<div style="display:flex; align-items:center; gap:14px; background:var(--card); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
            <div style="width:140px;">
              <label style="font-size:10px; margin:0 0 2px;">Input Pin (GPIO)</label>
              <input type="number" id="compPin1_${idx}" value="${c.pin1 !== undefined ? c.pin1 : 0}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <span style="font-size:11px; color:var(--text-dim);">Internal pullup enabled automatically</span>
            <span style="font-size:11px; color:var(--text-dim); margin-left:auto; font-family:var(--font-mono);">Entity: <code>${c.id || 'comp'}.state</code></span>
          </div>`;
        } else if (type === 7) { // ADC
          html += `<div style="display:flex; align-items:center; gap:14px; background:var(--card); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
            <div style="width:140px;">
              <label style="font-size:10px; margin:0 0 2px;">ADC Pin (GPIO)</label>
              <input type="number" id="compPin1_${idx}" value="${c.pin1 !== undefined ? c.pin1 : 0}" min="0" max="48" style="margin:0; padding:4px;">
            </div>
            <span style="font-size:11px; color:var(--text-dim); margin-left:auto; font-family:var(--font-mono);">Entity: <code>${c.id || 'comp'}.raw</code></span>
          </div>`;
        }

        html += `</div>`;
      });
      list.innerHTML = html;
    }

    function onComponentTypeChange(idx) {
      syncCurrentCompInputs();
      const typeEl = document.getElementById('compType_' + idx);
      if (typeEl) currentComponents[idx].type = parseInt(typeEl.value);
      renderComponentRows();
    }

    function addComponentRow() {
      syncCurrentCompInputs();
      const idx = currentComponents.length;
      currentComponents.push({
        id: 'comp' + (idx + 1),
        name: 'Component ' + (idx + 1),
        type: 1,
        pin1: 4,
        pin2: 255,
        flags: 1,
        param1: 0
      });
      renderComponentRows();
    }

    function removeComponentRow(idx) {
      syncCurrentCompInputs();
      currentComponents.splice(idx, 1);
      renderComponentRows();
    }

    function syncCurrentCompInputs() {
      currentComponents.forEach((c, idx) => {
        const idEl = document.getElementById('compCid_' + idx);
        const nameEl = document.getElementById('compName_' + idx);
        const typeEl = document.getElementById('compType_' + idx);
        const p1El = document.getElementById('compPin1_' + idx);
        const p2El = document.getElementById('compPin2_' + idx);
        const flagsEl = document.getElementById('compFlags_' + idx);
        const paramEl = document.getElementById('compParam1_' + idx);

        if (idEl) c.id = idEl.value.trim().toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 11);
        if (nameEl) c.name = nameEl.value.trim();
        if (typeEl) c.type = parseInt(typeEl.value) || 1;
        if (p1El) c.pin1 = parseInt(p1El.value) || 0;
        if (p2El) c.pin2 = parseInt(p2El.value) || 255;
        if (flagsEl) c.flags = flagsEl.checked ? 1 : 0;
        if (paramEl) c.param1 = parseInt(paramEl.value) || 0;
      });
    }

    async function saveComponents() {
      syncCurrentCompInputs();
      if (!activeCompNodeId) return;

      const res = await fetch('/api/nodes/components', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeCompNodeId, components: currentComponents })
      });

      if (res.ok) {
        closeModal('componentModal');
        showToast('Peripheral components saved and pushed to node!', 'success');
        refreshData();
      } else {
        showToast('Failed to save components', 'error');
      }
    }

    async function deleteNode(nodeId) {
      if (!confirm(`Are you sure you want to delete and unbind node '${nodeId}'?`)) return;
      const res = await fetch('/api/nodes/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: nodeId })
      });
      if (res.ok) {
        showToast('Node deleted', 'success');
        refreshData();
      } else {
        showToast('Failed to delete node', 'error');
      }
    }

    // =========================================================================
    // DISCOVERY & BINDING
    // =========================================================================
    let pendingNodesCache = [];
    function renderPending(pending) {
      pendingNodesCache = pending || [];
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

    function toggleBindApFields() {
      const en = document.getElementById('bindApEn').checked;
      document.getElementById('bindApFields').style.display = en ? 'block' : 'none';
      if (en && !document.getElementById('bindApSsid').value) {
        const id = document.getElementById('bindNodeId').value.trim() || 'N01';
        document.getElementById('bindApSsid').value = 'MiniHA_AP_' + id;
      }
    }

    function toggleApModalFields() {
      const en = document.getElementById('apModalEn').checked;
      document.getElementById('apModalFields').style.display = en ? 'block' : 'none';
    }

    let activeApNodeId = null;
    function openApModal(nodeId) {
      activeApNodeId = nodeId;
      const node = configuredNodes.find(n => n.id === nodeId);
      if (!node) return;

      document.getElementById('apModalTitle').innerText = `Configure Wi-Fi AP Bridge: ${node.name || nodeId} (${nodeId})`;
      const en = !!node.ap_enabled;
      document.getElementById('apModalEn').checked = en;
      document.getElementById('apModalSsid').value = node.ap_ssid || ('MiniHA_AP_' + nodeId);
      document.getElementById('apModalPass').value = node.ap_pass || '';
      toggleApModalFields();
      document.getElementById('apModal').style.display = 'flex';
    }

    async function saveNodeApConfig() {
      if (!activeApNodeId) return;
      const en = document.getElementById('apModalEn').checked;
      const ssid = document.getElementById('apModalSsid').value.trim();
      const pass = document.getElementById('apModalPass').value;

      if (en && !ssid) {
        showToast('Please specify an AP SSID', 'error');
        return;
      }

      const res = await fetch('/api/nodes/ap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeApNodeId, ap_enabled: en, ap_ssid: ssid, ap_pass: pass })
      });

      if (res.ok) {
        closeModal('apModal');
        showToast('AP Bridge configuration saved and pushed to slave!', 'success');
        refreshData();
      } else {
        showToast('Failed to save AP configuration', 'error');
      }
    }

    function openBindModal(mac) {
      activeBindMac = mac;
      document.getElementById('bindMacLabel').innerText = 'Device MAC: ' + mac;
      if (document.getElementById('bindApEn')) document.getElementById('bindApEn').checked = false;
      if (document.getElementById('bindApFields')) document.getElementById('bindApFields').style.display = 'none';
      if (document.getElementById('bindApSsid')) document.getElementById('bindApSsid').value = '';
      if (document.getElementById('bindApPass')) document.getElementById('bindApPass').value = '';
      document.getElementById('bindModal').style.display = 'flex';
    }

    async function submitBindNode() {
      const id = document.getElementById('bindNodeId').value.trim();
      const name = document.getElementById('bindNodeName').value.trim();
      const apEn = document.getElementById('bindApEn') ? document.getElementById('bindApEn').checked : false;
      const apSsid = document.getElementById('bindApSsid') ? document.getElementById('bindApSsid').value.trim() : '';
      const apPass = document.getElementById('bindApPass') ? document.getElementById('bindApPass').value : '';

      if (!id || !name) return showToast('Fill all fields', 'error');

      await fetch('/api/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac: activeBindMac, id: id, name: name, ap_enabled: apEn, ap_ssid: apSsid, ap_pass: apPass })
      });
      closeModal('bindModal');
      showToast('Node binding dispatched', 'success');
      refreshData();
    }

    // =========================================================================
    // AUTOMATION RULES ENGINE (MODAL-BASED)
    // =========================================================================
    let currentRules = [];

    async function loadRules() {
      try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        currentRules = data.rules || [];
        renderRules();
      } catch (e) {
        console.error(e);
      }
    }

    function renderRules() {
      const container = document.getElementById('rulesList');
      if (!container) return;
      if (currentRules.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding:30px 10px; text-align:center;">No automation rules configured. Click <strong>+ Add Rule</strong> above to create event-driven automations.</div>';
        return;
      }

      let html = '';
      currentRules.forEach((rule, idx) => {
        const isEnabled = rule.enabled;
        const cond = (rule.conditions && rule.conditions[0]) ? rule.conditions[0] : { node: '--', key: 'LVL', op: '>=', val: 0 };
        const act = (rule.actions && rule.actions[0]) ? rule.actions[0] : { target: 'LOCAL', slot: 1, val: 1 };
        const nTitle = rule.notify_title || '';

        html += `<div class="node-box" style="margin-bottom:12px; border:1px solid var(--card-border);">
          <div class="node-header" style="flex-wrap:wrap; gap:8px;">
            <div>
              <strong style="font-size:14px;">${rule.name || ('Rule #' + (idx + 1))}</strong>
              <span class="badge" style="margin-left:8px; font-size:10px; background:${isEnabled ? 'var(--success-subtle)' : 'var(--card-elevated)'}; color:${isEnabled ? 'var(--success)' : 'var(--text-dim)'};">${isEnabled ? 'ENABLED' : 'DISABLED'}</span>
            </div>
            <div style="display:flex; gap:8px;">
              <button class="btn btn-secondary btn-sm" onclick="toggleRuleEnable(${idx})" style="padding:3px 8px; font-size:11px;">${isEnabled ? 'Disable' : 'Enable'}</button>
              <button class="btn btn-secondary btn-sm" onclick="openAddRuleModal(${idx})" style="padding:3px 8px; font-size:11px;">Edit</button>
              <button class="btn btn-danger btn-sm" onclick="deleteRule(${idx})" style="padding:3px 8px; font-size:11px;">Delete</button>
            </div>
          </div>

          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:10px; margin-top:8px; font-size:12px;">
            <div style="background:var(--card-elevated); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
              <span style="font-size:10px; font-weight:700; text-transform:uppercase; color:var(--text-dim); display:block; margin-bottom:4px;">When (Condition)</span>
              <strong>${cond.node}</strong> &bull; <code>${cond.key}</code> <strong>${cond.op}</strong> ${cond.val}
            </div>
            <div style="background:var(--card-elevated); padding:8px 10px; border-radius:var(--radius-sm); border:1px solid var(--card-border-subtle);">
              <span style="font-size:10px; font-weight:700; text-transform:uppercase; color:var(--text-dim); display:block; margin-bottom:4px;">Then (Action)</span>
              Target <strong>${act.target}</strong> &bull; ${act.comp || ('Slot ' + act.slot)} &rarr; <strong style="color:${act.val === 1 ? 'var(--success)' : 'var(--text-dim)'}">${act.val === 1 ? 'TURN ON' : 'TURN OFF'}</strong>
            </div>
          </div>

          ${rule.notify ? `<div style="margin-top:8px; font-size:11px; color:var(--text-muted); background:rgba(16, 185, 129, 0.05); padding:6px 10px; border-radius:var(--radius-sm); border:1px solid rgba(16, 185, 129, 0.15);">
            <strong style="color:var(--success);">Push Alert:</strong> "${nTitle || 'Automation Alert'}" &mdash; ${rule.notify_msg || 'Condition triggered'}
          </div>` : ''}
        </div>`;
      });
      container.innerHTML = html;
    }

    let activeEditRuleIdx = -1;

    function updateRuleCondKeys(nodeId, selectedKey) {
      const select = document.getElementById('ruleModalCondKey');
      const node = configuredNodes.find(n => n.id === nodeId);
      let optHtml = '';
      if (node && node.components && node.components.length > 0) {
        node.components.forEach(c => {
          const cid = c.id || 'comp';
          const cName = c.name || cid;
          const cType = parseInt(c.type) || 1;
          if (cType === 4) { // Ultrasonic
            optHtml += `<option value="${cid}.dist">${cName} &rarr; Distance (cm) [${cid}.dist]</option>`;
            optHtml += `<option value="${cid}.level">${cName} &rarr; Tank Level (%) [${cid}.level]</option>`;
          } else if (cType === 5) { // DHT
            optHtml += `<option value="${cid}.temp">${cName} &rarr; Temperature (&deg;C) [${cid}.temp]</option>`;
            optHtml += `<option value="${cid}.hum">${cName} &rarr; Humidity (%) [${cid}.hum]</option>`;
          } else if (cType === 1) { // Relay
            optHtml += `<option value="${cid}.state">${cName} &rarr; Relay State (0/1) [${cid}.state]</option>`;
          } else if (cType === 2 || cType === 3) { // Button/Touch
            optHtml += `<option value="${cid}.state">${cName} &rarr; Input State (0/1) [${cid}.state]</option>`;
          } else if (cType === 7) { // ADC
            optHtml += `<option value="${cid}.raw">${cName} &rarr; ADC Value [${cid}.raw]</option>`;
          }
        });
      } else if (node && node.slots && node.slots.length > 0) {
        node.slots.forEach(s => {
          const sName = s.name || `Slot ${s.slot}`;
          if (s.type === 4) {
            optHtml += `<option value="SLOT_${s.slot}">Slot ${s.slot} (${sName}): Distance / Level (cm)</option>`;
          } else if (s.type === 6 || s.type === 7) {
            optHtml += `<option value="SLOT_${s.slot}_TMP">Slot ${s.slot} (${sName}): Temperature (&deg;C)</option>`;
            optHtml += `<option value="SLOT_${s.slot}_HUM">Slot ${s.slot} (${sName}): Humidity (%)</option>`;
          } else if (s.type === 1) {
            optHtml += `<option value="SLOT_${s.slot}">Slot ${s.slot} (${sName}): Relay Output State (0/1)</option>`;
          } else if (s.type === 2 || s.type === 3) {
            optHtml += `<option value="SLOT_${s.slot}">Slot ${s.slot} (${sName}): Physical Input State (0/1)</option>`;
          } else if (s.type === 9) {
            optHtml += `<option value="SLOT_${s.slot}">Slot ${s.slot} (${sName}): Analog Value</option>`;
          }
        });
      }
      optHtml += `<option value="LVL">Global / Primary Distance (cm)</option>`;
      optHtml += `<option value="TMP">Global / Primary Temperature (&deg;C)</option>`;
      optHtml += `<option value="HUM">Global / Primary Humidity (%)</option>`;
      select.innerHTML = optHtml;
      if (selectedKey) select.value = selectedKey;
    }

    function updateRuleActSlots(nodeId, selectedSlotOrComp) {
      const select = document.getElementById('ruleModalActSlot');
      const node = configuredNodes.find(n => n.id === nodeId);
      let optHtml = '';
      if (node && node.components && node.components.length > 0) {
        node.components.filter(c => parseInt(c.type) === 1).forEach((c, idx) => {
          const cid = c.id || ('comp' + idx);
          optHtml += `<option value="${cid}">${c.name || cid} [${cid}]</option>`;
        });
      }
      if (!optHtml && node && node.slots && node.slots.length > 0) {
        node.slots.filter(s => s.type === 1).forEach(s => {
          optHtml += `<option value="${s.slot}">Slot ${s.slot}: ${s.name || ('Relay ' + s.slot)}</option>`;
        });
      }
      if (!optHtml) {
        optHtml = `<option value="0">Default Actuator</option>`;
      }
      select.innerHTML = optHtml;
      if (selectedSlotOrComp !== undefined) select.value = selectedSlotOrComp;
    }

    function onRuleCondNodeChange() {
      const cNode = document.getElementById('ruleModalCondNode').value;
      updateRuleCondKeys(cNode);
    }

    function onRuleActTargetChange() {
      const aTarget = document.getElementById('ruleModalActTarget').value;
      updateRuleActSlots(aTarget);
    }

    function openAddRuleModal(editIdx = -1) {
      activeEditRuleIdx = editIdx;
      document.getElementById('ruleModalTitle').innerText = (editIdx >= 0) ? 'Edit Automation Rule' : 'Add Automation Rule';

      // Populate Node Dropdowns
      const condSelect = document.getElementById('ruleModalCondNode');
      const actSelect = document.getElementById('ruleModalActTarget');
      let optionsHtml = '<option value="LOCAL">LOCAL (Master Hub)</option>';
      configuredNodes.forEach(n => {
        optionsHtml += `<option value="${n.id}">${n.name || n.id} (${n.id})</option>`;
      });
      condSelect.innerHTML = optionsHtml;
      actSelect.innerHTML = optionsHtml;

      if (editIdx >= 0 && currentRules[editIdx]) {
        const r = currentRules[editIdx];
        document.getElementById('ruleModalName').value = r.name || '';
        const c = (r.conditions && r.conditions[0]) ? r.conditions[0] : {};
        condSelect.value = c.node || 'LOCAL';
        updateRuleCondKeys(c.node || 'LOCAL', c.key || 'LVL');
        document.getElementById('ruleModalCondOp').value = c.op || '>=';
        document.getElementById('ruleModalCondVal').value = (c.val !== undefined) ? c.val : 100;

        const a = (r.actions && r.actions[0]) ? r.actions[0] : {};
        actSelect.value = a.target || 'LOCAL';
        updateRuleActSlots(a.target || 'LOCAL', a.comp || a.slot || 0);
        document.getElementById('ruleModalActVal').value = (a.val !== undefined) ? a.val : 1;

        document.getElementById('ruleModalNotif').checked = !!r.notify;
        document.getElementById('ruleModalTitleText').value = r.notify_title || '';
        document.getElementById('ruleModalMsgText').value = r.notify_msg || '';
      } else {
        document.getElementById('ruleModalName').value = 'Rule #' + (currentRules.length + 1);
        if (configuredNodes.length > 0) condSelect.value = configuredNodes[0].id;
        updateRuleCondKeys(condSelect.value, 'LVL');
        document.getElementById('ruleModalCondOp').value = '>=';
        document.getElementById('ruleModalCondVal').value = 140;

        actSelect.value = 'LOCAL';
        updateRuleActSlots(actSelect.value, 0);
        document.getElementById('ruleModalActVal').value = 1;

        document.getElementById('ruleModalNotif').checked = true;
        document.getElementById('ruleModalTitleText').value = 'Automation Alert';
        document.getElementById('ruleModalMsgText').value = 'Rule condition triggered';
      }

      document.getElementById('ruleModal').style.display = 'flex';
    }

    async function saveRuleFromModal() {
      const name = document.getElementById('ruleModalName').value.trim();
      if (!name) return showToast('Please enter a rule name', 'error');

      const cNode = document.getElementById('ruleModalCondNode').value;
      const cKey = document.getElementById('ruleModalCondKey').value || 'LVL';
      const cOp = document.getElementById('ruleModalCondOp').value;
      const cVal = parseFloat(document.getElementById('ruleModalCondVal').value) || 0;

      const aTarget = document.getElementById('ruleModalActTarget').value;
      const aSlotVal = document.getElementById('ruleModalActSlot').value || '0';
      const aVal = parseInt(document.getElementById('ruleModalActVal').value) || 1;

      const isNotif = document.getElementById('ruleModalNotif').checked;
      const nTitle = document.getElementById('ruleModalTitleText').value.trim();
      const nMsg = document.getElementById('ruleModalMsgText').value.trim();

      const ruleObj = {
        name: name,
        enabled: true,
        conditions: [{ node: cNode, key: cKey, op: cOp, val: cVal }],
        actions: [{ target: aTarget, comp: aSlotVal, slot: parseInt(aSlotVal) || 0, val: aVal, reason: name }],
        notify: isNotif,
        notify_title: nTitle,
        notify_msg: nMsg
      };

      if (activeEditRuleIdx >= 0) {
        currentRules[activeEditRuleIdx] = ruleObj;
      } else {
        currentRules.push(ruleObj);
      }

      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: currentRules })
      });

      if (res.ok) {
        closeModal('ruleModal');
        showToast('Rule saved successfully!', 'success');
        renderRules();
      } else {
        showToast('Failed to save rule', 'error');
      }
    }

    async function toggleRuleEnable(idx) {
      if (!currentRules[idx]) return;
      currentRules[idx].enabled = !currentRules[idx].enabled;
      await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: currentRules })
      });
      renderRules();
    }

    async function deleteRule(idx) {
      if (!confirm('Delete this automation rule?')) return;
      currentRules.splice(idx, 1);
      await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: currentRules })
      });
      showToast('Rule deleted', 'success');
      renderRules();
    }

    async function clearAllRules() {
      if (!confirm('Are you sure you want to delete ALL automation rules?')) return;
      await fetch('/api/rules/clear', { method: 'POST' });
      currentRules = [];
      showToast('All rules cleared', 'success');
      renderRules();
    }

    // =========================================================================
    // USERS, SETTINGS & ACCOUNT
    // =========================================================================
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
      }
    }

    // =========================================================================
    // DOWNTIME-SAFE STANDALONE NODE SCHEDULES (SILICON EEPROM)
    // =========================================================================
    let activeSchedNodeId = null;
    let currentSchedules = [];

    function openScheduleTabForNode(nodeId) {
      activeSchedNodeId = nodeId;
      showTab('schedules');
    }

    function openScheduleModal(nodeId) {
      openScheduleTabForNode(nodeId);
    }

    function loadSchedulesTab() {
      const select = document.getElementById('schedTabNodeSelect');
      if (!select) return;

      let optHtml = '';
      configuredNodes.forEach(n => {
        optHtml += `<option value="${n.id}">${n.name || n.id} (${n.id})</option>`;
      });
      select.innerHTML = optHtml;

      if (!activeSchedNodeId && configuredNodes.length > 0) {
        activeSchedNodeId = configuredNodes[0].id;
      }
      if (activeSchedNodeId) {
        select.value = activeSchedNodeId;
      }
      onSchedNodeChange();
    }

    function onSchedNodeChange() {
      const select = document.getElementById('schedTabNodeSelect');
      if (select && select.value) {
        activeSchedNodeId = select.value;
      }
      const node = configuredNodes.find(n => n.id === activeSchedNodeId);
      currentSchedules = node ? JSON.parse(JSON.stringify(node.schedules || [])) : [];
      renderSchedulesTab();
    }

    function renderSchedulesTab() {
      const list = document.getElementById('schedTabList');
      if (!list) return;

      const node = configuredNodes.find(n => n.id === activeSchedNodeId);
      if (!node) {
        list.innerHTML = '<div style="color:var(--text-dim); padding:16px 0; font-size:13px;">No hardware node selected.</div>';
        return;
      }

      const relayComps = (node.components && node.components.length > 0)
        ? node.components.map((c, i) => ({ id: c.id, name: c.name || c.id, compIdx: i, type: parseInt(c.type) })).filter(c => c.type === 1)
        : (node.slots || []).map(s => ({ id: 'slot' + s.slot, name: s.name || ('Relay ' + s.slot), compIdx: s.slot, type: s.type })).filter(s => s.type === 1);

      if (currentSchedules.length === 0) {
        list.innerHTML = '<div style="color:var(--text-dim); padding:16px; background:var(--card-elevated); border-radius:var(--radius-sm); border:1px solid var(--card-border); font-size:13px;">No standalone schedules configured for this node. Click <strong>+ Add Daily Schedule</strong> below.</div>';
        return;
      }

      let html = '';
      currentSchedules.forEach((s, idx) => {
        let actCheckboxes = '';
        if (relayComps.length > 0) {
          relayComps.forEach(rc => {
            let isChecked = false;
            if (s.targetCompsMask !== undefined && s.targetCompsMask > 0) isChecked = !!(s.targetCompsMask & (1 << rc.compIdx));
            else if (s.targetSlotsMask !== undefined && s.targetSlotsMask > 0) isChecked = !!(s.targetSlotsMask & (1 << rc.compIdx));
            else if (s.targetSlots && Array.isArray(s.targetSlots)) isChecked = s.targetSlots.includes(rc.compIdx);
            else isChecked = (s.targetSlot === rc.compIdx || s.targetComp === rc.compIdx);
            actCheckboxes += `<label style="display:inline-flex; align-items:center; gap:5px; margin-right:8px; margin-bottom:4px; cursor:pointer; background:var(--card); padding:4px 8px; border-radius:var(--radius-sm); border:1px solid var(--card-border); font-size:11px;">
              <input type="checkbox" class="sched-chk-${idx}" value="${rc.compIdx}" ${isChecked ? 'checked' : ''}>
              <span>${rc.name} (${rc.id})</span>
            </label>`;
          });
        } else {
          actCheckboxes = '<span style="color:var(--warning); font-size:11px;">No Relay output actuators configured on this node. Go to Overview &rarr; Configure Components to add relays.</span>';
        }

        const onH = String(s.onHour || 0).padStart(2, '0');
        const onM = String(s.onMinute || 0).padStart(2, '0');
        const offH = String(s.offHour || 0).padStart(2, '0');
        const offM = String(s.offMinute || 0).padStart(2, '0');

        html += `<div style="background:var(--card-elevated); border:1px solid var(--card-border); border-radius:var(--radius-sm); padding:12px 14px; margin-bottom:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; border-bottom:1px solid var(--card-border-subtle); padding-bottom:6px;">
            <div style="display:flex; align-items:center; gap:8px;">
              <strong style="font-size:13px;">Daily Schedule #${idx + 1}</strong>
              <label style="display:inline-flex; align-items:center; gap:4px; margin:0; cursor:pointer; font-size:11px; color:var(--text-muted);">
                <input type="checkbox" id="schedEn_${idx}" ${s.enabled ? 'checked' : ''} style="width:auto; margin:0;">
                <span>Enabled</span>
              </label>
            </div>
            <button class="btn btn-danger btn-sm" onclick="removeScheduleRow(${idx})" style="padding:2px 8px; font-size:11px;">Delete</button>
          </div>
          
          <div style="margin-bottom:8px;">
            <label style="font-size:10px; margin:0 0 4px; display:block; text-transform:uppercase; color:var(--text-dim); font-weight:700;">Target Actuators (Multi-Select Support)</label>
            <div style="display:flex; flex-wrap:wrap; gap:4px; margin-top:2px;">
              ${actCheckboxes}
            </div>
          </div>

          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-top:6px;">
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Turn ON Time</label>
              <input type="time" id="schedOn_${idx}" value="${onH}:${onM}" style="margin:0; padding:6px;">
            </div>
            <div>
              <label style="font-size:10px; margin:0 0 2px;">Turn OFF Time</label>
              <input type="time" id="schedOff_${idx}" value="${offH}:${offM}" style="margin:0; padding:6px;">
            </div>
          </div>
        </div>`;
      });
      list.innerHTML = html;
    }

    function addScheduleToActiveNode() {
      if (currentSchedules.length >= 8) {
        showToast('Max 8 standalone schedules per slave microcontroller', 'error');
        return;
      }
      syncScheduleInputs();
      const node = configuredNodes.find(n => n.id === activeSchedNodeId);
      const relayComps = (node && node.components && node.components.length > 0)
        ? node.components.map((c, i) => ({ id: c.id, compIdx: i, type: parseInt(c.type) })).filter(c => c.type === 1)
        : (node ? (node.slots || []).filter(s => s.type === 1).map(s => ({ id: 'slot' + s.slot, compIdx: s.slot, type: s.type })) : []);
      const defaultSlot = (relayComps.length > 0) ? relayComps[0].compIdx : 0;

      currentSchedules.push({
        enabled: 1,
        targetSlot: defaultSlot,
        targetComp: defaultSlot,
        targetSlots: [defaultSlot],
        targetSlotsMask: (1 << defaultSlot),
        targetCompsMask: (1 << defaultSlot),
        action: 1,
        onHour: 18,
        onMinute: 0,
        offHour: 6,
        offMinute: 0
      });
      renderSchedulesTab();
    }

    function removeScheduleRow(idx) {
      syncScheduleInputs();
      currentSchedules.splice(idx, 1);
      renderSchedulesTab();
    }

    function syncScheduleInputs() {
      currentSchedules.forEach((s, idx) => {
        const onEl = document.getElementById('schedOn_' + idx);
        const offEl = document.getElementById('schedOff_' + idx);
        const enEl = document.getElementById('schedEn_' + idx);
        if (enEl) s.enabled = enEl.checked ? 1 : 0;
        if (onEl && onEl.value) {
          const parts = onEl.value.split(':');
          s.onHour = parseInt(parts[0]) || 0;
          s.onMinute = parseInt(parts[1]) || 0;
        }
        if (offEl && offEl.value) {
          const parts = offEl.value.split(':');
          s.offHour = parseInt(parts[0]) || 0;
          s.offMinute = parseInt(parts[1]) || 0;
        }
        const chks = document.querySelectorAll('.sched-chk-' + idx);
        let mask = 0;
        const selectedIndices = [];
        chks.forEach(chk => {
          if (chk.checked) {
            const cIdx = parseInt(chk.value);
            mask |= (1 << cIdx);
            selectedIndices.push(cIdx);
          }
        });
        s.targetCompsMask = mask;
        s.targetSlotsMask = mask;
        s.targetSlots = selectedIndices;
        s.targetSlot = selectedIndices.length > 0 ? selectedIndices[0] : 0;
        s.targetComp = s.targetSlot;
      });
    }

        const chks = document.querySelectorAll(`.sched-chk-${idx}:checked`);
        const targetSlots = [];
        let mask = 0;
        chks.forEach(cb => {
          const slotVal = parseInt(cb.value);
          targetSlots.push(slotVal);
          mask |= (1 << slotVal);
        });
        s.targetSlots = targetSlots;
        s.targetSlotsMask = mask;
        s.targetSlot = (targetSlots.length > 0) ? targetSlots[0] : 0;
        s.action = 1;
      });
    }

    async function saveActiveNodeSchedules() {
      syncScheduleInputs();
      if (!activeSchedNodeId) return;

      const res = await fetch('/api/nodes/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeSchedNodeId, schedules: currentSchedules })
      });

      if (res.ok) {
        const node = configuredNodes.find(n => n.id === activeSchedNodeId);
        if (node) node.schedules = currentSchedules;
        showToast('Schedules saved and pushed to slave EEPROM over RS-422!', 'success');
        refreshData();
      } else {
        showToast('Failed to save schedules', 'error');
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

  webServer.on("/", HTTP_GET, []() {
    webServer.send_P(200, "text/html; charset=utf-8", INDEX_HTML);
  });
  webServer.on("/index.html", HTTP_GET, []() {
    webServer.send_P(200, "text/html; charset=utf-8", INDEX_HTML);
  });
  webServer.on("/favicon.ico", HTTP_GET, []() {
    webServer.send(204);
  });
}
