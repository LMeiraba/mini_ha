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
void triggerProvisionNode(const String& mac, const String& newId, const String& name, bool apEnabled = false, const String& apSsid = "", const String& apPass = "", bool apHidden = false);

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
    prunePendingDevices();
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
      n["freeHeap"] = nodeStates[i].freeHeap;
      n["hasSeen"] = (nodeStates[i].lastSeen != 0);
      n["lastSeen"] = (nodeStates[i].lastSeen == 0) ? 999999 : ((millis() - nodeStates[i].lastSeen) / 1000);
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
    bool apHidden = doc.containsKey("ap_hidden") ? doc["ap_hidden"].as<bool>() : false;
    String apSsid = doc.containsKey("ap_ssid") ? doc["ap_ssid"].as<String>() : ("MiniHA_" + newId);
    String apPass = doc.containsKey("ap_pass") ? doc["ap_pass"].as<String>() : "";
    triggerProvisionNode(mac, newId, name, apEn, apSsid, apPass, apHidden);
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
    bool apHidden = doc.containsKey("ap_hidden") ? doc["ap_hidden"].as<bool>() : false;
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
        node["ap_hidden"] = apHidden;
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
    String p = "AP:" + String(apEn ? 1 : 0) + ":" + apSsid + ":" + apPass + ":" + String(apHidden ? 1 : 0);
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
      for (uint8_t i = 0; i < numTrackedNodes; i++) {
        if (nodeStates[i].nodeId == targetId) {
          nodeStates[i].lastSeen = 0;
          nodeStates[i].nodeId = "";
          break;
        }
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
  
  <script>
    if (localStorage.getItem('miniha_logged_in') === '1') {
      document.documentElement.classList.add('is-auth');
    }
  </script>

  <style>
    :root {
      --bg: #0b0f19;
      --sidebar-bg: #0f172a;
      --sidebar-border: rgba(255, 255, 255, 0.07);
      --card-bg: #141e33;
      --card-elevated: #1a2642;
      --card-border: rgba(255, 255, 255, 0.08);
      --card-border-focus: rgba(96, 165, 250, 0.6);
      
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;

      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --primary-subtle: rgba(59, 130, 246, 0.15);

      --success: #10b981;
      --success-subtle: rgba(16, 185, 129, 0.15);
      --success-border: rgba(16, 185, 129, 0.3);

      --warning: #f59e0b;
      --warning-subtle: rgba(245, 158, 11, 0.15);
      --warning-border: rgba(245, 158, 11, 0.3);

      --danger: #ef4444;
      --danger-subtle: rgba(239, 68, 68, 0.15);
      --danger-border: rgba(239, 68, 68, 0.3);

      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 13px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }

    /* Flash Prevention */
    html.is-auth #loginView { display: none !important; }
    html.is-auth #hubApp { display: flex !important; }
    html:not(.is-auth) #loginView { display: flex !important; }
    html:not(.is-auth) #hubApp { display: none !important; }

    /* Icons */
    .icon {
      width: 16px;
      height: 16px;
      stroke: currentColor;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      fill: none;
      flex-shrink: 0;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 7px 14px;
      font-size: 12px;
      font-weight: 500;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      cursor: pointer;
      background: var(--primary);
      color: #fff;
      transition: all 0.15s ease;
      text-decoration: none;
    }
    .btn:hover { background: var(--primary-hover); }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      border-color: var(--card-border);
      color: var(--text);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--text-dim);
    }
    .btn-danger {
      background: var(--danger-subtle);
      border-color: var(--danger-border);
      color: #fca5a5;
    }
    .btn-danger:hover {
      background: var(--danger);
      color: #fff;
    }
    .btn-sm { padding: 4px 10px; font-size: 11px; }

    /* Form Inputs */
    input[type="text"], input[type="password"], input[type="number"], select {
      width: 100%;
      padding: 8px 12px;
      background: #090d17;
      border: 1px solid var(--card-border);
      border-radius: var(--radius-sm);
      color: var(--text);
      font-size: 12px;
      outline: none;
      transition: border-color 0.15s ease;
      font-family: inherit;
    }
    input:focus, select:focus { border-color: var(--card-border-focus); }
    label {
      display: block;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* Badges & Status */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border-radius: 9999px;
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-muted);
      border: 1px solid var(--card-border);
    }
    .badge-primary { background: var(--primary-subtle); color: #93c5fd; border-color: rgba(59, 130, 246, 0.3); }
    .badge-success { background: var(--success-subtle); color: #6ee7b7; border-color: var(--success-border); }
    .badge-warning { background: var(--warning-subtle); color: #fcd34d; border-color: var(--warning-border); }
    .badge-danger  { background: var(--danger-subtle); color: #fca5a5; border-color: var(--danger-border); }

    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--text-dim);
      display: inline-block;
    }
    .status-dot.online {
      background: var(--success);
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.7);
    }
    .status-dot.warning {
      background: var(--warning);
      box-shadow: 0 0 6px rgba(245, 158, 11, 0.6);
    }
    .status-dot.offline {
      background: var(--danger);
    }

    /* Card Layouts */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-lg);
      padding: 18px 22px;
      margin-bottom: 20px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .card-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card-desc {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* App Shell Layout */
    #hubApp {
      display: none;
      min-height: 100vh;
    }

    /* Sidebar Navigation */
    .sidebar {
      width: 250px;
      background: var(--sidebar-bg);
      border-right: 1px solid var(--sidebar-border);
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0;
      bottom: 0;
      left: 0;
      z-index: 100;
    }
    .sidebar-brand {
      padding: 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-bottom: 1px solid var(--sidebar-border);
    }
    .brand-icon-box {
      width: 36px;
      height: 36px;
      border-radius: 9px;
      background: linear-gradient(135deg, #2563eb, #10b981);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      box-shadow: 0 0 16px rgba(37, 99, 235, 0.4);
    }
    .brand-text h1 {
      font-size: 15px;
      font-weight: 800;
      letter-spacing: 0.5px;
      line-height: 1.1;
    }
    .brand-text span {
      font-size: 9px;
      font-family: var(--font-mono);
      color: var(--success);
      font-weight: 600;
      letter-spacing: 1px;
    }

    .user-profile-strip {
      padding: 12px 20px;
      border-bottom: 1px solid var(--sidebar-border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(0, 0, 0, 0.15);
    }
    .user-info-text {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      color: var(--text-muted);
    }
    .user-info-text strong {
      color: var(--text);
    }

    .sidebar-nav {
      flex: 1;
      padding: 14px 10px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 9px 14px;
      color: var(--text-muted);
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      border-left: 3px solid transparent;
      user-select: none;
    }
    .nav-item:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
    }
    .nav-item.active {
      background: var(--primary-subtle);
      color: #60a5fa;
      border-left-color: var(--primary);
      font-weight: 600;
    }
    .nav-item .icon {
      color: inherit;
    }

    .sidebar-footer {
      padding: 16px;
      border-top: 1px solid var(--sidebar-border);
      display: flex;
      flex-direction: column;
      gap: 10px;
      background: rgba(0, 0, 0, 0.15);
    }
    .hub-status-pill {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-dim);
    }

    /* Main Content Area */
    .main-wrap {
      margin-left: 250px;
      flex: 1;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .main-header {
      padding: 16px 28px;
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--sidebar-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 90;
    }
    .page-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text);
    }
    .main-body {
      padding: 24px 28px;
      flex: 1;
    }

    /* Dashboard KPI Banner */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-md);
      padding: 14px 18px;
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .kpi-icon-wrap {
      width: 40px;
      height: 40px;
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(255, 255, 255, 0.05);
      color: var(--primary);
    }
    .kpi-data .kpi-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .kpi-data .kpi-val {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
      line-height: 1.2;
    }

    /* Unified Control Cards (Dashboard Tab) */
    .controls-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }
    .control-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-md);
      padding: 16px;
      transition: border-color 0.15s ease;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .control-card:hover {
      border-color: rgba(255, 255, 255, 0.15);
    }
    .control-card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }
    .control-name {
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
    }
    .control-sub {
      font-size: 10px;
      color: var(--text-dim);
      font-family: var(--font-mono);
      margin-top: 2px;
    }

    /* Modern Toggle Switch */
    .toggle-switch-wrap {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
    }
    .toggle-status-text {
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .toggle-status-text.on { color: var(--success); }
    .toggle-status-text.off { color: var(--text-dim); }

    .switch-btn {
      position: relative;
      width: 44px;
      height: 24px;
      background: #1e293b;
      border-radius: 9999px;
      border: 1px solid var(--card-border);
      cursor: pointer;
      transition: background 0.2s ease, border-color 0.2s ease;
      padding: 0;
      outline: none;
    }
    .switch-btn.active {
      background: var(--success);
      border-color: var(--success);
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.4);
    }
    .switch-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .switch-thumb {
      position: absolute;
      top: 2px;
      left: 2px;
      width: 18px;
      height: 18px;
      background: #fff;
      border-radius: 50%;
      transition: transform 0.2s ease;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }
    .switch-btn.active .switch-thumb {
      transform: translateX(20px);
    }

    /* Ultrasonic Tank Graphic */
    .tank-visual-wrap {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-top: 8px;
    }
    .tank-pillar {
      width: 32px;
      height: 72px;
      background: #090d17;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      position: relative;
      overflow: hidden;
      flex-shrink: 0;
    }
    .tank-fluid {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      background: linear-gradient(to top, #2563eb, #38bdf8);
      transition: height 0.4s ease;
      box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
    }
    .tank-metrics {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .tank-percent {
      font-size: 20px;
      font-weight: 800;
      color: #38bdf8;
      line-height: 1;
    }
    .tank-dist {
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-muted);
    }

    /* Climate Graphic */
    .climate-visual-wrap {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-top: 8px;
    }
    .climate-box {
      flex: 1;
      padding: 8px 12px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: var(--radius-sm);
      border: 1px solid var(--card-border);
    }
    .climate-val {
      font-size: 18px;
      font-weight: 700;
      line-height: 1.1;
    }
    .climate-val.temp { color: #f97316; }
    .climate-val.hum { color: #38bdf8; }
    .climate-lbl {
      font-size: 10px;
      color: var(--text-dim);
      text-transform: uppercase;
      font-family: var(--font-mono);
      margin-top: 2px;
    }

    /* Hardware Node Card (Nodes Tab) */
    .node-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-lg);
      padding: 20px;
      margin-bottom: 18px;
      transition: border-color 0.15s ease;
    }
    .node-card:hover {
      border-color: rgba(255, 255, 255, 0.15);
    }
    .node-card-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
    }
    .node-meta-badges {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .node-actions-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .node-hardware-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 10px;
      padding: 12px 14px;
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: var(--radius-md);
      margin-bottom: 14px;
      font-family: var(--font-mono);
      font-size: 11px;
    }
    .hw-prop {
      display: flex;
      flex-direction: column;
    }
    .hw-lbl {
      color: var(--text-dim);
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .hw-val {
      color: var(--text);
      font-weight: 600;
      margin-top: 2px;
    }

    /* Table Styles */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th {
      text-align: left;
      padding: 10px 14px;
      color: var(--text-dim);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--card-border);
      font-weight: 600;
    }
    td {
      padding: 12px 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: var(--text);
    }
    tr:last-child td { border-bottom: none; }

    /* Modals */
    .modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .modal-card {
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-lg);
      width: 100%;
      max-width: 540px;
      padding: 22px 24px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--card-border);
    }
    .modal-title {
      font-size: 15px;
      font-weight: 700;
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
      margin-top: 20px;
      padding-top: 14px;
      border-top: 1px solid var(--card-border);
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      padding: 10px 18px;
      background: var(--card-elevated);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-sm);
      color: var(--text);
      font-size: 12px;
      box-shadow: 0 6px 20px rgba(0,0,0,0.4);
      z-index: 2000;
      display: none;
      animation: fadeIn 0.2s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Admin role guards */
    .admin-only { display: none !important; }
    body.role-admin .admin-only { display: inline-flex !important; }
    body.role-admin div.admin-only, body.role-admin .card.admin-only { display: block !important; }
    body.role-admin .nav-item.admin-only { display: flex !important; }

    /* Login View */
    .login-wrapper {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: radial-gradient(circle at 50% 20%, #1e293b 0%, #0b0f19 80%);
    }
    .login-card {
      width: 100%;
      max-width: 380px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-lg);
      padding: 28px 24px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    }
  </style>
</head>
<body>

  <!-- ========================================================================= -->
  <!-- 1. LOGIN SCREEN -->
  <!-- ========================================================================= -->
  <div id="loginView" class="login-wrapper">
    <div class="login-card">
      <div style="display:flex; align-items:center; gap:12px; margin-bottom:18px;">
        <div class="brand-icon-box">
          <svg class="icon" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg>
        </div>
        <div>
          <div style="font-size:16px; font-weight:800; letter-spacing:0.5px;">MINI-HA</div>
          <div style="font-size:10px; color:var(--text-dim); font-family:var(--font-mono); text-transform:uppercase;">Hardware Supervisor</div>
        </div>
      </div>

      <div style="font-size:12px; color:var(--text-muted); line-height:1.5; margin-bottom:18px;">
        Sign in to manage RS-422 star nodes, wireless child slaves, and automation telemetry.
      </div>

      <form onsubmit="handleLogin(event); return false;">
        <div style="margin-bottom:12px;">
          <label>Username</label>
          <input type="text" id="loginUser" required autocomplete="username" autofocus placeholder="admin">
        </div>

        <div style="margin-bottom:16px;">
          <label>Password</label>
          <div style="position:relative; display:flex; align-items:center;">
            <input type="password" id="loginPass" required autocomplete="current-password" placeholder="Password">
            <button type="button" onclick="togglePassVisibilityLocal()" style="position:absolute; right:10px; background:none; border:none; color:var(--text-dim); cursor:pointer;">
              <svg class="icon" viewBox="0 0 24 24"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
        </div>

        <button type="submit" class="btn" style="width:100%; padding:9px;">Sign In</button>
      </form>

      <div style="margin-top:18px; padding-top:12px; border-top:1px solid rgba(255,255,255,0.05); display:flex; justify-content:space-between; font-size:10px; color:var(--text-dim); font-family:var(--font-mono);">
        <span>miniha.local</span>
        <span>v0.1.0-beta</span>
      </div>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- 2. MAIN APPLICATION SHELL -->
  <!-- ========================================================================= -->
  <div id="hubApp">
    
    <!-- LEFT SIDEBAR -->
    <aside class="sidebar">
      <div class="sidebar-brand">
        <div class="brand-icon-box">
          <svg class="icon" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg>
        </div>
        <div class="brand-text">
          <h1>MINI-HA</h1>
          <span>LOCAL HUB</span>
        </div>
      </div>

      <div class="user-profile-strip">
        <div class="user-info-text">
          <svg class="icon" style="width:13px; height:13px;" viewBox="0 0 24 24"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <strong id="sidebarUsername">admin</strong>
        </div>
        <span class="badge badge-success" id="sidebarRoleBadge">ADMIN</span>
      </div>

      <nav class="sidebar-nav">
        <div class="nav-item active" id="nav-dashboard" onclick="switchNavTab('dashboard')">
          <svg class="icon" viewBox="0 0 24 24"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>
          <span>Dashboard</span>
        </div>

        <div class="nav-item" id="nav-nodes" onclick="switchNavTab('nodes')">
          <svg class="icon" viewBox="0 0 24 24"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>
          <span>Hardware Nodes</span>
        </div>

        <div class="nav-item admin-only" id="nav-rules" onclick="switchNavTab('rules')">
          <svg class="icon" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span>Automations</span>
        </div>

        <div class="nav-item admin-only" id="nav-schedules" onclick="switchNavTab('schedules')">
          <svg class="icon" viewBox="0 0 24 24"><path d="M8 2v4"/><path d="M16 2v4"/><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M3 10h18"/><path d="M12 14v4l2 2"/></svg>
          <span>Schedules</span>
        </div>

        <div class="nav-item admin-only" id="nav-users" onclick="switchNavTab('users')">
          <svg class="icon" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          <span>Users</span>
        </div>

        <div class="nav-item admin-only" id="nav-settings" onclick="switchNavTab('settings')">
          <svg class="icon" viewBox="0 0 24 24"><line x1="4" x2="20" y1="21" y2="21"/><line x1="4" x2="20" y1="3" y2="3"/><line x1="12" x2="20" y1="12" y2="12"/><line x1="4" x2="8" y1="12" y2="12"/><circle cx="10" cy="12" r="2"/></svg>
          <span>Settings</span>
        </div>

        <div class="nav-item" id="nav-account" onclick="switchNavTab('account')">
          <svg class="icon" viewBox="0 0 24 24"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          <span>Account</span>
        </div>
      </nav>

      <div class="sidebar-footer">
        <div class="hub-status-pill">
          <span style="display:flex; align-items:center; gap:6px;">
            <span class="status-dot online"></span>
            <span>RS-422 STAR BUS</span>
          </span>
          <span id="sidebarUptime">0h</span>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="handleLogout()" style="width:100%; justify-content:center;">
          <svg class="icon" style="width:13px; height:13px;" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
          <span>Sign Out</span>
        </button>
      </div>
    </aside>

    <!-- RIGHT MAIN WRAPPER -->
    <div class="main-wrap">
      
      <!-- Top Header Strip -->
      <header class="main-header">
        <div>
          <h2 class="page-title" id="pageTitle">Home Dashboard</h2>
          <div style="font-size:11px; color:var(--text-dim);" id="pageSub">Unified controls, sensors & mesh telemetry</div>
        </div>
        <div style="display:flex; align-items:center; gap:12px;">
          <span class="badge" id="hubRtcClock" style="font-family:var(--font-mono); font-size:11px;">--:--:--</span>
          <span class="badge badge-primary">192.168.4.1</span>
        </div>
      </header>

      <!-- Main Body Views -->
      <main class="main-body">

        <!-- Default Password Alert Banner -->
        <div id="defaultPassBanner" class="card" style="display:none; background:var(--warning-subtle); border-color:var(--warning-border); padding:12px 18px; margin-bottom:18px;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <div style="display:flex; align-items:center; gap:8px;">
              <svg class="icon" style="color:var(--warning);" viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>
              <span><strong>Security Notice:</strong> Using default password (<code>admin / admin123</code>). Change password immediately.</span>
            </div>
            <button class="btn btn-sm btn-secondary" onclick="openPassModal()">Change Password</button>
          </div>
        </div>

        <!-- ========================================================================= -->
        <!-- TAB 1: DASHBOARD (UNIFIED CONTROLS & SENSOR TELEMETRY) -->
        <!-- ========================================================================= -->
        <section id="viewDashboard">
          <!-- KPI Summary Strip -->
          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-icon-wrap" style="color:#60a5fa;">
                <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9"/></svg>
              </div>
              <div class="kpi-data">
                <div class="kpi-label">Nodes Connected</div>
                <div class="kpi-val" id="kpiNodesOnline">0 / 0 Online</div>
              </div>
            </div>

            <div class="kpi-card">
              <div class="kpi-icon-wrap" style="color:#10b981;">
                <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>
              </div>
              <div class="kpi-data">
                <div class="kpi-label">Active Switches</div>
                <div class="kpi-val" id="kpiActiveRelays">0 ON</div>
              </div>
            </div>

            <div class="kpi-card">
              <div class="kpi-icon-wrap" style="color:#38bdf8;">
                <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24"><path d="M12 22a7 7 0 0 0 7-7c0-2-1-3.9-3-5.5s-3.5-4-4-6.5c-.5 2.5-2 4.9-4 6.5C6 11.1 5 13 5 15a7 7 0 0 0 7 7z"/></svg>
              </div>
              <div class="kpi-data">
                <div class="kpi-label">Water Tank</div>
                <div class="kpi-val" id="kpiTankLevel">-- %</div>
              </div>
            </div>

            <div class="kpi-card">
              <div class="kpi-icon-wrap" style="color:#f59e0b;">
                <svg class="icon" style="width:20px; height:20px;" viewBox="0 0 24 24"><path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/></svg>
              </div>
              <div class="kpi-data">
                <div class="kpi-label">Environment</div>
                <div class="kpi-val" id="kpiClimate">-- &deg;C</div>
              </div>
            </div>
          </div>

          <!-- Live Actuators & Switches Section -->
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">
                  <svg class="icon" style="color:var(--primary);" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                  <span>Actuators & Relays</span>
                </h3>
                <p class="card-desc">Instant sub-millisecond local switching over isolated RS-422 bus</p>
              </div>
            </div>
            <div id="dashboardRelaysGrid" class="controls-grid">
              <div style="color:var(--text-dim); padding:10px 0;">No actuators configured. Add relays in Hardware Nodes tab.</div>
            </div>
          </div>

          <!-- Live Sensors & Gauges Section -->
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">
                  <svg class="icon" style="color:var(--success);" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><path d="m14.83 9.17 4.24-4.24"/><path d="m14.83 14.83 4.24 4.24"/><path d="m9.17 14.83-4.24 4.24"/></svg>
                  <span>Sensors & Telemetry Feeds</span>
                </h3>
                <p class="card-desc">Real-time water levels, temperature dials, and hardware bus feeds</p>
              </div>
            </div>
            <div id="dashboardSensorsGrid" class="controls-grid">
              <div style="color:var(--text-dim); padding:10px 0;">No sensors active.</div>
            </div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 2: HARDWARE NODES & PROVISIONING -->
        <!-- ========================================================================= -->
        <section id="viewNodes" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Configured Slave Microcontrollers</h3>
                <p class="card-desc">Isolated RS-422 hardware star ports & downstream Wi-Fi mesh nodes</p>
              </div>
            </div>
            <div id="nodesCardsContainer">
              <div style="color:var(--text-dim);">Loading nodes...</div>
            </div>
          </div>

          <!-- Discovered Unbound Slaves Card -->
          <div class="card admin-only" id="discoveryCard">
            <div class="card-header">
              <div>
                <h3 class="card-title">
                  <span class="status-dot warning"></span>
                  <span>Discovered Unbound Slaves (Live Bus Listener)</span>
                </h3>
                <p class="card-desc">Microcontrollers announcing factory ANN packets on RS-422 serial or Wi-Fi mesh</p>
              </div>
              <button class="btn btn-secondary btn-sm" onclick="fetchPendingNodes()">Refresh Bus</button>
            </div>
            <div id="pendingTable">
              <div style="color:var(--text-dim); font-size:12px; padding:10px 0;">No unprovisioned devices detected on bus.</div>
            </div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 3: AUTOMATIONS (RULES ENGINE) -->
        <!-- ========================================================================= -->
        <section id="viewRules" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Automation Rules Engine</h3>
                <p class="card-desc">Event-driven logic evaluated locally by Master supervisor. Triggers target actuators upon threshold breach.</p>
              </div>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-sm" onclick="openAddRuleModal()">+ Add Rule</button>
                <button class="btn btn-secondary btn-sm" onclick="clearAllRules()">Clear All Rules</button>
              </div>
            </div>
            <div id="rulesList"><div style="color:var(--text-dim);">Loading automation rules...</div></div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 4: SCHEDULES (EEPROM STANDALONE) -->
        <!-- ========================================================================= -->
        <section id="viewSchedules" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Downtime-Safe Standalone Schedules</h3>
                <p class="card-desc">Schedules run directly inside slave microcontroller on-chip EEPROM. Operates autonomously even if Master hub is disconnected.</p>
              </div>
              <div style="display:flex; align-items:center; gap:8px;">
                <label style="margin:0; font-size:11px;">Target Node:</label>
                <select id="schedNodeSelect" onchange="loadNodeSchedules(this.value)" style="width:160px; padding:4px 8px; font-size:11px;"></select>
              </div>
            </div>

            <div id="schedulesContainer" style="margin-bottom:16px;">
              <div style="color:var(--text-dim);">Select a node to inspect EEPROM standalone schedules.</div>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:14px; border-top:1px solid rgba(255,255,255,0.06);">
              <button class="btn btn-secondary btn-sm" onclick="addScheduleRow()">+ Add Daily Schedule</button>
              <button class="btn btn-sm" onclick="saveActiveNodeSchedules()">Save &amp; Push to Slave EEPROM</button>
            </div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 5: USERS & RBAC -->
        <!-- ========================================================================= -->
        <section id="viewUsers" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">User Accounts & Access Control (RBAC)</h3>
                <p class="card-desc">Manage accounts, member switches, and guest dashboards with SHA-256 tokens</p>
              </div>
              <button class="btn btn-sm" onclick="openAddUserModal()">+ Add User</button>
            </div>
            <div id="usersList"><div style="color:var(--text-dim);">Loading users...</div></div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 6: SETTINGS (WIFI STA & CLOUD BROKER) -->
        <!-- ========================================================================= -->
        <section id="viewSettings" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Home Wi-Fi Network (Client STA Mode)</h3>
                <p class="card-desc">Connect Master Hub to your home router for local LAN web access</p>
              </div>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px;">
              <div>
                <label>Home Wi-Fi SSID</label>
                <input type="text" id="cfgStaSSID" placeholder="Home Wi-Fi Name">
              </div>
              <div>
                <label>Wi-Fi Password</label>
                <input type="password" id="cfgStaPass" placeholder="Leave unchanged or enter new">
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Cloud MQTT Bridge</h3>
                <p class="card-desc">Optional TLS MQTT bridge for mobile app remote access beyond local LAN</p>
              </div>
              <label style="display:flex; align-items:center; gap:8px; margin:0; cursor:pointer;">
                <input type="checkbox" id="cfgMqttEn" style="width:auto;">
                <span style="font-size:11px; font-weight:600;">Enable Cloud Bridge</span>
              </label>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px;">
              <div>
                <label>MQTT Broker Host</label>
                <input type="text" id="cfgMqttBroker" placeholder="e.g. broker.emqx.io">
              </div>
              <div>
                <label>Broker Port</label>
                <input type="number" id="cfgMqttPort" value="8883">
              </div>
              <div>
                <label>Home Mesh ID</label>
                <input type="text" id="cfgMqttHomeId" placeholder="home_1">
              </div>
              <div>
                <label>Broker Username</label>
                <input type="text" id="cfgMqttUser" placeholder="Optional">
              </div>
              <div>
                <label>Broker Password</label>
                <input type="password" id="cfgMqttPass" placeholder="Optional">
              </div>
            </div>
            <div style="margin-top:18px; text-align:right;">
              <button class="btn" onclick="saveSystemSettings()">Save System Settings</button>
            </div>
          </div>
        </section>

        <!-- ========================================================================= -->
        <!-- TAB 7: ACCOUNT & DIAGNOSTICS -->
        <!-- ========================================================================= -->
        <section id="viewAccount" style="display:none;">
          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">User Profile & Password</h3>
                <p class="card-desc">Signed-in account credentials & roles</p>
              </div>
              <span class="badge badge-success" id="accountRoleBadge">ADMIN</span>
            </div>
            <div style="display:flex; flex-direction:column; gap:12px; max-width:320px;">
              <div>
                <label>Account Username</label>
                <div style="font-size:14px; font-weight:700;" id="accountUserDisplay">admin</div>
              </div>
              <div>
                <label>New Password</label>
                <input type="password" id="accountNewPass" placeholder="Enter new password">
              </div>
              <button class="btn btn-sm" onclick="submitAccountPassChange()">Update Password</button>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <h3 class="card-title">Master Supervisor Hardware Diagnostics</h3>
                <p class="card-desc">System health, Flash partition layout, and memory status</p>
              </div>
            </div>
            <div class="node-hardware-strip" style="grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));">
              <div class="hw-prop"><span class="hw-lbl">Hardware Chip</span><span class="hw-val" id="diagChip">ESP32 Supervisor</span></div>
              <div class="hw-prop"><span class="hw-lbl">RAM Usage</span><span class="hw-val" id="diagHeap">-- KB Free</span></div>
              <div class="hw-prop"><span class="hw-lbl">Flash Storage</span><span class="hw-val" id="diagLittleFS">-- KB (LittleFS)</span></div>
              <div class="hw-prop"><span class="hw-lbl">Uptime</span><span class="hw-val" id="diagUptime">-- s</span></div>
              <div class="hw-prop"><span class="hw-lbl">Firmware Spec</span><span class="hw-val" id="diagFirmware">v3.2.0 Decoupled</span></div>
            </div>
          </div>
        </section>

      </main>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- MODALS -->
  <!-- ========================================================================= -->

  <!-- BIND MODAL -->
  <div id="bindModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card">
      <div class="modal-head">
        <h4 class="modal-title">Provision &amp; Bind Unbound Slave</h4>
        <button class="btn btn-secondary btn-sm" onclick="closeBindModal()">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">
        Assign a persistent Node ID to hardware MAC: <code id="bindMacDisplay" style="color:var(--text); font-family:var(--font-mono);"></code>
      </div>

      <div style="display:flex; flex-direction:column; gap:12px;">
        <div>
          <label>Assigned Node ID</label>
          <input type="text" id="bindNodeId" placeholder="e.g. N01 or N01-esp32c3">
        </div>
        <div>
          <label>Friendly Name</label>
          <input type="text" id="bindNodeName" placeholder="e.g. Living Room Node">
        </div>

        <div style="padding:12px; background:rgba(0,0,0,0.2); border:1px solid var(--card-border); border-radius:var(--radius-sm); margin-top:4px;">
          <label style="display:flex; align-items:center; gap:8px; margin:0; cursor:pointer;">
            <input type="checkbox" id="bindApEnable" onchange="toggleBindApFields()" style="width:auto;">
            <span style="font-size:11px; font-weight:600;">Enable Downstream SoftAP Bridge</span>
          </label>
          <div id="bindApFields" style="display:none; margin-top:10px; display:flex; flex-direction:column; gap:8px;">
            <div>
              <label>Downstream SSID</label>
              <input type="text" id="bindApSsid" placeholder="e.g. MiniHA_N01">
            </div>
            <div>
              <label>Downstream Password</label>
              <input type="password" id="bindApPass" placeholder="Min 8 chars (or leave empty for open)">
            </div>
            <label style="display:flex; align-items:center; gap:8px; margin-top:4px; font-size:11px; cursor:pointer;">
              <input type="checkbox" id="bindApHidden" style="width:auto;">
              <span>Hide Network (Hidden SSID)</span>
            </label>
          </div>
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closeBindModal()">Cancel</button>
        <button class="btn" onclick="submitBindNode()">Bind Device</button>
      </div>
    </div>
  </div>

  <!-- CONFIGURE WI-FI AP BRIDGE MODAL -->
  <div id="apModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card">
      <div class="modal-head">
        <h4 class="modal-title" id="apModalTitle">Configure Wi-Fi AP Bridge</h4>
        <button class="btn btn-secondary btn-sm" onclick="closeApModal()">&times;</button>
      </div>
      <div style="font-size:12px; color:var(--text-muted); margin-bottom:14px; line-height:1.4;">
        When enabled, this wired slave broadcasts a local Wi-Fi Access Point so nearby wireless slaves can route transparently over RS-422.
      </div>

      <div style="display:flex; flex-direction:column; gap:12px;">
        <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
          <input type="checkbox" id="apModalEnable" onchange="toggleApModalFields()" style="width:auto;">
          <span style="font-size:12px; font-weight:600;">ENABLE DOWNSTREAM SOFTAP BRIDGE</span>
        </label>

        <div id="apModalFieldsWrap" style="display:flex; flex-direction:column; gap:10px;">
          <div>
            <label>Downstream Wi-Fi SSID</label>
            <input type="text" id="apModalSsid" placeholder="e.g. MiniHA_AP_N01">
          </div>
          <div>
            <label>Downstream Password</label>
            <input type="text" id="apModalPass" placeholder="Min 8 characters (or leave empty for open)">
          </div>
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
            <input type="checkbox" id="apModalHidden" style="width:auto;">
            <span style="font-size:11px; color:var(--text-muted);">Hide Network (Do not broadcast SSID)</span>
          </label>
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closeApModal()">Cancel</button>
        <button class="btn" onclick="submitApModal()">Save &amp; Push to Slave</button>
      </div>
    </div>
  </div>

  <!-- CONFIGURE COMPONENTS MODAL -->
  <div id="compModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card" style="max-width:700px;">
      <div class="modal-head">
        <div>
          <h4 class="modal-title" id="compModalTitle">Configure Peripherals</h4>
          <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);" id="compModalChip">Chip: ESP32-C3</div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="closeComponentModal()">&times;</button>
      </div>

      <div id="compRowsContainer" style="display:flex; flex-direction:column; gap:10px; margin-bottom:14px;">
        <!-- Dynamic Component Rows -->
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; padding-top:10px; border-top:1px solid var(--card-border);">
        <button class="btn btn-secondary btn-sm" onclick="addNewComponentRow()">+ Add Peripheral Component</button>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-secondary" onclick="closeComponentModal()">Cancel</button>
          <button class="btn" onclick="saveComponentModal()">Save &amp; Push to Slave</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ADD RULE MODAL -->
  <div id="ruleModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card">
      <div class="modal-head">
        <h4 class="modal-title" id="ruleModalTitle">Add Automation Rule</h4>
        <button class="btn btn-secondary btn-sm" onclick="closeRuleModal()">&times;</button>
      </div>
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div>
          <label>Rule Name</label>
          <input type="text" id="ruleNameInput" placeholder="e.g. Tank Overflow Auto-Off">
        </div>

        <div style="padding:10px; background:rgba(0,0,0,0.2); border:1px solid var(--card-border); border-radius:var(--radius-sm);">
          <strong style="font-size:11px; text-transform:uppercase; color:var(--primary); display:block; margin-bottom:8px;">IF Condition</strong>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px;">
            <div>
              <label>Node</label>
              <select id="ruleCondNode" onchange="updateRuleCondKeys(this.value)"></select>
            </div>
            <div>
              <label>Variable / Key</label>
              <select id="ruleCondKey"></select>
            </div>
          </div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
            <div>
              <label>Operator</label>
              <select id="ruleCondOp">
                <option value=">">&gt; (Greater than)</option>
                <option value="<">&lt; (Less than)</option>
                <option value="==">== (Equal to)</option>
                <option value="!=">!= (Not equal)</option>
              </select>
            </div>
            <div>
              <label>Threshold Value</label>
              <input type="number" id="ruleCondVal" step="any" value="85">
            </div>
          </div>
        </div>

        <div style="padding:10px; background:rgba(0,0,0,0.2); border:1px solid var(--card-border); border-radius:var(--radius-sm);">
          <strong style="font-size:11px; text-transform:uppercase; color:var(--success); display:block; margin-bottom:8px;">THEN Action</strong>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px;">
            <div>
              <label>Target Node</label>
              <select id="ruleActTarget" onchange="updateRuleActSlots(this.value)"></select>
            </div>
            <div>
              <label>Actuator / Peripheral</label>
              <select id="ruleActSlot"></select>
            </div>
          </div>
          <div>
            <label>Action Command</label>
            <select id="ruleActState">
              <option value="1">Turn ON</option>
              <option value="0">Turn OFF</option>
            </select>
          </div>
        </div>
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closeRuleModal()">Cancel</button>
        <button class="btn" onclick="saveRuleFromModal()">Save Rule</button>
      </div>
    </div>
  </div>

  <!-- CHANGE PASSWORD MODAL -->
  <div id="passModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card" style="max-width:380px;">
      <div class="modal-head">
        <h4 class="modal-title">Change Password</h4>
        <button class="btn btn-secondary btn-sm" onclick="closePassModal()">&times;</button>
      </div>
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div>
          <label>New Password</label>
          <input type="password" id="modalNewPass" placeholder="Enter new password">
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closePassModal()">Cancel</button>
        <button class="btn" onclick="submitModalPassChange()">Update Password</button>
      </div>
    </div>
  </div>

  <!-- ADD USER MODAL -->
  <div id="addUserModal" class="modal-backdrop" style="display:none;">
    <div class="modal-card" style="max-width:380px;">
      <div class="modal-head">
        <h4 class="modal-title">Add User Account</h4>
        <button class="btn btn-secondary btn-sm" onclick="closeAddUserModal()">&times;</button>
      </div>
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div>
          <label>Username</label>
          <input type="text" id="addUserName" placeholder="Username">
        </div>
        <div>
          <label>Password</label>
          <input type="password" id="addUserPass" placeholder="Password">
        </div>
        <div>
          <label>Role</label>
          <select id="addUserRole">
            <option value="member">Member (Can control switches)</option>
            <option value="guest">Guest (Read-only)</option>
            <option value="admin">Admin (Full access)</option>
          </select>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-secondary" onclick="closeAddUserModal()">Cancel</button>
        <button class="btn" onclick="submitAddUser()">Create Account</button>
      </div>
    </div>
  </div>

  <!-- TOAST NOTIFICATION -->
  <div id="toast"></div>

  <!-- ========================================================================= -->
  <!-- JAVASCRIPT APPLICATION CORE -->
  <!-- ========================================================================= -->
  <script>
    let currentSession = { loggedIn: false, role: 'none' };
    let nodesCache = [];
    let liveStates = {};
    let pendingNodesCache = [];
    let currentSchedules = [];
    let activeSchedNodeId = '';
    let editingRuleIdx = -1;

    // Navigation Switcher
    function switchNavTab(tab) {
      const tabs = ['dashboard', 'nodes', 'rules', 'schedules', 'users', 'settings', 'account'];
      tabs.forEach(t => {
        const navEl = document.getElementById('nav-' + t);
        const viewEl = document.getElementById('view' + t.charAt(0).toUpperCase() + t.slice(1));
        if (navEl) {
          if (t === tab) navEl.classList.add('active');
          else navEl.classList.remove('active');
        }
        if (viewEl) {
          viewEl.style.display = (t === tab) ? 'block' : 'none';
        }
      });

      const titles = {
        dashboard: ['Home Dashboard', 'Unified controls, sensors & mesh telemetry'],
        nodes: ['Hardware Nodes & Provisioning', 'Configured slaves, peripherals & real-time discovery'],
        rules: ['Automations Engine', 'Local event-driven logic evaluated by Master hub'],
        schedules: ['Downtime-Safe Schedules', 'Autonomous EEPROM daily schedules per slave'],
        users: ['User Accounts & RBAC', 'Manage accounts, member switches & guest dashboards'],
        settings: ['System Settings', 'Home Wi-Fi STA client & optional Cloud MQTT bridge'],
        account: ['Account & Diagnostics', 'User security, Flash partition health & heap diagnostics']
      };
      if (titles[tab]) {
        document.getElementById('pageTitle').innerText = titles[tab][0];
        document.getElementById('pageSub').innerText = titles[tab][1];
      }

      if (tab === 'account') loadAccountDiagnostics();
      if (tab === 'rules') loadRules();
      if (tab === 'schedules') loadSchedulesTab();
      if (tab === 'users') loadUsers();
      if (tab === 'settings') loadSettings();
    }

    // Authentication & Session
    async function checkSession() {
      try {
        const res = await fetch('/api/session');
        const data = await res.json();
        currentSession = data;
        if (data.loggedIn) {
          localStorage.setItem('miniha_logged_in', '1');
          document.documentElement.classList.remove('not-auth');
          document.documentElement.classList.add('is-auth');
          document.getElementById('loginView').style.display = 'none';
          document.getElementById('hubApp').style.display = 'flex';

          document.getElementById('sidebarUsername').innerText = data.user || 'admin';
          document.getElementById('sidebarRoleBadge').innerText = (data.role || 'ADMIN').toUpperCase();
          
          const isAdmin = (data.role === 'admin');
          if (isAdmin) {
            document.body.classList.add('role-admin');
          } else {
            document.body.classList.remove('role-admin');
          }
          document.querySelectorAll('.admin-only').forEach(el => el.style.display = isAdmin ? '' : 'none');
          document.getElementById('defaultPassBanner').style.display = (isAdmin && data.isDefault) ? 'block' : 'none';

          // Sync browser real-world time to Master & Slaves (downtime-safe local RTC)
          fetch('/api/time', { method: 'POST', body: String(Math.floor(Date.now() / 1000)) }).catch(()=>{});

          refreshData();
        } else {
          localStorage.removeItem('miniha_logged_in');
          document.documentElement.classList.remove('is-auth');
          document.documentElement.classList.add('not-auth');
          document.getElementById('loginView').style.display = 'flex';
          document.getElementById('hubApp').style.display = 'none';
        }
      } catch (e) {
        console.error(e);
        localStorage.removeItem('miniha_logged_in');
        document.documentElement.classList.remove('is-auth');
        document.documentElement.classList.add('not-auth');
        document.getElementById('loginView').style.display = 'flex';
        document.getElementById('hubApp').style.display = 'none';
      }
    }

    async function handleLogin(e) {
      if (e) e.preventDefault();
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
          localStorage.setItem('miniha_logged_in', '1');
          showToast('Signed in successfully', 'success');
          checkSession();
        } else {
          showToast(data.error || 'Login failed', 'error');
        }
      } catch (err) {
        showToast('Connection failed', 'error');
      }
    }

    async function handleLogout() {
      await fetch('/api/logout', { method: 'POST' });
      localStorage.removeItem('miniha_logged_in');
      document.getElementById('loginUser').value = '';
      document.getElementById('loginPass').value = '';
      checkSession();
    }

    function togglePassVisibilityLocal() {
      const p = document.getElementById('loginPass');
      if (p) p.type = (p.type === 'password') ? 'text' : 'password';
    }

    // Real-Time Telemetry & Data Polling
    async function refreshData() {
      try {
        const [nRes, sRes] = await Promise.all([fetch('/api/nodes'), fetch('/api/state')]);
        if (nRes.ok) {
          const nData = await nRes.json();
          nodesCache = nData.nodes || [];
        }
        if (sRes.ok) {
          const sData = await sRes.json();
          liveStates = {};
          (sData.nodes || []).forEach(n => {
            liveStates[n.id] = n;
          });
        }

        renderDashboard();
        renderNodesCards();
        fetchPendingNodes();
        updateRtcClock();
      } catch (e) {
        console.warn('Refresh error:', e);
      }
    }

    function updateRtcClock() {
      const d = new Date();
      document.getElementById('hubRtcClock').textContent = d.toLocaleTimeString();
    }

    // =========================================================================
    // TAB 1: RENDER UNIFIED DASHBOARD
    // =========================================================================
    function renderDashboard() {
      let totalNodes = nodesCache.length;
      let onlineNodes = 0;
      let activeRelays = 0;
      let latestTankLevel = null;
      let latestTemp = null;
      let latestHum = null;

      let relaysHtml = '';
      let sensorsHtml = '';

      nodesCache.forEach(node => {
        const state = liveStates[node.id] || { components: {}, relays: [], lastSeen: 999999, hasSeen: false };
        const isOnline = (state.hasSeen && state.lastSeen <= 8);
        if (isOnline) onlineNodes++;

        const comps = node.components || [];
        comps.forEach((c, idx) => {
          const compId = c.id || ('comp' + idx);
          const compName = c.name || compId;
          const cType = parseInt(c.type) || 1;
          const compState = (state.components && state.components[compId]) ? state.components[compId] : null;

          if (cType === 1) { // Relay Actuator
            let isOn = false;
            if (compState && compState.v1 !== undefined) {
              isOn = (compState.v1 == 1);
            } else if (state.relays && state.relays[idx] !== undefined) {
              isOn = (state.relays[idx] == 1);
            }
            if (isOn && isOnline) activeRelays++;

            const canControl = (currentSession.role === 'admin' || currentSession.role === 'member');
            relaysHtml += `
              <div class="control-card">
                <div class="control-card-header">
                  <div>
                    <div class="control-name">${escapeHtml(compName)}</div>
                    <div class="control-sub">${escapeHtml(node.name || node.id)} &bull; GPIO ${c.pin1}</div>
                  </div>
                  <span class="badge ${isOn ? 'badge-success' : ''}">${isOn ? 'ON' : 'OFF'}</span>
                </div>
                <div class="toggle-switch-wrap">
                  <span class="toggle-status-text ${isOn ? 'on' : 'off'}">${isOn ? 'ENERGIZED' : 'STANDBY'}</span>
                  <button class="switch-btn ${isOn ? 'active' : ''}" ${canControl ? '' : 'disabled'} onclick="toggleComponent('${node.id}', '${compId}', ${isOn})" title="Toggle ${escapeHtml(compName)}">
                    <span class="switch-thumb"></span>
                  </button>
                </div>
              </div>`;
          } else if (cType === 2) { // Ultrasonic Sensor
            let dist = (compState && compState.v1 !== undefined) ? compState.v1 : state.dist;
            let level = (compState && compState.v2 !== undefined) ? compState.v2 : -1;
            if (level === -1 && dist >= 0) {
              level = Math.max(0, Math.min(100, Math.round((1 - (dist / 200)) * 100)));
            }
            if (level >= 0) latestTankLevel = level;

            sensorsHtml += `
              <div class="control-card">
                <div class="control-card-header">
                  <div>
                    <div class="control-name">${escapeHtml(compName)}</div>
                    <div class="control-sub">${escapeHtml(node.name || node.id)} &bull; Ultrasonic (Trig ${c.pin1}, Echo ${c.pin2})</div>
                  </div>
                  <span class="badge badge-primary">Liquid Gauge</span>
                </div>
                <div class="tank-visual-wrap">
                  <div class="tank-pillar">
                    <div class="tank-fluid" style="height:${level >= 0 ? level : 0}%;"></div>
                  </div>
                  <div class="tank-metrics">
                    <div class="tank-percent">${level >= 0 ? level : '--'}%</div>
                    <div class="tank-dist">${dist >= 0 ? dist + ' cm distance' : 'Sensor idle'}</div>
                    <div style="font-size:10px; color:var(--text-dim); margin-top:2px;">Target: [${compId}.level]</div>
                  </div>
                </div>
              </div>`;
          } else if (cType === 3) { // DHT Sensor
            let t = (compState && compState.v1 !== undefined) ? compState.v1 : state.temp;
            let h = (compState && compState.v2 !== undefined) ? compState.v2 : state.hum;
            if (t > 0) latestTemp = t;
            if (h > 0) latestHum = h;

            sensorsHtml += `
              <div class="control-card">
                <div class="control-card-header">
                  <div>
                    <div class="control-name">${escapeHtml(compName)}</div>
                    <div class="control-sub">${escapeHtml(node.name || node.id)} &bull; DHT Sensor (GPIO ${c.pin1})</div>
                  </div>
                  <span class="badge badge-warning">Climate</span>
                </div>
                <div class="climate-visual-wrap">
                  <div class="climate-box">
                    <div class="climate-val temp">${t > 0 ? t.toFixed(1) : '--'}&deg;C</div>
                    <div class="climate-lbl">Temperature</div>
                  </div>
                  <div class="climate-box">
                    <div class="climate-val hum">${h > 0 ? Math.round(h) : '--'}%</div>
                    <div class="climate-lbl">Humidity</div>
                  </div>
                </div>
              </div>`;
          } else if (cType === 4 || cType === 5) { // Button / Touch
            let bVal = (compState && compState.v1 !== undefined) ? compState.v1 : 0;
            sensorsHtml += `
              <div class="control-card">
                <div class="control-card-header">
                  <div>
                    <div class="control-name">${escapeHtml(compName)}</div>
                    <div class="control-sub">${escapeHtml(node.name || node.id)} &bull; ${cType === 5 ? 'Touch Pin' : 'Digital Button'} (GPIO ${c.pin1})</div>
                  </div>
                  <span class="badge">${cType === 5 ? 'Touch' : 'Button'}</span>
                </div>
                <div style="margin-top:10px; display:flex; align-items:center; gap:8px;">
                  <span class="status-dot ${bVal == 1 ? 'online' : ''}"></span>
                  <span style="font-size:12px; font-weight:600; font-family:var(--font-mono);">${bVal == 1 ? 'PRESSED / ACTIVE' : 'RELEASED'}</span>
                </div>
              </div>`;
          } else if (cType === 6) { // Analog ADC
            let aVal = (compState && compState.v1 !== undefined) ? compState.v1 : 0;
            sensorsHtml += `
              <div class="control-card">
                <div class="control-card-header">
                  <div>
                    <div class="control-name">${escapeHtml(compName)}</div>
                    <div class="control-sub">${escapeHtml(node.name || node.id)} &bull; Analog ADC (GPIO ${c.pin1})</div>
                  </div>
                  <span class="badge badge-primary">ADC</span>
                </div>
                <div style="margin-top:8px;">
                  <div style="font-size:18px; font-weight:700; color:#38bdf8; font-family:var(--font-mono);">${Math.round(aVal)}</div>
                  <div style="font-size:10px; color:var(--text-dim); margin-top:2px;">Raw 12-bit ADC reading [${compId}.val]</div>
                </div>
              </div>`;
          }
        });
      });

      // Update KPI Banner
      document.getElementById('kpiNodesOnline').textContent = `${onlineNodes} / ${totalNodes} Online`;
      document.getElementById('kpiActiveRelays').textContent = `${activeRelays} ON`;
      document.getElementById('kpiTankLevel').textContent = (latestTankLevel !== null) ? `${latestTankLevel}%` : '-- %';
      document.getElementById('kpiClimate').textContent = (latestTemp !== null) ? `${latestTemp.toFixed(1)}°C` : '-- °C';

      const relaysGrid = document.getElementById('dashboardRelaysGrid');
      if (relaysGrid) {
        relaysGrid.innerHTML = relaysHtml || '<div style="color:var(--text-dim); padding:10px 0;">No actuators configured yet. Use Hardware Nodes tab to configure peripherals.</div>';
      }

      const sensorsGrid = document.getElementById('dashboardSensorsGrid');
      if (sensorsGrid) {
        sensorsGrid.innerHTML = sensorsHtml || '<div style="color:var(--text-dim); padding:10px 0;">No sensors active.</div>';
      }
    }

    // Toggle Component Action
    async function toggleComponent(nodeId, compId, currentState) {
      const targetState = currentState ? 0 : 1;
      try {
        await fetch('/api/control', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: nodeId, comp: compId, val: targetState })
        });
        showToast('Command dispatched', 'info');
        refreshData();
      } catch (e) {
        showToast('Control dispatch failed', 'error');
      }
    }

    // =========================================================================
    // TAB 2: RENDER HARDWARE NODES CARDS & REAL-TIME DISCOVERY
    // =========================================================================
    function renderNodesCards() {
      const container = document.getElementById('nodesCardsContainer');
      if (!container) return;

      if (!nodesCache || nodesCache.length === 0) {
        container.innerHTML = '<div style="color:var(--text-dim); padding:16px 0;">No slave hardware nodes bound yet. Bind discovered devices below.</div>';
        return;
      }

      let html = '';
      nodesCache.forEach(node => {
        const state = liveStates[node.id] || { relays: [], components: {}, lastSeen: 999999, hasSeen: false, freeHeap: 0 };
        
        let statusBadge = '';
        if (state.hasSeen && state.lastSeen <= 8) {
          statusBadge = '<span class="badge badge-success"><span class="status-dot online"></span>Online</span>';
        } else if (state.hasSeen && state.lastSeen <= 30) {
          statusBadge = `<span class="badge badge-warning"><span class="status-dot warning"></span>${state.lastSeen}s ago</span>`;
        } else {
          statusBadge = '<span class="badge badge-danger"><span class="status-dot offline"></span>Offline</span>';
        }

        const compCount = (node.components && node.components.length) ? node.components.length : 0;
        const ramDisplay = state.freeHeap ? (Math.round(state.freeHeap / 1024) + ' KB Free') : 'ESP Active';
        const apStatus = node.ap_enabled ? (node.ap_ssid + (node.ap_hidden ? ' (Hidden)' : '')) : 'Disabled';

        html += `
          <div class="node-card">
            <div class="node-card-head">
              <div>
                <div class="node-meta-badges">
                  <strong style="font-size:15px; color:var(--text);">${escapeHtml(node.name || node.id)}</strong>
                  <span class="badge" style="font-family:var(--font-mono);">${escapeHtml(node.id)}</span>
                  ${statusBadge}
                </div>
              </div>
              <div class="node-actions-bar">
                <button class="btn btn-secondary btn-sm admin-only" onclick="openComponentModal('${node.id}')">Configure Components</button>
                <button class="btn btn-secondary btn-sm admin-only" onclick="openApModal('${node.id}')">Wi-Fi AP Bridge</button>
                <button class="btn btn-secondary btn-sm admin-only" onclick="openScheduleTabForNode('${node.id}')">Schedules</button>
                <button class="btn btn-danger btn-sm admin-only" onclick="deleteNode('${node.id}')">Delete</button>
              </div>
            </div>

            <div class="node-hardware-strip">
              <div class="hw-prop"><span class="hw-lbl">Hardware Chip</span><span class="hw-val">${escapeHtml(node.chip || 'ESP32/ESP8266')}</span></div>
              <div class="hw-prop"><span class="hw-lbl">RAM Usage</span><span class="hw-val">${ramDisplay}</span></div>
              <div class="hw-prop"><span class="hw-lbl">Flash / Storage</span><span class="hw-val">EEPROM Protected</span></div>
              <div class="hw-prop"><span class="hw-lbl">Hardware MAC</span><span class="hw-val">${escapeHtml(node.mac || '--')}</span></div>
              <div class="hw-prop"><span class="hw-lbl">Peripherals</span><span class="hw-val">${compCount} active</span></div>
              <div class="hw-prop"><span class="hw-lbl">AP Bridge</span><span class="hw-val">${escapeHtml(apStatus)}</span></div>
            </div>
          </div>`;
      });

      container.innerHTML = html;
    }

    // Real-Time Discovery Polling
    async function fetchPendingNodes() {
      if (currentSession.role !== 'admin') return;
      try {
        const res = await fetch('/api/pending');
        if (res.ok) {
          const data = await res.json();
          pendingNodesCache = data.pending || [];
          renderPendingTable();
        }
      } catch (e) {}
    }

    function renderPendingTable() {
      const container = document.getElementById('pendingTable');
      if (!container) return;

      // Filter out any devices that are already bound
      const boundMacs = new Set((nodesCache || []).map(n => n.mac));
      const unassigned = (pendingNodesCache || []).filter(p => !boundMacs.has(p.mac));

      if (unassigned.length === 0) {
        container.innerHTML = '<div style="color:var(--text-dim); font-size:12px; padding:10px 0;">No unprovisioned devices detected on bus. (Unplugged devices auto-prune in 12s)</div>';
        return;
      }

      let html = `
        <table>
          <thead>
            <tr>
              <th>MAC Address</th>
              <th>Microcontroller</th>
              <th>Safe GPIO Pins</th>
              <th style="text-align:right;">Action</th>
            </tr>
          </thead>
          <tbody>`;

      unassigned.forEach(p => {
        html += `
          <tr>
            <td style="font-family:var(--font-mono); font-weight:600;">${escapeHtml(p.mac)}</td>
            <td><span class="badge badge-primary">${escapeHtml(p.chip || 'ESP32')}</span></td>
            <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim);">${escapeHtml(p.gpios || '--')}</td>
            <td style="text-align:right;">
              <button class="btn btn-sm" onclick="openBindModal('${p.mac}', '${p.chip}')">Bind</button>
            </td>
          </tr>`;
      });

      html += '</tbody></table>';
      container.innerHTML = html;
    }

    // =========================================================================
    // MODAL HANDLERS & AP BRIDGE PROVISIONING
    // =========================================================================

    // Bind Modal
    let pendingBindMac = '';
    function openBindModal(mac, chip) {
      pendingBindMac = mac;
      document.getElementById('bindMacDisplay').textContent = mac;
      const nextIdx = nodesCache.length + 1;
      document.getElementById('bindNodeId').value = 'N0' + nextIdx;
      document.getElementById('bindNodeName').value = 'Node ' + nextIdx + ' (' + (chip || 'ESP') + ')';
      document.getElementById('bindApEnable').checked = false;
      document.getElementById('bindApSsid').value = 'MiniHA_N0' + nextIdx;
      document.getElementById('bindApPass').value = '';
      document.getElementById('bindApHidden').checked = false;
      toggleBindApFields();
      document.getElementById('bindModal').style.display = 'flex';
    }
    function closeBindModal() {
      document.getElementById('bindModal').style.display = 'none';
    }
    function toggleBindApFields() {
      const en = document.getElementById('bindApEnable').checked;
      document.getElementById('bindApFields').style.display = en ? 'flex' : 'none';
    }
    async function submitBindNode() {
      const nodeId = document.getElementById('bindNodeId').value.trim();
      const nodeName = document.getElementById('bindNodeName').value.trim();
      if (!nodeId) return showToast('Node ID is required', 'error');

      const apEnabled = document.getElementById('bindApEnable').checked;
      const apSsid = document.getElementById('bindApSsid').value.trim();
      const apPass = document.getElementById('bindApPass').value;
      const apHidden = document.getElementById('bindApHidden').checked;

      const res = await fetch('/api/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mac: pendingBindMac,
          id: nodeId,
          name: nodeName,
          ap_enabled: apEnabled,
          ap_ssid: apSsid,
          ap_pass: apPass,
          ap_hidden: apHidden
        })
      });

      if (res.ok) {
        showToast(`Node '${nodeId}' bound successfully!`, 'success');
        closeBindModal();
        refreshData();
      } else {
        showToast('Failed to bind node', 'error');
      }
    }

    // AP Bridge Modal
    let activeApNodeId = '';
    function openApModal(nodeId) {
      activeApNodeId = nodeId;
      const node = nodesCache.find(n => n.id === nodeId);
      document.getElementById('apModalTitle').textContent = `Configure Wi-Fi AP Bridge: ${node ? (node.name || node.id) : nodeId}`;
      const en = node && node.ap_enabled;
      document.getElementById('apModalEnable').checked = en;
      document.getElementById('apModalSsid').value = (node && node.ap_ssid) ? node.ap_ssid : ('MiniHA_AP_' + nodeId);
      document.getElementById('apModalPass').value = (node && node.ap_pass) ? node.ap_pass : '';
      document.getElementById('apModalHidden').checked = node && node.ap_hidden;
      toggleApModalFields();
      document.getElementById('apModal').style.display = 'flex';
    }
    function closeApModal() {
      document.getElementById('apModal').style.display = 'none';
    }
    function toggleApModalFields() {
      const en = document.getElementById('apModalEnable').checked;
      document.getElementById('apModalFieldsWrap').style.display = en ? 'flex' : 'none';
    }
    async function submitApModal() {
      const apEnabled = document.getElementById('apModalEnable').checked;
      const apSsid = document.getElementById('apModalSsid').value.trim();
      const apPass = document.getElementById('apModalPass').value;
      const apHidden = document.getElementById('apModalHidden').checked;

      const res = await fetch('/api/nodes/ap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: activeApNodeId,
          ap_enabled: apEnabled,
          ap_ssid: apSsid,
          ap_pass: apPass,
          ap_hidden: apHidden
        })
      });

      if (res.ok) {
        showToast('AP Bridge config dispatched to slave', 'success');
        closeApModal();
        refreshData();
      } else {
        showToast('Failed to save AP bridge config', 'error');
      }
    }

    // Delete Node
    async function deleteNode(nodeId) {
      if (!confirm(`Are you sure you want to delete and unbind node '${nodeId}'?`)) return;
      const res = await fetch('/api/nodes/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: nodeId })
      });
      if (res.ok) {
        showToast('Node deleted successfully', 'success');
        refreshData();
      } else {
        showToast('Failed to delete node', 'error');
      }
    }

    // Component Modal
    let activeCompNodeId = '';
    let currentModalComponents = [];
    let activeSafePins = [0, 1, 3, 4, 5, 6, 7, 8, 10, 20, 21];

    function openComponentModal(nodeId) {
      activeCompNodeId = nodeId;
      const node = nodesCache.find(n => n.id === nodeId);
      document.getElementById('compModalTitle').textContent = `Configure Peripherals: ${node ? (node.name || node.id) : nodeId}`;
      
      const chip = (node && node.chip) ? node.chip.toUpperCase() : 'ESP32C3';
      document.getElementById('compModalChip').textContent = `Chip Architecture: ${chip}`;

      if (chip.includes('8266')) {
        activeSafePins = [4, 5, 12, 13, 14, 0, 2, 15, 16];
      } else if (chip.includes('C3')) {
        activeSafePins = [0, 1, 3, 4, 5, 6, 7, 8, 10, 20, 21];
      } else {
        activeSafePins = [4, 5, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33];
      }

      currentModalComponents = (node && node.components) ? JSON.parse(JSON.stringify(node.components)) : [];
      renderComponentModalRows();
      document.getElementById('compModal').style.display = 'flex';
    }

    function closeComponentModal() {
      document.getElementById('compModal').style.display = 'none';
    }

    function renderComponentModalRows() {
      const container = document.getElementById('compRowsContainer');
      if (currentModalComponents.length === 0) {
        container.innerHTML = '<div style="color:var(--text-dim); padding:10px 0;">No peripheral components assigned. Click "+ Add Peripheral Component" below.</div>';
        return;
      }

      let html = '';
      currentModalComponents.forEach((c, idx) => {
        const type = parseInt(c.type) || 1;
        const pin1 = c.pin1 !== undefined ? c.pin1 : 255;
        const pin2 = c.pin2 !== undefined ? c.pin2 : 255;

        html += `
          <div style="padding:12px; background:rgba(0,0,0,0.25); border:1px solid var(--card-border); border-radius:var(--radius-sm); display:grid; grid-template-columns:1fr 1.2fr 0.8fr 0.8fr 1fr auto; gap:8px; align-items:center;">
            <div>
              <label>Component Type</label>
              <select onchange="updateCompType(${idx}, this.value)" style="font-size:11px;">
                <option value="1" ${type===1?'selected':''}>Relay Actuator</option>
                <option value="2" ${type===2?'selected':''}>Ultrasonic (HC-SR04)</option>
                <option value="3" ${type===3?'selected':''}>DHT Temp/Humidity</option>
                <option value="4" ${type===4?'selected':''}>Digital Push Button</option>
                <option value="5" ${type===5?'selected':''}>Capacitive Touch</option>
                <option value="6" ${type===6?'selected':''}>Analog Sensor (ADC)</option>
              </select>
            </div>
            <div>
              <label>Friendly Name</label>
              <input type="text" value="${escapeHtml(c.name || ('Comp ' + (idx + 1)))}" onchange="currentModalComponents[${idx}].name=this.value.trim()" style="font-size:11px;">
            </div>
            <div>
              <label>Primary Pin</label>
              <select onchange="currentModalComponents[${idx}].pin1=parseInt(this.value)" style="font-size:11px;">
                ${renderPinOptions(pin1)}
              </select>
            </div>
            <div>
              <label>${type===2 ? 'Echo Pin' : 'Sec Pin'}</label>
              <select ${type===2 ? '' : 'disabled'} onchange="currentModalComponents[${idx}].pin2=parseInt(this.value)" style="font-size:11px;">
                <option value="255">None</option>
                ${renderPinOptions(pin2)}
              </select>
            </div>
            <div>
              <label>Entity Tag</label>
              <input type="text" value="${escapeHtml(c.id || ('comp' + idx))}" onchange="currentModalComponents[${idx}].id=this.value.trim()" style="font-size:11px;">
            </div>
            <div>
              <button class="btn btn-danger btn-sm" onclick="removeComponentRow(${idx})" style="padding:4px 8px; margin-top:14px;">&times;</button>
            </div>
          </div>`;
      });
      container.innerHTML = html;
    }

    function renderPinOptions(selectedPin) {
      let out = '';
      activeSafePins.forEach(p => {
        out += `<option value="${p}" ${p===selectedPin?'selected':''}>GPIO ${p}</option>`;
      });
      return out;
    }

    function updateCompType(idx, val) {
      currentModalComponents[idx].type = parseInt(val);
      renderComponentModalRows();
    }

    function addNewComponentRow() {
      const idx = currentModalComponents.length;
      const defPin = activeSafePins[idx % activeSafePins.length] || 0;
      currentModalComponents.push({
        type: 1,
        name: 'Relay ' + (idx + 1),
        id: 'relay' + (idx + 1),
        pin1: defPin,
        pin2: 255,
        flags: 0,
        param1: 0
      });
      renderComponentModalRows();
    }

    function removeComponentRow(idx) {
      currentModalComponents.splice(idx, 1);
      renderComponentModalRows();
    }

    async function saveComponentModal() {
      const res = await fetch('/api/nodes/components', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeCompNodeId, components: currentModalComponents })
      });
      if (res.ok) {
        showToast('Components saved & dispatched over bus', 'success');
        closeComponentModal();
        refreshData();
      } else {
        showToast('Failed to save components', 'error');
      }
    }

    // =========================================================================
    // AUTOMATIONS (RULES ENGINE)
    // =========================================================================
    async function loadRules() {
      try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        const rules = data.rules || [];
        const container = document.getElementById('rulesList');
        if (rules.length === 0) {
          container.innerHTML = '<div style="color:var(--text-dim); padding:10px 0;">No automation rules configured. Click "+ Add Rule" above to create event-driven logic.</div>';
          return;
        }

        let html = '';
        rules.forEach((r, idx) => {
          const c = r.cond || {};
          const a = r.act || {};
          html += `
            <div style="padding:14px; background:rgba(0,0,0,0.2); border:1px solid var(--card-border); border-radius:var(--radius-sm); margin-bottom:10px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
              <div>
                <strong style="font-size:13px; color:var(--text);">${escapeHtml(r.name || ('Rule #' + (idx + 1)))}</strong>
                <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-muted); margin-top:4px;">
                  IF <span style="color:#60a5fa;">[${escapeHtml(c.node || 'LOCAL')}.${escapeHtml(c.key || 'LVL')}]</span>
                  ${escapeHtml(c.op || '>')} <span style="color:#f59e0b;">${c.val}</span>
                  THEN <span style="color:#10b981;">[${escapeHtml(a.target || 'LOCAL')}.${escapeHtml(a.comp || ('slot' + (a.slot||0)))}] &rarr; ${a.state == 1 ? 'ON' : 'OFF'}</span>
                </div>
              </div>
              <div style="display:flex; gap:6px;">
                <button class="btn btn-secondary btn-sm" onclick="editRule(${idx})">Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteRule(${idx})">Delete</button>
              </div>
            </div>`;
        });
        container.innerHTML = html;
      } catch (e) {}
    }

    function openAddRuleModal() {
      editingRuleIdx = -1;
      document.getElementById('ruleModalTitle').textContent = 'Add Automation Rule';
      document.getElementById('ruleNameInput').value = 'Rule #' + (document.querySelectorAll('#rulesList > div').length + 1);
      populateRuleNodeSelectors();
      document.getElementById('ruleModal').style.display = 'flex';
    }

    function closeRuleModal() {
      document.getElementById('ruleModal').style.display = 'none';
    }

    function populateRuleNodeSelectors() {
      const condNode = document.getElementById('ruleCondNode');
      const actTarget = document.getElementById('ruleActTarget');
      condNode.innerHTML = '';
      actTarget.innerHTML = '';

      condNode.appendChild(new Option('LOCAL (Master)', 'LOCAL'));
      actTarget.appendChild(new Option('LOCAL (Master)', 'LOCAL'));

      nodesCache.forEach(n => {
        condNode.appendChild(new Option(n.name || n.id, n.id));
        actTarget.appendChild(new Option(n.name || n.id, n.id));
      });

      updateRuleCondKeys(condNode.value);
      updateRuleActSlots(actTarget.value);
    }

    function updateRuleCondKeys(nodeId) {
      const keySelect = document.getElementById('ruleCondKey');
      keySelect.innerHTML = '';
      keySelect.appendChild(new Option('Tank Level % (LVL)', 'LVL'));
      keySelect.appendChild(new Option('Temperature °C (TMP)', 'TMP'));
      keySelect.appendChild(new Option('Humidity % (HUM)', 'HUM'));
      keySelect.appendChild(new Option('Distance cm (dist)', 'dist'));

      const node = nodesCache.find(n => n.id === nodeId);
      if (node && node.components) {
        node.components.forEach(c => {
          if (c.id) keySelect.appendChild(new Option(c.name + ' [' + c.id + ']', c.id));
        });
      }
    }

    function updateRuleActSlots(nodeId) {
      const slotSelect = document.getElementById('ruleActSlot');
      slotSelect.innerHTML = '';
      const node = nodesCache.find(n => n.id === nodeId);
      if (node && node.components) {
        node.components.forEach((c, idx) => {
          if (c.type == 1) { // Relay
            slotSelect.appendChild(new Option(c.name || c.id || ('Relay ' + idx), c.id || idx));
          }
        });
      }
      if (slotSelect.options.length === 0) {
        slotSelect.appendChild(new Option('Relay 0 (Default)', 0));
      }
    }

    async function saveRuleFromModal() {
      const name = document.getElementById('ruleNameInput').value.trim();
      const condNode = document.getElementById('ruleCondNode').value;
      const condKey = document.getElementById('ruleCondKey').value;
      const condOp = document.getElementById('ruleCondOp').value;
      const condVal = parseFloat(document.getElementById('ruleCondVal').value) || 0;
      const actTarget = document.getElementById('ruleActTarget').value;
      const actSlot = document.getElementById('ruleActSlot').value;
      const actState = parseInt(document.getElementById('ruleActState').value) || 0;

      const ruleObj = {
        name: name,
        cond: { node: condNode, key: condKey, op: condOp, val: condVal },
        act: { target: actTarget, comp: actSlot, slot: parseInt(actSlot)||0, state: actState }
      };

      const res = await fetch('/api/rules');
      const data = await res.json();
      const rules = data.rules || [];

      if (editingRuleIdx >= 0 && editingRuleIdx < rules.length) {
        rules[editingRuleIdx] = ruleObj;
      } else {
        rules.push(ruleObj);
      }

      await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules })
      });

      showToast('Automation rule saved', 'success');
      closeRuleModal();
      loadRules();
    }

    async function deleteRule(idx) {
      if (!confirm('Delete this automation rule?')) return;
      const res = await fetch('/api/rules');
      const data = await res.json();
      const rules = data.rules || [];
      rules.splice(idx, 1);
      await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules })
      });
      showToast('Rule deleted', 'success');
      loadRules();
    }

    async function clearAllRules() {
      if (!confirm('Are you sure you want to delete ALL automation rules?')) return;
      await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: [] })
      });
      showToast('All rules cleared', 'success');
      loadRules();
    }

    // =========================================================================
    // DOWNTIME-SAFE EEPROM STANDALONE SCHEDULES
    // =========================================================================
    function openScheduleTabForNode(nodeId) {
      switchNavTab('schedules');
      const select = document.getElementById('schedNodeSelect');
      if (select) {
        select.value = nodeId;
        loadNodeSchedules(nodeId);
      }
    }

    function loadSchedulesTab() {
      const select = document.getElementById('schedNodeSelect');
      select.innerHTML = '';
      nodesCache.forEach(n => {
        select.appendChild(new Option(n.name || n.id, n.id));
      });
      if (nodesCache.length > 0) {
        activeSchedNodeId = nodesCache[0].id;
        loadNodeSchedules(activeSchedNodeId);
      }
    }

    function loadNodeSchedules(nodeId) {
      activeSchedNodeId = nodeId;
      const node = nodesCache.find(n => n.id === nodeId);
      currentSchedules = (node && node.schedules) ? JSON.parse(JSON.stringify(node.schedules)) : [];
      renderSchedulesList();
    }

    function renderSchedulesList() {
      const container = document.getElementById('schedulesContainer');
      if (currentSchedules.length === 0) {
        container.innerHTML = '<div style="color:var(--text-dim); padding:10px 0;">No standalone schedules configured for this node. Click "+ Add Daily Schedule" below.</div>';
        return;
      }

      const node = nodesCache.find(n => n.id === activeSchedNodeId);
      const comps = (node && node.components) ? node.components.filter(c => c.type == 1) : [];

      let html = '';
      currentSchedules.forEach((s, idx) => {
        const startH = String(s.startH !== undefined ? s.startH : 6).padStart(2, '0');
        const startM = String(s.startM !== undefined ? s.startM : 0).padStart(2, '0');
        const dur = s.durationMin !== undefined ? s.durationMin : 15;
        const mask = s.targetCompsMask !== undefined ? s.targetCompsMask : (s.targetSlotsMask !== undefined ? s.targetSlotsMask : 1);

        let checkboxesHtml = '';
        if (comps.length > 0) {
          comps.forEach((c, cIdx) => {
            const isChecked = (mask & (1 << cIdx)) !== 0;
            checkboxesHtml += `
              <label style="display:inline-flex; align-items:center; gap:4px; margin-right:10px; font-size:11px; text-transform:none; cursor:pointer;">
                <input type="checkbox" class="sched-chk-${idx}" value="${cIdx}" ${isChecked?'checked':''} style="width:auto;">
                <span>${escapeHtml(c.name || ('Relay ' + cIdx))}</span>
              </label>`;
          });
        } else {
          checkboxesHtml = '<span style="color:var(--text-dim); font-size:11px;">Relay 0 (Default)</span>';
        }

        html += `
          <div style="padding:12px; background:rgba(0,0,0,0.2); border:1px solid var(--card-border); border-radius:var(--radius-sm); margin-bottom:10px; display:grid; grid-template-columns:120px 140px 1fr auto; gap:12px; align-items:center;">
            <div>
              <label>Daily Start Time</label>
              <input type="time" value="${startH}:${startM}" onchange="updateScheduleTime(${idx}, this.value)" style="font-size:11px;">
            </div>
            <div>
              <label>Duration (Minutes)</label>
              <input type="number" min="1" max="1440" value="${dur}" onchange="currentSchedules[${idx}].durationMin=parseInt(this.value)||1" style="font-size:11px;">
            </div>
            <div>
              <label>Target Actuators</label>
              <div style="display:flex; flex-wrap:wrap; margin-top:4px;">${checkboxesHtml}</div>
            </div>
            <div>
              <button class="btn btn-danger btn-sm" onclick="removeScheduleRow(${idx})" style="padding:4px 8px; margin-top:14px;">&times;</button>
            </div>
          </div>`;
      });
      container.innerHTML = html;
    }

    function updateScheduleTime(idx, val) {
      if (!val) return;
      const parts = val.split(':');
      currentSchedules[idx].startH = parseInt(parts[0]) || 0;
      currentSchedules[idx].startM = parseInt(parts[1]) || 0;
    }

    function addScheduleRow() {
      if (currentSchedules.length >= 8) {
        return showToast('Maximum 8 standalone schedule slots per microcontroller EEPROM', 'warning');
      }
      currentSchedules.push({
        startH: 6,
        startM: 0,
        durationMin: 30,
        targetCompsMask: 1,
        targetSlotsMask: 1,
        action: 1
      });
      renderSchedulesList();
    }

    function removeScheduleRow(idx) {
      currentSchedules.splice(idx, 1);
      renderSchedulesList();
    }

    function syncScheduleInputs() {
      currentSchedules.forEach((s, idx) => {
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

    async function saveActiveNodeSchedules() {
      syncScheduleInputs();
      if (!activeSchedNodeId) return;

      const res = await fetch('/api/nodes/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: activeSchedNodeId, schedules: currentSchedules })
      });

      if (res.ok) {
        showToast(`Schedules pushed to Node '${activeSchedNodeId}' EEPROM`, 'success');
        refreshData();
      } else {
        showToast('Failed to save schedules', 'error');
      }
    }

    // =========================================================================
    // USERS, SETTINGS & ACCOUNT
    // =========================================================================
    async function loadUsers() {
      try {
        const res = await fetch('/api/users');
        const data = await res.json();
        const users = data.users || [];
        const container = document.getElementById('usersList');

        let html = `
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th style="text-align:right;">Actions</th>
              </tr>
            </thead>
            <tbody>`;

        users.forEach(u => {
          html += `
            <tr>
              <td><strong style="color:var(--text);">${escapeHtml(u.user)}</strong></td>
              <td><span class="badge ${u.role==='admin'?'badge-success':(u.role==='member'?'badge-primary':'')}">${escapeHtml((u.role||'guest').toUpperCase())}</span></td>
              <td style="text-align:right;">
                ${u.user !== 'admin' ? `<button class="btn btn-danger btn-sm" onclick="deleteUser('${u.user}')">Delete</button>` : '<span style="color:var(--text-dim); font-size:11px;">Primary Admin</span>'}
              </td>
            </tr>`;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
      } catch (e) {}
    }

    function openAddUserModal() {
      document.getElementById('addUserName').value = '';
      document.getElementById('addUserPass').value = '';
      document.getElementById('addUserModal').style.display = 'flex';
    }
    function closeAddUserModal() {
      document.getElementById('addUserModal').style.display = 'none';
    }
    async function submitAddUser() {
      const u = document.getElementById('addUserName').value.trim();
      const p = document.getElementById('addUserPass').value;
      const r = document.getElementById('addUserRole').value;
      if (!u || !p) return showToast('Username and password required', 'error');

      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: u, pass: p, role: r })
      });
      if (res.ok) {
        showToast(`User '${u}' created`, 'success');
        closeAddUserModal();
        loadUsers();
      } else {
        showToast('Failed to create user', 'error');
      }
    }

    async function deleteUser(u) {
      if (!confirm(`Delete user '${u}'?`)) return;
      const res = await fetch('/api/users/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: u })
      });
      if (res.ok) {
        showToast('User deleted', 'success');
        loadUsers();
      } else {
        showToast('Failed to delete user', 'error');
      }
    }

    async function loadSettings() {
      try {
        const res = await fetch('/api/system');
        const d = await res.json();
        document.getElementById('cfgStaSSID').value = d.sta_ssid || '';
        document.getElementById('cfgMqttEn').checked = !!d.mqtt_enabled;
        document.getElementById('cfgMqttBroker').value = d.mqtt_broker || '';
        document.getElementById('cfgMqttPort').value = d.mqtt_port || 8883;
        document.getElementById('cfgMqttHomeId').value = d.mqtt_home_id || 'home_1';
        document.getElementById('cfgMqttUser').value = d.mqtt_user || '';
      } catch (e) {}
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
      showToast('Settings saved. Hub is updating...', 'success');
    }

    async function loadAccountDiagnostics() {
      try {
        document.getElementById('accountUserDisplay').textContent = currentSession.user || 'admin';
        document.getElementById('accountRoleBadge').textContent = (currentSession.role || 'ADMIN').toUpperCase();

        const res = await fetch('/api/system');
        const d = await res.json();
        if (d.free_heap) {
          const freeKb = Math.round(d.free_heap / 1024);
          const totalKb = Math.round((d.total_heap || d.free_heap) / 1024);
          document.getElementById('diagHeap').textContent = freeKb + ' KB Free / ' + totalKb + ' KB';
        }
        if (d.littlefs_total) {
          const usedKb = Math.round((d.littlefs_used || 0) / 1024);
          const totKb = Math.round(d.littlefs_total / 1024);
          document.getElementById('diagLittleFS').textContent = usedKb + ' KB used / ' + totKb + ' KB';
        }
        if (d.uptime !== undefined) {
          const hrs = Math.floor(d.uptime / 3600);
          const mins = Math.floor((d.uptime % 3600) / 60);
          document.getElementById('diagUptime').textContent = hrs + 'h ' + mins + 'm';
          document.getElementById('sidebarUptime').textContent = hrs + 'h ' + mins + 'm';
        }
        document.getElementById('diagChip').textContent = d.chip || 'ESP32 Supervisor';
      } catch (e) {}
    }

    function openPassModal() {
      document.getElementById('modalNewPass').value = '';
      document.getElementById('passModal').style.display = 'flex';
    }
    function closePassModal() {
      document.getElementById('passModal').style.display = 'none';
    }
    async function submitModalPassChange() {
      const p = document.getElementById('modalNewPass').value;
      if (!p) return showToast('Password required', 'error');
      const res = await fetch('/api/users/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: currentSession.user || 'admin', pass: p, role: currentSession.role || 'admin' })
      });
      if (res.ok) {
        showToast('Password updated successfully!', 'success');
        closePassModal();
        document.getElementById('defaultPassBanner').style.display = 'none';
      } else {
        showToast('Failed to update password', 'error');
      }
    }

    async function submitAccountPassChange() {
      const p = document.getElementById('accountNewPass').value;
      if (!p) return showToast('Password required', 'error');
      const res = await fetch('/api/users/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: currentSession.user || 'admin', pass: p, role: currentSession.role || 'admin' })
      });
      if (res.ok) {
        showToast('Password updated successfully', 'success');
        document.getElementById('accountNewPass').value = '';
        document.getElementById('defaultPassBanner').style.display = 'none';
      } else {
        showToast('Failed to update password', 'error');
      }
    }

    // Utilities
    function showToast(msg, type = 'info') {
      const t = document.getElementById('toast');
      if (!t) return;
      t.textContent = msg;
      t.style.display = 'block';
      if (type === 'error') {
        t.style.borderColor = 'var(--danger-border)';
        t.style.color = '#fca5a5';
      } else if (type === 'success') {
        t.style.borderColor = 'var(--success-border)';
        t.style.color = '#6ee7b7';
      } else if (type === 'warning') {
        t.style.borderColor = 'var(--warning-border)';
        t.style.color = '#fcd34d';
      } else {
        t.style.borderColor = 'var(--card-border)';
        t.style.color = 'var(--text)';
      }
      clearTimeout(t._timeout);
      t._timeout = setTimeout(() => { t.style.display = 'none'; }, 3500);
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

    // Startup
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
