#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "node_protocol.h"

// =========================================================================
// MASTER STORAGE & CONFIGURATION BROKER (LittleFS JSON Manager)
// =========================================================================

#define NODES_CONFIG_PATH  "/config/nodes.json"
#define RULES_CONFIG_PATH  "/config/rules.json"
#define SYSTEM_CONFIG_PATH "/config/system.json"
#define USERS_CONFIG_PATH  "/config/users.json"

struct PendingNode {
  String mac;
  String chip;
  String gpios;
  uint8_t slots;
  uint8_t portNum;
  String mode;
  String fw;
  unsigned long lastSeen;
};

#define MAX_PENDING_NODES 8
extern PendingNode pendingNodes[MAX_PENDING_NODES];
extern uint8_t numPendingNodes;

inline void ensureConfigFile(const char* path, const char* defaultContent) {
  // Use "a+" (append and read) mode so O_CREAT is set in VFS, completely preventing "no permits for creation" errors
  File f = LittleFS.open(path, "a+");
  if (f) {
    if (f.size() == 0) {
      f.print(defaultContent);
    }
    f.close();
  }
}

inline bool initLittleFSStorage() {
  if (!LittleFS.begin(true)) {
    Serial.println("[STORAGE] LittleFS Mount Failed!");
    return false;
  }
  Serial.println("[STORAGE] LittleFS Mounted Successfully.");

  // Ensure /config directory exists (mkdir is idempotent in LittleFS)
  LittleFS.mkdir("/config");

  // Self-healing: Initialize default configuration registries without triggering VFS open errors
  ensureConfigFile(RULES_CONFIG_PATH, R"({"rules":[]})");
  ensureConfigFile(NODES_CONFIG_PATH, R"({"nodes":[]})");
  ensureConfigFile("/config/notifications.json", R"({"notifications":[]})");
  ensureConfigFile(SYSTEM_CONFIG_PATH, R"({
  "ap_ssid": "Mini-HA-Master",
  "ap_pass": "12345678",
  "sta_ssid": "",
  "sta_pass": "",
  "sta_enabled": false,
  "sta_hidden": false,
  "mqtt_enabled": false,
  "mqtt_broker": "",
  "mqtt_port": 8883,
  "mqtt_user": "",
  "mqtt_pass": "",
  "mqtt_home_id": "home_1"
})");
  ensureConfigFile(USERS_CONFIG_PATH, R"({
  "users": [
    { "user": "admin", "pass": "admin123", "role": "admin" },
    { "user": "member", "pass": "member123", "role": "member" },
    { "user": "guest", "pass": "guest123", "role": "guest" }
  ]
})");

  return true;
}

inline void removePendingDevice(const String& mac) {
  for (uint8_t i = 0; i < numPendingNodes; i++) {
    if (pendingNodes[i].mac == mac) {
      for (uint8_t j = i; j + 1 < numPendingNodes; j++) {
        pendingNodes[j] = pendingNodes[j + 1];
      }
      numPendingNodes--;
      return;
    }
  }
}

inline void prunePendingDevices() {
  unsigned long now = millis();
  for (int i = 0; i < (int)numPendingNodes; ) {
    if (now - pendingNodes[i].lastSeen > 12000) {
      for (uint8_t j = i; j + 1 < numPendingNodes; j++) {
        pendingNodes[j] = pendingNodes[j + 1];
      }
      numPendingNodes--;
    } else {
      i++;
    }
  }

  File f = LittleFS.open(NODES_CONFIG_PATH, "r");
  if (f) {
    DynamicJsonDocument doc(4096);
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (!err && doc.containsKey("nodes")) {
      for (JsonObject node : doc["nodes"].as<JsonArray>()) {
        String boundMac = node["mac"].as<String>();
        if (boundMac.length() > 0) {
          removePendingDevice(boundMac);
        }
      }
    }
  }
}

inline void registerPendingDevice(const String& mac, const String& chip, const String& gpios, uint8_t slots, uint8_t portNum = 1, const String& mode = "WIRED", const String& fw = "v0.1.1-beta") {
  File f = LittleFS.open(NODES_CONFIG_PATH, "r");
  if (f) {
    DynamicJsonDocument doc(4096);
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (!err && doc.containsKey("nodes")) {
      for (JsonObject node : doc["nodes"].as<JsonArray>()) {
        if (node["mac"].as<String>() == mac) {
          // Automatic Re-provision on reflash/reboot!
          extern void broadcastBusPacket(const String& pkt);
          String existingId = node["id"].as<String>();
          bool apEnabled = node.containsKey("ap") ? node["ap"].as<bool>() : false;
          String apSsid = node.containsKey("ap_ssid") ? node["ap_ssid"].as<String>() : "";
          String apPass = node.containsKey("ap_pass") ? node["ap_pass"].as<String>() : "";
          String bindPkt = "MAC:" + mac + ":SET_ID:" + existingId;
          if (apEnabled && apSsid.length() > 0) {
            bindPkt += ":AP:1:AP_SSID:" + apSsid + ":AP_PASS:" + apPass;
          }
          broadcastBusPacket(buildPacket("ALL", "M", "BIND", bindPkt));
          Serial.printf("[AUTO-BIND] Re-provisioned recognized MAC %s back to Node ID: %s (Port: %d, Mode: %s, FW: %s)\n", mac.c_str(), existingId.c_str(), portNum, mode.c_str(), fw.c_str());

          // Re-dispatch component peripherals if previously assigned
          if (node.containsKey("components") && node["components"].is<JsonArray>()) {
            JsonArray comps = node["components"].as<JsonArray>();
            int idx = 0;
            for (JsonObject c : comps) {
              int type = c["type"].as<int>();
              int pin1 = c.containsKey("pin1") ? c["pin1"].as<int>() : 255;
              int pin2 = c.containsKey("pin2") ? c["pin2"].as<int>() : 255;
              int flags = c.containsKey("flags") ? c["flags"].as<int>() : 0;
              int param1 = c.containsKey("param1") ? c["param1"].as<int>() : 0;
              String cid = c.containsKey("id") ? c["id"].as<String>() : ("c" + String(idx));
              String p = "COMP:" + String(idx) + ":" + String(type) + ":" + String(pin1) + ":" + String(pin2) + ":" + String(flags) + ":" + String(param1) + ":" + cid;
              broadcastBusPacket(buildPacket(existingId, "M", "CFG", p));
              idx++;
            }
          }
          return; // Recognized & re-provisioned
        }
      }
    }
  }

  for (uint8_t i = 0; i < numPendingNodes; i++) {
    if (pendingNodes[i].mac == mac) {
      pendingNodes[i].chip = chip;
      pendingNodes[i].gpios = gpios;
      pendingNodes[i].slots = slots;
      pendingNodes[i].portNum = portNum;
      pendingNodes[i].mode = mode;
      pendingNodes[i].fw = fw;
      pendingNodes[i].lastSeen = millis();
      return; // Already registered
    }
  }
  if (numPendingNodes < MAX_PENDING_NODES) {
    pendingNodes[numPendingNodes].mac = mac;
    pendingNodes[numPendingNodes].chip = chip;
    pendingNodes[numPendingNodes].gpios = gpios;
    pendingNodes[numPendingNodes].slots = slots;
    pendingNodes[numPendingNodes].portNum = portNum;
    pendingNodes[numPendingNodes].mode = mode;
    pendingNodes[numPendingNodes].fw = fw;
    pendingNodes[numPendingNodes].lastSeen = millis();
    numPendingNodes++;
    Serial.printf("[DISCOVERY] New Unbound Device Cataloged: MAC=%s, Chip=%s, GPIOs=%s (Port: %d, Mode: %s, FW: %s)\n", 
      mac.c_str(), chip.c_str(), gpios.c_str(), portNum, mode.c_str(), fw.c_str());
  }
}
