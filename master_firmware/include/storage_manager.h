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

struct PendingNode {
  String mac;
  String chip;
  String gpios;
  uint8_t slots;
  unsigned long lastSeen;
};

#define MAX_PENDING_NODES 8
extern PendingNode pendingNodes[MAX_PENDING_NODES];
extern uint8_t numPendingNodes;

inline bool initLittleFSStorage() {
  if (!LittleFS.begin(true)) {
    Serial.println("[STORAGE] LittleFS Mount Failed!");
    return false;
  }
  Serial.println("[STORAGE] LittleFS Mounted Successfully.");

  // Self-healing: Ensure /config directory exists
  if (!LittleFS.exists("/config")) {
    LittleFS.mkdir("/config");
  }

  // Self-healing: If rules.json does not exist, initialize empty registry
  if (!LittleFS.exists(RULES_CONFIG_PATH)) {
    Serial.println("[STORAGE] Auto-creating default /config/rules.json...");
    File f = LittleFS.open(RULES_CONFIG_PATH, "w");
    if (f) {
      f.print(R"({"rules":[]})");
      f.close();
    }
  }

  // Self-healing: If nodes.json does not exist, initialize empty registry
  if (!LittleFS.exists(NODES_CONFIG_PATH)) {
    Serial.println("[STORAGE] Auto-creating default /config/nodes.json...");
    File f = LittleFS.open(NODES_CONFIG_PATH, "w");
    if (f) {
      f.print(R"({"nodes":[]})");
      f.close();
    }
  }

  // Self-healing: If system.json does not exist, initialize default credentials
  if (!LittleFS.exists(SYSTEM_CONFIG_PATH)) {
    Serial.println("[STORAGE] Auto-creating default /config/system.json...");
    File f = LittleFS.open(SYSTEM_CONFIG_PATH, "w");
    if (f) {
      f.print(R"({
  "ap_ssid": "Mini-HA-Master",
  "ap_pass": "12345678",
  "sta_ssid": "",
  "sta_pass": "",
  "sta_enabled": false,
  "admin_user": "admin",
  "admin_pass": "admin123",
  "member_user": "member",
  "member_pass": "member123",
  "guest_user": "user",
  "guest_pass": "user123",
  "supla_enabled": false,
  "supla_server": "",
  "supla_email": "",
  "supla_guid": "",
  "supla_authkey": ""
})");
      f.close();
    }
  }

  return true;
}

inline void registerPendingDevice(const String& mac, const String& chip, const String& gpios, uint8_t slots) {
  for (uint8_t i = 0; i < numPendingNodes; i++) {
    if (pendingNodes[i].mac == mac) {
      pendingNodes[i].lastSeen = millis();
      return; // Already registered
    }
  }
  if (numPendingNodes < MAX_PENDING_NODES) {
    pendingNodes[numPendingNodes].mac = mac;
    pendingNodes[numPendingNodes].chip = chip;
    pendingNodes[numPendingNodes].gpios = gpios;
    pendingNodes[numPendingNodes].slots = slots;
    pendingNodes[numPendingNodes].lastSeen = millis();
    numPendingNodes++;
    Serial.printf("[DISCOVERY] New Unbound Device Cataloged: MAC=%s, Chip=%s, GPIOs=%s\n", 
      mac.c_str(), chip.c_str(), gpios.c_str());
  }
}
