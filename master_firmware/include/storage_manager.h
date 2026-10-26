#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "node_protocol.h"

// =========================================================================
// MASTER STORAGE & CONFIGURATION BROKER (LittleFS JSON Manager)
// =========================================================================

#define NODES_CONFIG_PATH "/config/nodes.json"
#define RULES_CONFIG_PATH "/config/rules.json"

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
