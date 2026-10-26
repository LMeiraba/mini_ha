#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "node_protocol.h"
#include "storage_manager.h"

// =========================================================================
// GENERIC DYNAMIC RULES & TELEMETRY ENGINE
// =========================================================================
// Runs 100% offline on ESP32 silicon.
// Evaluates JSON condition-action rules between any registered nodes.
// =========================================================================

struct GenericNodeTelemetry {
  String nodeId = "";
  int distance = -1;
  float temp = 0.0;
  float hum = 0.0;
  bool relayStates[MAX_GPIO_SLOTS] = {false};
  unsigned long lastSeen = 0;
};

#define MAX_TRACKED_NODES 16
extern GenericNodeTelemetry nodeStates[MAX_TRACKED_NODES];
extern uint8_t numTrackedNodes;

inline GenericNodeTelemetry* getOrCreateNodeState(const String& nodeId) {
  for (uint8_t i = 0; i < numTrackedNodes; i++) {
    if (nodeStates[i].nodeId == nodeId) return &nodeStates[i];
  }
  if (numTrackedNodes < MAX_TRACKED_NODES) {
    nodeStates[numTrackedNodes].nodeId = nodeId;
    nodeStates[numTrackedNodes].lastSeen = millis();
    return &nodeStates[numTrackedNodes++];
  }
  return nullptr;
}

void executeAction(const String& targetNode, int slot, int state, const String& reason);

inline void evaluateDynamicRules() {
  if (!LittleFS.exists(RULES_CONFIG_PATH)) return;
  File file = LittleFS.open(RULES_CONFIG_PATH, "r");
  if (!file) return;

  DynamicJsonDocument doc(4096);
  DeserializationError err = deserializeJson(doc, file);
  file.close();
  if (err) return;

  JsonArray rules = doc["rules"].as<JsonArray>();
  for (JsonObject rule : rules) {
    if (!rule["enabled"].as<bool>()) continue;

    bool allConditionsMet = true;
    JsonArray conditions = rule["conditions"].as<JsonArray>();

    for (JsonObject cond : conditions) {
      String node = cond["node"].as<String>();
      String key = cond["key"].as<String>();
      String op = cond["op"].as<String>();
      float targetVal = cond["val"].as<float>();

      GenericNodeTelemetry* ns = getOrCreateNodeState(node);
      if (!ns) {
        allConditionsMet = false;
        break;
      }

      float currentVal = 0;
      if (key == "LVL" || key == "DIST") currentVal = ns->distance;
      else if (key == "TMP") currentVal = ns->temp;
      else if (key == "HUM") currentVal = ns->hum;
      else if (key.startsWith("SLOT_")) {
        int s = key.substring(5).toInt();
        if (s >= 0 && s < MAX_GPIO_SLOTS) currentVal = ns->relayStates[s] ? 1 : 0;
      }

      // Check condition
      bool condResult = false;
      if (op == ">=") condResult = (currentVal >= targetVal);
      else if (op == "<=") condResult = (currentVal <= targetVal && currentVal != -1);
      else if (op == "==") condResult = (currentVal == targetVal);
      else if (op == ">")  condResult = (currentVal > targetVal);
      else if (op == "<")  condResult = (currentVal < targetVal && currentVal != -1);

      if (!condResult) {
        allConditionsMet = false;
        break;
      }
    }

    if (allConditionsMet) {
      JsonArray actions = rule["actions"].as<JsonArray>();
      for (JsonObject act : actions) {
        String target = act["target"].as<String>();
        int slot = act.containsKey("slot") ? act["slot"].as<int>() : 0;
        int val = act.containsKey("val") ? act["val"].as<int>() : 1;
        String reason = act.containsKey("reason") ? act["reason"].as<String>() : rule["name"].as<String>();
        executeAction(target, slot, val, reason);
      }
    }
  }
}
