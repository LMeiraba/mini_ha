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
  float slotValues[MAX_GPIO_SLOTS] = {0.0};
  float slotSecondary[MAX_GPIO_SLOTS] = {0.0};
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
extern void publishMqttNotification(const String& title, const String& msg, const String& level);

#define MAX_CONFIGURED_RULES 16
static bool ruleActiveState[MAX_CONFIGURED_RULES] = {false};
static DynamicJsonDocument cachedRulesDoc(4096);
static bool cachedRulesLoaded = false;

inline void reloadRulesCache() {
  cachedRulesDoc.clear();
  if (LittleFS.exists(RULES_CONFIG_PATH)) {
    File file = LittleFS.open(RULES_CONFIG_PATH, "r");
    if (file) {
      deserializeJson(cachedRulesDoc, file);
      file.close();
    }
  }
  cachedRulesLoaded = true;
  Serial.println("[RULES] In-memory rules cache reloaded from LittleFS.");
}

inline void evaluateDynamicRules() {
  if (!cachedRulesLoaded) {
    reloadRulesCache();
  }
  if (!cachedRulesDoc.containsKey("rules")) return;

  JsonArray rules = cachedRulesDoc["rules"].as<JsonArray>();
  int rIdx = 0;
  for (JsonObject rule : rules) {
    if (rIdx >= MAX_CONFIGURED_RULES) break;
    if (!rule["enabled"].as<bool>()) {
      ruleActiveState[rIdx++] = false;
      continue;
    }

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
        String sub = key.substring(5);
        if (sub.endsWith("_TMP")) {
          int s = sub.substring(0, sub.indexOf('_')).toInt();
          if (s >= 0 && s < MAX_GPIO_SLOTS) currentVal = ns->slotValues[s];
        } else if (sub.endsWith("_HUM")) {
          int s = sub.substring(0, sub.indexOf('_')).toInt();
          if (s >= 0 && s < MAX_GPIO_SLOTS) currentVal = ns->slotSecondary[s];
        } else {
          int s = sub.toInt();
          if (s >= 0 && s < MAX_GPIO_SLOTS) currentVal = ns->slotValues[s];
        }
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
      // Rising edge check: only notify once when condition first becomes true
      if (!ruleActiveState[rIdx]) {
        ruleActiveState[rIdx] = true;
        if (rule.containsKey("notify") && rule["notify"].as<bool>()) {
          String notifTitle = rule.containsKey("notify_title") ? rule["notify_title"].as<String>() : rule["name"].as<String>();
          String notifMsg = rule.containsKey("notify_msg") ? rule["notify_msg"].as<String>() : "Automation rule triggered!";
          publishMqttNotification(notifTitle, notifMsg, "warning");
        }
      }

      JsonArray actions = rule["actions"].as<JsonArray>();
      for (JsonObject act : actions) {
        String target = act["target"].as<String>();
        int slot = act.containsKey("slot") ? act["slot"].as<int>() : 0;
        int val = act.containsKey("val") ? act["val"].as<int>() : 1;
        String reason = act.containsKey("reason") ? act["reason"].as<String>() : rule["name"].as<String>();
        executeAction(target, slot, val, reason);
      }
    } else {
      ruleActiveState[rIdx] = false;
    }
    rIdx++;
  }
}
