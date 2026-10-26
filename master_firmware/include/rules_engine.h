#pragma once
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "storage_manager.h"

// =========================================================================
// DECLARATIVE RULE AUTOMATION ENGINE
// =========================================================================
// Runs 100% offline on ESP32 silicon.
// Evaluates JSON condition-action rules without any hardcoded logic!
// =========================================================================

struct MasterTelemetryCache {
  int rooftopLevel = -1;
  float rooftopTemp = 0.0;
  float rooftopHum = 0.0;
  int groundLevel = 100;
  bool pumpState = false;
  unsigned long pumpStartTime = 0;
  unsigned long lastRooftopHeartbeat = 0;
};

extern MasterTelemetryCache sysState;
void executeAction(const String& target, const String& cmd, int val, const String& reason);

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

      float currentVal = 0;
      if (node == "LOCAL") {
        if (key == "GROUND_LVL") currentVal = sysState.groundLevel;
        else if (key == "PUMP_STATE") currentVal = sysState.pumpState ? 1 : 0;
      } else if (node == "N01") {
        if (key == "LVL") currentVal = sysState.rooftopLevel;
        else if (key == "TMP") currentVal = sysState.rooftopTemp;
        else if (key == "HUM") currentVal = sysState.rooftopHum;
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
        String cmd = act["cmd"].as<String>();
        int val = act["val"].as<int>();
        String reason = act.containsKey("reason") ? act["reason"].as<String>() : rule["name"].as<String>();
        executeAction(target, cmd, val, reason);
      }
    }
  }

  // Silicon Failsafes (Hard limits)
  if (sysState.pumpState && (millis() - sysState.pumpStartTime > 30 * 60 * 1000UL)) {
    executeAction("LOCAL", "SET_PUMP", 0, "FAILSAFE: Max 30 min run time exceeded");
  }
  if (sysState.pumpState && millis() > 30000 && (millis() - sysState.lastRooftopHeartbeat > 15000)) {
    executeAction("LOCAL", "SET_PUMP", 0, "FAILSAFE: Lost connection to Rooftop Node");
  }
}
