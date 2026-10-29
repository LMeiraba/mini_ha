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
// Evaluates JSON multi-condition (AND/OR) action rules between registered nodes.
// =========================================================================

struct GenericNodeTelemetry {
  String nodeId = "";
  int distance = -1;
  float temp = 0.0;
  float hum = 0.0;
  bool relayStates[MAX_COMPONENTS] = {false};
  float slotValues[MAX_COMPONENTS] = {0.0};
  float slotSecondary[MAX_COMPONENTS] = {0.0};
  
  // Dynamic component entity storage
  String compKeys[MAX_COMPONENTS];
  float compVal1[MAX_COMPONENTS] = {0.0};
  float compVal2[MAX_COMPONENTS] = {0.0};
  uint8_t numComps = 0;
  unsigned long lastSeen = 0;
  uint32_t freeHeap = 0;
  uint8_t port = 1;
  String mode = "WIRED";
  String fwVersion = "v0.1.1-beta";

  void setComponentData(const String& key, float v1, float v2 = 0.0) {
    for (uint8_t i = 0; i < numComps; i++) {
      if (compKeys[i] == key) {
        compVal1[i] = v1;
        compVal2[i] = v2;
        return;
      }
    }
    if (numComps < MAX_COMPONENTS) {
      compKeys[numComps] = key;
      compVal1[numComps] = v1;
      compVal2[numComps] = v2;
      numComps++;
    }
  }

  float getMetricValue(const String& metricKey) {
    String prefix = metricKey;
    String suffix = "";
    int dotIdx = metricKey.indexOf('.');
    if (dotIdx != -1) {
      prefix = metricKey.substring(0, dotIdx);
      suffix = metricKey.substring(dotIdx + 1);
    }

    for (uint8_t i = 0; i < numComps; i++) {
      if (compKeys[i] == prefix || compKeys[i] == metricKey) {
        if (suffix == "hum" || suffix == "level" || suffix == "pct") {
          return compVal2[i];
        }
        return compVal1[i];
      }
    }

    if (metricKey == "LVL" || metricKey == "DIST") return distance;
    if (metricKey == "TMP" || metricKey == "TEMP") return temp;
    if (metricKey == "HUM") return hum;
    if (metricKey.startsWith("SLOT_")) {
      int s = metricKey.substring(5).toInt();
      if (s >= 0 && s < MAX_COMPONENTS) return slotValues[s];
    }
    return 0.0;
  }
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
    nodeStates[numTrackedNodes].lastSeen = 0; // 0 indicates offline until first packet received
    nodeStates[numTrackedNodes].freeHeap = 0;
    return &nodeStates[numTrackedNodes++];
  }
  return nullptr;
}

void executeAction(const String& targetNode, const String& compId, int state, const String& reason);
void executeAction(const String& targetNode, int slot, int state, const String& reason);
extern void publishMqttNotification(const String& title, const String& msg, const String& level);

// =========================================================================
// AUTOMATION RULES ENGINE (MULTI-CONDITION AND/OR & MULTI-ACTION)
// =========================================================================
#define MAX_CONFIGURED_RULES 24
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

inline bool evaluateSingleCondition(JsonObject cond) {
  String node = cond["node"].as<String>();
  String key = cond["key"].as<String>();
  String op = cond["op"].as<String>();
  float targetVal = cond["val"].as<float>();

  // Any state change / flip event condition (triggers on edge toggle)
  if (key.endsWith(".change") || op == "changed") {
    return true;
  }

  GenericNodeTelemetry* ns = getOrCreateNodeState(node);
  if (!ns) return false;

  float currentVal = ns->getMetricValue(key);

  if (op == ">=") return (currentVal >= targetVal);
  if (op == "<=") return (currentVal <= targetVal && currentVal != -1);
  if (op == "==") return (currentVal == targetVal);
  if (op == "!=") return (currentVal != targetVal);
  if (op == ">")  return (currentVal > targetVal);
  if (op == "<")  return (currentVal < targetVal && currentVal != -1);
  return false;
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
    if (rule.containsKey("enabled") && !rule["enabled"].as<bool>()) {
      ruleActiveState[rIdx++] = false;
      continue;
    }

    String logic = rule.containsKey("logic") ? rule["logic"].as<String>() : "AND";
    logic.toUpperCase();

    bool conditionMet = false;
    bool hasChangeEvent = false;

    // Check multiple conditions (or legacy single cond)
    if (rule.containsKey("conditions") && rule["conditions"].is<JsonArray>() && rule["conditions"].as<JsonArray>().size() > 0) {
      JsonArray conditions = rule["conditions"].as<JsonArray>();
      for (JsonObject cond : conditions) {
        String k = cond["key"].as<String>();
        String o = cond["op"].as<String>();
        if (k.endsWith(".change") || o == "changed") { hasChangeEvent = true; break; }
      }
      if (logic == "OR") {
        conditionMet = false;
        for (JsonObject cond : conditions) {
          if (evaluateSingleCondition(cond)) {
            conditionMet = true;
            break;
          }
        }
      } else { // "AND"
        conditionMet = true;
        for (JsonObject cond : conditions) {
          if (!evaluateSingleCondition(cond)) {
            conditionMet = false;
            break;
          }
        }
      }
    } else if (rule.containsKey("cond")) {
      String k = rule["cond"]["key"].as<String>();
      String o = rule["cond"]["op"].as<String>();
      if (k.endsWith(".change") || o == "changed") hasChangeEvent = true;
      conditionMet = evaluateSingleCondition(rule["cond"].as<JsonObject>());
    }

    if (conditionMet) {
      // Edge trigger: Execute actions once when condition transitions to TRUE
      if (!ruleActiveState[rIdx]) {
        ruleActiveState[rIdx] = true;

        // Execute multiple actions
        if (rule.containsKey("actions") && rule["actions"].is<JsonArray>()) {
          JsonArray actions = rule["actions"].as<JsonArray>();
          for (JsonObject act : actions) {
            String target = act["target"].as<String>();
            String comp = act.containsKey("comp") ? act["comp"].as<String>() : (act.containsKey("slot") ? String(act["slot"].as<int>()) : "0");
            int val = act.containsKey("val") ? act["val"].as<int>() : (act.containsKey("state") ? act["state"].as<int>() : 1);
            String reason = act.containsKey("reason") ? act["reason"].as<String>() : rule["name"].as<String>();
            executeAction(target, comp, val, reason);
          }
        } else if (rule.containsKey("act")) {
          JsonObject act = rule["act"].as<JsonObject>();
          String target = act["target"].as<String>();
          String comp = act.containsKey("comp") ? act["comp"].as<String>() : (act.containsKey("slot") ? String(act["slot"].as<int>()) : "0");
          int val = act.containsKey("val") ? act["val"].as<int>() : (act.containsKey("state") ? act["state"].as<int>() : 1);
          String reason = act.containsKey("reason") ? act["reason"].as<String>() : rule["name"].as<String>();
          executeAction(target, comp, val, reason);
        }

        // For edge-flip events, reset active state so subsequent flips trigger immediately
        if (hasChangeEvent) {
          ruleActiveState[rIdx] = false;
        }
      }
    } else {
      ruleActiveState[rIdx] = false;
    }
    rIdx++;
  }
}

// =========================================================================
// INDEPENDENT NOTIFICATION & ALERT RULES ENGINE (NO STATE MODIFICATION)
// =========================================================================
#define NOTIFICATIONS_CONFIG_PATH "/config/notifications.json"
#define MAX_CONFIGURED_NOTIFS 16
static bool notifActiveState[MAX_CONFIGURED_NOTIFS] = {false};
static DynamicJsonDocument cachedNotifsDoc(4096);
static bool cachedNotifsLoaded = false;

struct AlertLogEntry {
  String title;
  String msg;
  String level;
  uint32_t timestamp;
};
#define MAX_ALERT_LOGS 20
static AlertLogEntry recentAlerts[MAX_ALERT_LOGS];
static uint8_t alertCount = 0;

inline void logAlert(const String& title, const String& msg, const String& level) {
  if (alertCount < MAX_ALERT_LOGS) {
    alertCount++;
  }
  for (int i = alertCount - 1; i > 0; i--) {
    recentAlerts[i] = recentAlerts[i - 1];
  }
  recentAlerts[0].title = title;
  recentAlerts[0].msg = msg;
  recentAlerts[0].level = level;
  time_t now = time(nullptr);
  recentAlerts[0].timestamp = (now > 1700000000) ? (uint32_t)now : (millis() / 1000);
}

inline void clearAlertLogs() {
  alertCount = 0;
}

inline void reloadNotificationsCache() {
  cachedNotifsDoc.clear();
  File file = LittleFS.open(NOTIFICATIONS_CONFIG_PATH, "r");
  if (!file || file.size() == 0) {
    if (file) file.close();
    File wFile = LittleFS.open(NOTIFICATIONS_CONFIG_PATH, "w");
    if (wFile) {
      wFile.print(R"({"notifications":[]})");
      wFile.close();
    }
    file = LittleFS.open(NOTIFICATIONS_CONFIG_PATH, "r");
  }
  if (file) {
    deserializeJson(cachedNotifsDoc, file);
    file.close();
  }
  cachedNotifsLoaded = true;
  Serial.println("[NOTIFS] In-memory notifications cache reloaded from LittleFS.");
}

inline void evaluateNotificationRules() {
  if (!cachedNotifsLoaded) {
    reloadNotificationsCache();
  }
  if (!cachedNotifsDoc.containsKey("notifications")) return;

  JsonArray notifs = cachedNotifsDoc["notifications"].as<JsonArray>();
  int nIdx = 0;
  for (JsonObject notif : notifs) {
    if (nIdx >= MAX_CONFIGURED_NOTIFS) break;
    if (notif.containsKey("enabled") && !notif["enabled"].as<bool>()) {
      notifActiveState[nIdx++] = false;
      continue;
    }

    String logic = notif.containsKey("logic") ? notif["logic"].as<String>() : "AND";
    logic.toUpperCase();

    bool conditionMet = false;
    if (notif.containsKey("conditions") && notif["conditions"].is<JsonArray>() && notif["conditions"].as<JsonArray>().size() > 0) {
      JsonArray conditions = notif["conditions"].as<JsonArray>();
      if (logic == "OR") {
        conditionMet = false;
        for (JsonObject cond : conditions) {
          if (evaluateSingleCondition(cond)) {
            conditionMet = true;
            break;
          }
        }
      } else { // "AND"
        conditionMet = true;
        for (JsonObject cond : conditions) {
          if (!evaluateSingleCondition(cond)) {
            conditionMet = false;
            break;
          }
        }
      }
    } else if (notif.containsKey("cond")) {
      conditionMet = evaluateSingleCondition(notif["cond"].as<JsonObject>());
    }

    if (conditionMet) {
      // Rising edge check: only notify once when condition first becomes true
      if (!notifActiveState[nIdx]) {
        notifActiveState[nIdx] = true;
        String title = notif.containsKey("title") ? notif["title"].as<String>() : (notif.containsKey("name") ? notif["name"].as<String>() : "System Alert");
        String msg = notif.containsKey("msg") ? notif["msg"].as<String>() : "Threshold condition triggered";
        String level = notif.containsKey("level") ? notif["level"].as<String>() : "warning";
        publishMqttNotification(title, msg, level);
        logAlert(title, msg, level);
        Serial.printf("[ALERT] %s: %s (Level: %s)\n", title.c_str(), msg.c_str(), level.c_str());
      }
    } else {
      notifActiveState[nIdx] = false;
    }
    nIdx++;
  }
}
