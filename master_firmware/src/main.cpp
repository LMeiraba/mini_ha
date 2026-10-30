#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ESPmDNS.h>
#include <DNSServer.h>

#include "node_protocol.h"
#include "storage_manager.h"
#include "rules_engine.h"
#include "web_dashboard.h"

// =========================================================================
// MINI-HOMEASSISTANT GENERIC MASTER SUPERVISOR (ESP32-C3 & ESP32-DevKit)
// =========================================================================

#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
  #define MASTER_CHIP_NAME     "ESP32-C3"
  #define PORT1_RX_PIN         4
  #define PORT1_TX_PIN         5
  HardwareSerial BusPort1(1);
#else
  // Classic ESP32 Dev Board (Dual-Core Xtensa ESP32-WROOM-32)
  #define MASTER_CHIP_NAME     "ESP32-DevKit"
  // Port 1: Hardware UART1 (GPIO 4 RX, GPIO 5 TX) -> Dedicated Star Branch 1
  #define PORT1_RX_PIN         4
  #define PORT1_TX_PIN         5
  HardwareSerial BusPort1(1);

  // Port 2: Hardware UART2 (GPIO 16 RX, GPIO 17 TX) -> Dedicated Star Branch 2
  #define PORT2_RX_PIN         16
  #define PORT2_TX_PIN         17
  HardwareSerial BusPort2(2);
#endif

WebServer webServer(80);
DNSServer dnsServer;

// Direct Wireless TCP Mesh Server (Port 8266)
// Listens simultaneously across SoftAP (192.168.4.1) and Home Wi-Fi Router (STA IP)
#define MAX_MESH_CLIENTS 4
WiFiServer meshServer(DEFAULT_MESH_PORT);
WiFiClient meshClients[MAX_MESH_CLIENTS];
String meshRxBuf[MAX_MESH_CLIENTS];

// Unified Star Hub Dispatcher: Broadcasts full-duplex out all physical isolated UART star ports
// and active direct Wi-Fi mesh socket clients.
void broadcastBusPacket(const String& pkt) {
  BusPort1.println(pkt);
#if !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(ESP32C3)
  BusPort2.println(pkt);
#endif
  for (uint8_t c = 0; c < MAX_MESH_CLIENTS; c++) {
    if (meshClients[c] && meshClients[c].connected()) {
      meshClients[c].println(pkt);
    }
  }
}

// Global State & Telemetry Storage
PendingNode pendingNodes[MAX_PENDING_NODES];
uint8_t numPendingNodes = 0;

GenericNodeTelemetry nodeStates[MAX_TRACKED_NODES];
uint8_t numTrackedNodes = 0;

String busRxBuf1 = "";
String busRxBuf2 = "";
unsigned long lastRulePoll = 0;
unsigned long lastBusPoll = 0;

void handleIncomingBusPacket(const ParsedPacket& pkt, uint8_t portNum = 1);

void pollBusPort(HardwareSerial& port, String& buf, uint8_t portNum) {
  while (port.available()) {
    char c = (char)port.read();
    if (c == '\n') {
      buf.trim();
      if (buf.length() > 0) {
        ParsedPacket pkt = parseProtocolLine(buf);
        if (pkt.isValid) {
          handleIncomingBusPacket(pkt, portNum);
        }
      }
      buf = "";
    } else if (c != '\r') {
      buf += c;
      if (buf.length() > PROTOCOL_MAX_LINE) buf = "";
    }
  }
}

SystemSecurityConfig sysSecurity;

void loadSystemSecurity() {
  File f = LittleFS.open(SYSTEM_CONFIG_PATH, "r");
  if (f) {
    DynamicJsonDocument doc(512);
    deserializeJson(doc, f);
    f.close();
    if (doc.containsKey("ap_ssid")) sysSecurity.apSsid = doc["ap_ssid"].as<String>();
    if (doc.containsKey("ap_pass")) sysSecurity.apPass = doc["ap_pass"].as<String>();
    if (doc.containsKey("sta_ssid")) sysSecurity.staSsid = doc["sta_ssid"].as<String>();
    if (doc.containsKey("sta_pass")) sysSecurity.staPass = doc["sta_pass"].as<String>();
    if (doc.containsKey("sta_enabled")) sysSecurity.staEnabled = doc["sta_enabled"].as<bool>();
    if (doc.containsKey("sta_hidden")) sysSecurity.staHidden = doc["sta_hidden"].as<bool>();
    if (doc.containsKey("mqtt_enabled")) sysSecurity.mqttEnabled = doc["mqtt_enabled"].as<bool>();
    if (doc.containsKey("mqtt_broker")) sysSecurity.mqttBroker = doc["mqtt_broker"].as<String>();
    if (doc.containsKey("mqtt_port")) sysSecurity.mqttPort = doc["mqtt_port"].as<uint16_t>();
    if (doc.containsKey("mqtt_user")) sysSecurity.mqttUser = doc["mqtt_user"].as<String>();
    if (doc.containsKey("mqtt_pass")) sysSecurity.mqttPass = doc["mqtt_pass"].as<String>();
    if (doc.containsKey("mqtt_home_id")) sysSecurity.mqttHomeId = doc["mqtt_home_id"].as<String>();
  }
  if (sysSecurity.apSsid.length() == 0) sysSecurity.apSsid = "Mini-HA-Master";
  if (sysSecurity.apPass.length() < 8) sysSecurity.apPass = "12345678";
  if (sysSecurity.mqttHomeId.length() == 0) sysSecurity.mqttHomeId = "home_1";
  if (sysSecurity.mqttPort == 0) sysSecurity.mqttPort = 8883;
}

// =========================================================================
// CLOUD MQTT BRIDGE (TLS / EMQX SERVERLESS / SECURE PWA BRIDGE)
// =========================================================================
WiFiClientSecure secureClient;
PubSubClient mqttClient(secureClient);
unsigned long lastMqttConnectAttempt = 0;
unsigned long lastMqttStatePublish = 0;
bool mqttSchemaNeedsPublish = false;

// Action Dispatcher for Dynamic Rules Engine & Web UI
void executeAction(const String& targetNode, const String& compId, int state, const String& reason) {
  Serial.printf("[ACTION] Target %s Comp %s -> %d | Reason: %s\n", targetNode.c_str(), compId.c_str(), state, reason.c_str());
  broadcastBusPacket(buildPacket(targetNode, "M", "SET", compId + ":" + String(state)));
}

void executeAction(const String& targetNode, int slot, int state, const String& reason) {
  Serial.printf("[ACTION] Target %s Slot %d -> %d | Reason: %s\n", targetNode.c_str(), slot, state, reason.c_str());
  broadcastBusPacket(buildPacket(targetNode, "M", "SET", "SLOT:" + String(slot) + ":STATE:" + String(state)));
}

void publishMqttSchema() {
  if (!mqttClient.connected()) return;
  File file = LittleFS.open(NODES_CONFIG_PATH, "r");
  if (!file) return;
  DynamicJsonDocument doc(4096);
  deserializeJson(doc, file);
  file.close();

  DynamicJsonDocument schemaDoc(4096);
  schemaDoc["home"] = sysSecurity.mqttHomeId;
  schemaDoc["master"] = MASTER_CHIP_NAME;
  schemaDoc["nodes"] = doc["nodes"];

  String out;
  serializeJson(schemaDoc, out);
  String topic = "miniha/" + sysSecurity.mqttHomeId + "/schema";
  mqttClient.publish(topic.c_str(), out.c_str(), true); // Retained
  Serial.printf("[MQTT] Published schema to %s (%d bytes)\n", topic.c_str(), out.length());
}

void publishMqttState() {
  if (!mqttClient.connected()) return;
  DynamicJsonDocument stateDoc(4096);
  stateDoc["home"] = sysSecurity.mqttHomeId;
  JsonObject nodesObj = stateDoc.createNestedObject("nodes");

  for (uint8_t i = 0; i < numTrackedNodes; i++) {
    JsonObject n = nodesObj.createNestedObject(nodeStates[i].nodeId);
    bool online = (millis() - nodeStates[i].lastSeen < 10000);
    n["online"] = online;
    n["temp"] = nodeStates[i].temp;
    n["hum"] = nodeStates[i].hum;
    n["dist"] = nodeStates[i].distance;

    JsonObject slotsObj = n.createNestedObject("slots");
    for (int s = 0; s < MAX_COMPONENTS; s++) {
      slotsObj[String(s + 1)] = nodeStates[i].relayStates[s] ? 1 : 0;
    }

    JsonObject compsObj = n.createNestedObject("components");
    for (uint8_t c = 0; c < nodeStates[i].numComps; c++) {
      JsonObject co = compsObj.createNestedObject(nodeStates[i].compKeys[c]);
      co["v1"] = nodeStates[i].compVal1[c];
      co["v2"] = nodeStates[i].compVal2[c];
    }
  }

  String out;
  serializeJson(stateDoc, out);
  String topic = "miniha/" + sysSecurity.mqttHomeId + "/state";
  mqttClient.publish(topic.c_str(), out.c_str(), true); // Retained
}

void publishMqttNotification(const String& title, const String& msg, const String& level) {
  if (!mqttClient.connected()) return;
  DynamicJsonDocument doc(512);
  doc["title"] = title;
  doc["msg"] = msg;
  doc["level"] = level;
  doc["time"] = millis();
  String out;
  serializeJson(doc, out);
  String topic = "miniha/" + sysSecurity.mqttHomeId + "/notify";
  mqttClient.publish(topic.c_str(), out.c_str());
  Serial.printf("[NOTIFY] Published: '%s' - %s\n", title.c_str(), msg.c_str());
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String topicStr = String(topic);
  String msg = "";
  for (unsigned int i = 0; i < length; i++) {
    msg += (char)payload[i];
  }
  Serial.printf("[MQTT RX] %s -> %s\n", topic, msg.c_str());

  DynamicJsonDocument doc(512);
  DeserializationError err = deserializeJson(doc, msg);
  if (err) return;

  // 1. Remote User Login Authentication over MQTT
  if (topicStr.endsWith("/auth/login")) {
    String client = doc.containsKey("client") ? doc["client"].as<String>() : "";
    String user = doc.containsKey("user") ? doc["user"].as<String>() : "";
    String pass = doc.containsKey("pass") ? doc["pass"].as<String>() : "";

    UserRole uRole = ROLE_NONE;
    String roleStr = "";
    String token = createSessionForUser(user, pass, &uRole, &roleStr);

    DynamicJsonDocument res(256);
    if (token.length() > 0) {
      res["status"] = "ok";
      res["token"] = token;
      res["user"] = user;
      res["role"] = roleStr;
      Serial.printf("[AUTH] Login SUCCESS: User '%s' (%s) via MQTT\n", user.c_str(), roleStr.c_str());
    } else {
      res["status"] = "error";
      res["error"] = "Invalid username or password";
      Serial.printf("[AUTH] Login FAILED: User '%s' via MQTT\n", user.c_str());
    }

    String out;
    serializeJson(res, out);
    String replyTopic = "miniha/" + sysSecurity.mqttHomeId + "/auth/reply/" + client;
    mqttClient.publish(replyTopic.c_str(), out.c_str());
    return;
  }

  // 2. Control Action with Cryptographic Token Verification
  if (topicStr.endsWith("/set")) {
    if (doc.containsKey("target") && doc.containsKey("state") && (doc.containsKey("comp") || doc.containsKey("slot"))) {
      String token = doc.containsKey("token") ? doc["token"].as<String>() : "";
      String target = doc["target"].as<String>();
      int state = doc["state"].as<int>();

      String username = "";
      UserRole role = validateToken(token, &username);
      if (role < ROLE_MEMBER) {
        Serial.printf("[SECURITY] Rejected command for '%s': User '%s' unauthorized (Role: %d)\n", 
                      target.c_str(), username.c_str(), role);
        return;
      }

      GenericNodeTelemetry* ns = getOrCreateNodeState(target);
      if (doc.containsKey("comp")) {
        String comp = doc["comp"].as<String>();
        executeAction(target, comp, state, "MQTT by '" + username + "'");
        if (ns) ns->setComponentData(comp, state);
      } else {
        int slot = doc["slot"].as<int>();
        executeAction(target, slot, state, "MQTT by '" + username + "'");
        if (ns && slot >= 1 && slot <= MAX_COMPONENTS) {
          ns->relayStates[slot - 1] = (state == 1);
        }
      }
      publishMqttState();
    }
  }
}

void maintainMqtt() {
  if (!sysSecurity.mqttEnabled || sysSecurity.mqttBroker.length() == 0) return;
  if (WiFi.status() != WL_CONNECTED) return;

  if (mqttClient.connected()) {
    mqttClient.loop();
    if (mqttSchemaNeedsPublish) {
      mqttSchemaNeedsPublish = false;
      publishMqttSchema();
    }
    if (millis() - lastMqttStatePublish > 3000) {
      lastMqttStatePublish = millis();
      publishMqttState();
    }
    return;
  }

  if (millis() - lastMqttConnectAttempt > 5000) {
    lastMqttConnectAttempt = millis();
    Serial.printf("[MQTT] Connecting to %s:%d...\n", sysSecurity.mqttBroker.c_str(), sysSecurity.mqttPort);

    secureClient.setInsecure();
    secureClient.setTimeout(3); // 3-second non-blocking timeout to prevent bus starvation
    mqttClient.setServer(sysSecurity.mqttBroker.c_str(), sysSecurity.mqttPort);
    mqttClient.setCallback(mqttCallback);
    mqttClient.setBufferSize(4096);

    String clientId = "MiniHA_Master_" + String((uint32_t)ESP.getEfuseMac(), HEX);
    String statusTopic = "miniha/" + sysSecurity.mqttHomeId + "/status";
    String willPayload = "{\"online\":false}";

    bool connected = false;
    if (sysSecurity.mqttUser.length() > 0) {
      connected = mqttClient.connect(clientId.c_str(), sysSecurity.mqttUser.c_str(), sysSecurity.mqttPass.c_str(),
                                     statusTopic.c_str(), 1, true, willPayload.c_str());
    } else {
      connected = mqttClient.connect(clientId.c_str(),
                                     statusTopic.c_str(), 1, true, willPayload.c_str());
    }

    if (connected) {
      Serial.println("[MQTT] Connected to Cloud Broker!");
      // Publish retained birth message immediately
      mqttClient.publish(statusTopic.c_str(), "{\"online\":true}", true);

      String setTopic = "miniha/" + sysSecurity.mqttHomeId + "/set";
      String authTopic = "miniha/" + sysSecurity.mqttHomeId + "/auth/login";
      mqttClient.subscribe(setTopic.c_str());
      mqttClient.subscribe(authTopic.c_str());
      Serial.printf("[MQTT] Subscribed to %s & %s\n", setTopic.c_str(), authTopic.c_str());
      publishMqttSchema();
      publishMqttState();
    } else {
      Serial.printf("[MQTT] Connect failed, rc=%d. Will retry in 5s\n", mqttClient.state());
    }
  }
}

// Bind & Provision Discovered Slaves
void triggerProvisionNode(const String& mac, const String& newId, const String& name, bool apEnabled, const String& apSsid, const String& apPass, bool apHidden) {
  String bindPayload = "MAC:" + mac + ":SET_ID:" + newId;
  if (apEnabled) {
    bindPayload += ":AP:1:AP_SSID:" + apSsid + ":AP_PASS:" + apPass + ":AP_HIDDEN:" + String(apHidden ? 1 : 0);
  }
  Serial.printf("[PROV] Dispatching BIND packet: MAC=%s -> ID=%s (%s) | AP: %s (Hidden: %d)\n",
                mac.c_str(), newId.c_str(), name.c_str(), apEnabled ? apSsid.c_str() : "OFF", apHidden ? 1 : 0);
  broadcastBusPacket(buildPacket("NEW", "M", "BIND", bindPayload));

  File file = LittleFS.open(NODES_CONFIG_PATH, "r");
  DynamicJsonDocument doc(4096);
  if (file) {
    deserializeJson(doc, file);
    file.close();
  }

  String nodeChip = "ESP32";
  String nodeMode = "WIRED";
  String nodePort = "UART1";
  String nodeFw = "v0.1.1-beta";
  for (uint8_t i = 0; i < numPendingNodes; i++) {
    if (pendingNodes[i].mac == mac) {
      if (pendingNodes[i].chip.length() > 0) nodeChip = pendingNodes[i].chip;
      if (pendingNodes[i].mode.length() > 0) nodeMode = pendingNodes[i].mode;
      nodePort = (pendingNodes[i].portNum == 2) ? "UART2" : ((pendingNodes[i].portNum == 3) ? "WIFI" : "UART1");
      if (pendingNodes[i].fw.length() > 0) nodeFw = pendingNodes[i].fw;
      break;
    }
  }

  JsonArray nodes = doc["nodes"].as<JsonArray>();
  bool found = false;
  for (JsonObject node : nodes) {
    if (node["id"].as<String>() == newId) {
      found = true;
      node["mac"] = mac;
      node["name"] = name;
      node["chip"] = nodeChip;
      node["mode"] = nodeMode;
      node["port"] = nodePort;
      node["fw"] = nodeFw;
      if (apEnabled) {
        node["ap_enabled"] = true;
        node["ap_hidden"] = apHidden;
        node["ap_ssid"] = apSsid;
        node["ap_pass"] = apPass;
      }
      if (node.containsKey("ap_enabled") && node["ap_enabled"].as<bool>()) {
        delay(40);
        String apS = node.containsKey("ap_ssid") ? node["ap_ssid"].as<String>() : ("MiniHA_" + newId);
        String apP = node.containsKey("ap_pass") ? node["ap_pass"].as<String>() : "";
        int apH = (node.containsKey("ap_hidden") && node["ap_hidden"].as<bool>()) ? 1 : 0;
        broadcastBusPacket(buildPacket(newId, "M", "CFG", "AP:1:" + apS + ":" + apP + ":" + String(apH)));
      }
      if (node.containsKey("components")) {
        int idx = 0;
        for (JsonObject comp : node["components"].as<JsonArray>()) {
          delay(40);
          int type = comp["type"].as<int>();
          int pin1 = comp.containsKey("pin1") ? comp["pin1"].as<int>() : 255;
          int pin2 = comp.containsKey("pin2") ? comp["pin2"].as<int>() : 255;
          int flags = comp.containsKey("flags") ? comp["flags"].as<int>() : 0;
          int param1 = comp.containsKey("param1") ? comp["param1"].as<int>() : 0;
          String compId = comp.containsKey("id") ? comp["id"].as<String>() : ("c" + String(idx));
          String p = "COMP:" + String(idx) + ":" + String(type) + ":" + String(pin1) + ":" + String(pin2) + ":" + String(flags) + ":" + String(param1) + ":" + compId;
          broadcastBusPacket(buildPacket(newId, "M", "CFG", p));
          idx++;
        }
      }
      if (node.containsKey("slots")) {
        for (JsonObject slot : node["slots"].as<JsonArray>()) {
          delay(40);
          String p = "SLOT:" + String(slot["slot"].as<int>()) + 
                     ":GPIO:" + String(slot["gpio"].as<int>()) + 
                     ":TYPE:" + String(slot["type"].as<int>()) + 
                     ":INV:" + String(slot["activeLow"].as<int>());
          broadcastBusPacket(buildPacket(newId, "M", "CFG", p));
        }
      }
      break;
    }
  }

  if (!found) {
    JsonObject n = nodes.createNestedObject();
    n["id"] = newId;
    n["name"] = name;
    n["mac"] = mac;
    n["chip"] = nodeChip;
    n["mode"] = nodeMode;
    n["port"] = nodePort;
    n["fw"] = nodeFw;
    n["ap_enabled"] = apEnabled;
    n["ap_hidden"] = apHidden;
    n["ap_ssid"] = apSsid;
    n["ap_pass"] = apPass;
    n.createNestedArray("components");
    n.createNestedArray("slots");
    n.createNestedArray("links");
    n.createNestedArray("schedules");
  }

  File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
  if (outF) {
    serializeJson(doc, outF);
    outF.close();
  }
  removePendingDevice(mac);
  mqttSchemaNeedsPublish = true;
}

// Bus Packet Handler (RS-422 and Wireless Mesh)
void handleIncomingBusPacket(const ParsedPacket& pkt, uint8_t portNum) {
  if (pkt.to != "M") return;

  // 1. Factory Discovery Announcement
  if (pkt.verb == "ANN") {
    int mIdx = pkt.payload.indexOf("MAC:") + 4;
    int cIdx = pkt.payload.indexOf(":CHIP:");
    int gIdx = pkt.payload.indexOf(":GPIOS:");
    int sIdx = pkt.payload.indexOf(":SLOTS:");
    int modeIdx = pkt.payload.indexOf(":MODE:");
    int fwIdx = pkt.payload.indexOf(":FW:");

    if (cIdx != -1 && gIdx != -1) {
      String mac = pkt.payload.substring(mIdx, cIdx);
      String chip = pkt.payload.substring(cIdx + 6, gIdx);
      String gpios = pkt.payload.substring(gIdx + 7, sIdx);
      uint8_t slots = (sIdx != -1) ? pkt.payload.substring(sIdx + 7, (modeIdx != -1) ? modeIdx : pkt.payload.length()).toInt() : 16;
      String mode = (modeIdx != -1) ? pkt.payload.substring(modeIdx + 6, (pkt.payload.indexOf(':', modeIdx + 6) != -1 ? pkt.payload.indexOf(':', modeIdx + 6) : pkt.payload.length())) : ((portNum == 3) ? "WIFI" : "WIRED");
      String fw = (fwIdx != -1) ? pkt.payload.substring(fwIdx + 4) : "v0.1.1-beta";
      registerPendingDevice(mac, chip, gpios, slots, portNum, mode, fw);
    }
  }
  // 2. Periodic Telemetry Reply or Push-on-Change Sensor Delta
  else if (pkt.verb == "REP" || pkt.verb == "DATA") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) {
      ns->lastSeen = millis();
      ns->port = portNum;

      // Check for component token format: pump=1:tank=142,71:climate=27.4,62
      if (pkt.payload.indexOf('=') != -1) {
        int curPos = 0;
        int len = pkt.payload.length();
        while (curPos < len) {
          int nextColon = pkt.payload.indexOf(':', curPos);
          if (nextColon == -1) nextColon = len;
          String token = pkt.payload.substring(curPos, nextColon);
          int eqIdx = token.indexOf('=');
          if (eqIdx != -1) {
            String key = token.substring(0, eqIdx);
            String valStr = token.substring(eqIdx + 1);
            int commaIdx = valStr.indexOf(',');
            float v1 = 0.0;
            float v2 = 0.0;
            if (commaIdx != -1) {
              v1 = valStr.substring(0, commaIdx).toFloat();
              v2 = valStr.substring(commaIdx + 1).toFloat();
            } else {
              v1 = valStr.toFloat();
            }
            ns->setComponentData(key, v1, v2);

            // Backward compatibility shortcuts & hardware metadata
            if (key == "heap") {
              ns->freeHeap = (uint32_t)v1;
            } else if (key == "fw") {
              ns->fwVersion = valStr;
            } else if (key == "mode") {
              ns->mode = valStr;
            } else if (key.indexOf("tank") != -1 || key.indexOf("dist") != -1) {
              ns->distance = (int)v1;
            } else if (key.indexOf("climate") != -1 || key.indexOf("dht") != -1) {
              ns->temp = v1;
              ns->hum = v2;
            }
          }
          curPos = nextColon + 1;
        }
      }

      int lvlIdx = pkt.payload.indexOf("LVL:");
      int tmpIdx = pkt.payload.indexOf(":TMP:");
      int humIdx = pkt.payload.indexOf(":HUM:");
      int outIdx = pkt.payload.indexOf(":OUT:");

      if (lvlIdx != -1 && tmpIdx != -1) {
        ns->distance = pkt.payload.substring(lvlIdx + 4, tmpIdx).toInt();
      }
      if (tmpIdx != -1 && humIdx != -1) {
        ns->temp = pkt.payload.substring(tmpIdx + 5, humIdx).toFloat();
      }
      if (humIdx != -1 && outIdx != -1) {
        ns->hum = pkt.payload.substring(humIdx + 5, outIdx).toFloat();
      }
      if (outIdx != -1) {
        String outs = pkt.payload.substring(outIdx + 5);
        int slotIdx = 0;
        int lastColon = -1;
        while (slotIdx < MAX_COMPONENTS) {
          int nextColon = outs.indexOf(':', lastColon + 1);
          String valStr = (nextColon == -1) ? outs.substring(lastColon + 1) : outs.substring(lastColon + 1, nextColon);
          bool st = (valStr.toInt() == 1);
          ns->relayStates[slotIdx] = st;
          ns->slotValues[slotIdx] = st ? 1.0 : 0.0;
          slotIdx++;
          if (nextColon == -1) break;
          lastColon = nextColon;
        }
      }

      // Parse multi-sensor slot tokens: :S<slot>:<val>, :S<slot>T:<val>, :S<slot>H:<val>
      int curPos = 0;
      while ((curPos = pkt.payload.indexOf(":S", curPos)) != -1) {
        int nextColon = pkt.payload.indexOf(':', curPos + 2);
        if (nextColon == -1) break;
        String tag = pkt.payload.substring(curPos + 2, nextColon);
        int afterValColon = pkt.payload.indexOf(':', nextColon + 1);
        String valStr = (afterValColon == -1) ? pkt.payload.substring(nextColon + 1) : pkt.payload.substring(nextColon + 1, afterValColon);

        if (tag.endsWith("T")) {
          int s = tag.substring(0, tag.length() - 1).toInt();
          if (s >= 0 && s < MAX_COMPONENTS) ns->slotValues[s] = valStr.toFloat();
        } else if (tag.endsWith("H")) {
          int s = tag.substring(0, tag.length() - 1).toInt();
          if (s >= 0 && s < MAX_COMPONENTS) ns->slotSecondary[s] = valStr.toFloat();
        } else {
          int s = tag.toInt();
          if (s >= 0 && s < MAX_COMPONENTS) ns->slotValues[s] = valStr.toFloat();
        }
        curPos = nextColon + 1;
      }

      // Real-time Event-Driven Rule & Alert Evaluation on Telemetry / Delta Update
      evaluateDynamicRules();
      evaluateNotificationRules();
    }
  }
  // 3. Instant Slot State Event
  else if (pkt.verb == "EVT") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) {
      ns->lastSeen = millis();
      int compIdx = pkt.payload.indexOf("COMP:");
      int sIdx = pkt.payload.indexOf("SLOT:");
      int stIdx = pkt.payload.indexOf(":STATE:");

      if (compIdx != -1 && stIdx != -1) {
        String cid = pkt.payload.substring(compIdx + 5, stIdx);
        int state = pkt.payload.substring(stIdx + 7).toInt();
        ns->setComponentData(cid, state);
        publishMqttState();
      } else if (sIdx != -1 && stIdx != -1) {
        int slot = pkt.payload.substring(sIdx + 5, stIdx).toInt();
        int state = pkt.payload.substring(stIdx + 7).toInt();
        if (slot >= 0 && slot < MAX_COMPONENTS) {
          ns->relayStates[slot] = (state == 1);
          ns->slotValues[slot] = (state == 1) ? 1.0 : 0.0;
          ns->setComponentData("slot" + String(slot), state);
          publishMqttState();
        }
      }

      // Real-time Event-Driven Rule & Alert Evaluation on Relay / Actuator State Change
      evaluateDynamicRules();
      evaluateNotificationRules();
    }
  }
  // 4. Physical Input Trigger Event
  else if (pkt.verb == "INPUT") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) {
      ns->lastSeen = millis();
      int compIdx = pkt.payload.indexOf("COMP:");
      int sIdx = pkt.payload.indexOf("SLOT:");
      int stIdx = pkt.payload.indexOf(":STATE:");

      if (compIdx != -1 && stIdx != -1) {
        String cid = pkt.payload.substring(compIdx + 5, stIdx);
        int state = pkt.payload.substring(stIdx + 7).toInt();
        ns->setComponentData(cid, state);
      } else if (sIdx != -1 && stIdx != -1) {
        int slot = pkt.payload.substring(sIdx + 5, stIdx).toInt();
        int state = pkt.payload.substring(stIdx + 7).toInt();
        if (slot >= 0 && slot < MAX_COMPONENTS) {
          ns->slotValues[slot] = state;
          ns->setComponentData("slot" + String(slot), state);
        }
      }

      // Real-time Event-Driven Rule & Alert Evaluation on Physical Button / Switch Input (<5ms response)
      evaluateDynamicRules();
      evaluateNotificationRules();
    }
  }
  // 5. Slave Acknowledgment
  else if (pkt.verb == "ACK") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) ns->lastSeen = millis();
    Serial.printf("[ACK] Node %s: %s\n", pkt.from.c_str(), pkt.payload.c_str());
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.printf("\n[MASTER] Booting Mini-HomeAssistant Supervisor v0.1.1-beta on %s...\n", MASTER_CHIP_NAME);
  // Initialize Isolated RS-422 Star Hardware Serial Ports
  BusPort1.begin(115200, SERIAL_8N1, PORT1_RX_PIN, PORT1_TX_PIN);
  Serial.printf("[MASTER] Star Port 1: UART1 (RX: GPIO%d, TX: GPIO%d)\n", PORT1_RX_PIN, PORT1_TX_PIN);
#if !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(ESP32C3)
  BusPort2.begin(115200, SERIAL_8N1, PORT2_RX_PIN, PORT2_TX_PIN);
  Serial.printf("[MASTER] Star Port 2: UART2 (RX: GPIO%d, TX: GPIO%d)\n", PORT2_RX_PIN, PORT2_TX_PIN);
#endif

  // Initialize LittleFS Flash Storage
  initLittleFSStorage();
  loadSystemSecurity();

  // Network Provisioning & Standalone SoftAP Setup:
  // If home Wi-Fi credentials exist, try connecting as STA for 8 seconds.
  bool connectedSTA = false;
  if (sysSecurity.staEnabled && sysSecurity.staSsid.length() > 0) {
    Serial.printf("[WIFI] Connecting to Home Wi-Fi: %s (Hidden: %d)...\n", sysSecurity.staSsid.c_str(), sysSecurity.staHidden ? 1 : 0);
    WiFi.mode(WIFI_AP_STA);
    if (sysSecurity.staHidden) {
      WiFi.begin(sysSecurity.staSsid.c_str(), sysSecurity.staPass.c_str(), 0, nullptr, true);
    } else {
      WiFi.begin(sysSecurity.staSsid.c_str(), sysSecurity.staPass.c_str());
    }

    unsigned long startAttempt = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < 8000) {
      delay(250);
      Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
      connectedSTA = true;
      Serial.printf("\n[WIFI] Connected to Home Network! Local STA IP: %s\n", WiFi.localIP().toString().c_str());
    } else {
      Serial.println("\n[WIFI] Could not connect to Home Wi-Fi. Operating in pure standalone SoftAP mode.");
      WiFi.disconnect(true, false);
      WiFi.mode(WIFI_AP);
    }
  } else {
    WiFi.disconnect(true, false);
    WiFi.mode(WIFI_AP);
  }

  // Always broadcast SoftAP for isolated mesh slaves and direct local web dashboard access
  IPAddress apIP(192, 168, 4, 1);
  IPAddress apGW(192, 168, 4, 1);
  IPAddress apMask(255, 255, 255, 0);
  WiFi.softAPConfig(apIP, apGW, apMask);
  bool apStarted = WiFi.softAP(sysSecurity.apSsid.c_str(), sysSecurity.apPass.c_str());
  if (apStarted) {
    dnsServer.start(53, "miniha.local", apIP);
    Serial.printf("[AP] Isolated Star-Mesh SoftAP '%s' active at http://%s\n", 
                  sysSecurity.apSsid.c_str(), WiFi.softAPIP().toString().c_str());
  } else {
    Serial.printf("[AP] ERROR: Failed to start SoftAP '%s'!\n", sysSecurity.apSsid.c_str());
  }

  // mDNS Responder: broadcast http://miniha.local
  if (MDNS.begin("miniha")) {
    MDNS.addService("http", "tcp", 80);
    Serial.println("[mDNS] Responder started at http://miniha.local");
  }

  // Setup Web Endpoints & Collect Session Headers
  const char* headerkeys[] = {"Cookie", "X-Auth-Token"};
  webServer.collectHeaders(headerkeys, 2);
  webServer.enableCORS(true);
  setupWebEndpoints();
  webServer.begin();

  // Start Direct Wireless TCP Mesh Server (Port 8266)
  meshServer.begin();
  meshServer.setNoDelay(true);
  Serial.printf("[MESH] Direct Wireless TCP Socket Server active on port %d\n", DEFAULT_MESH_PORT);

  // Initialize Cloud MQTT Client if configured
  if (sysSecurity.mqttEnabled && connectedSTA && sysSecurity.mqttBroker.length() > 0) {
    Serial.printf("[MQTT] Cloud Bridge enabled for broker: %s:%d (Home ID: %s)\n", 
                  sysSecurity.mqttBroker.c_str(), sysSecurity.mqttPort, sysSecurity.mqttHomeId.c_str());
  } else {
    Serial.println("[MQTT] Cloud Bridge dormant (Local Star-Mesh & Web Dashboard Active).");
  }

  Serial.println("[MASTER] Supervisor initialization complete.");
}

void loop() {
  // 1. Maintain Captive DNS, Web Server & Cloud MQTT Bridge
  dnsServer.processNextRequest();
  webServer.handleClient();
  maintainMqtt();

  // 2. Read incoming packets from isolated full-duplex star ports
  pollBusPort(BusPort1, busRxBuf1, 1);
#if !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(ESP32C3)
  pollBusPort(BusPort2, busRxBuf2, 2);
#endif

  // 2b. Maintain Direct Wireless TCP Mesh Clients (Port 8266)
  if (meshServer.hasClient()) {
    WiFiClient newClient = meshServer.available();
    if (newClient) {
      bool accepted = false;
      for (uint8_t c = 0; c < MAX_MESH_CLIENTS; c++) {
        if (!meshClients[c] || !meshClients[c].connected()) {
          meshClients[c] = newClient;
          meshRxBuf[c] = "";
          accepted = true;
          Serial.printf("[MESH] Wireless slave socket accepted on slot %d from %s\n", c, newClient.remoteIP().toString().c_str());
          break;
        }
      }
      if (!accepted) {
        newClient.stop();
        Serial.println("[MESH] Max wireless slave sockets reached. Rejected connection.");
      }
    }
  }

  for (uint8_t c = 0; c < MAX_MESH_CLIENTS; c++) {
    if (meshClients[c] && meshClients[c].connected()) {
      while (meshClients[c].available()) {
        char ch = (char)meshClients[c].read();
        if (ch == '\n') {
          meshRxBuf[c].trim();
          if (meshRxBuf[c].length() > 0) {
            ParsedPacket pkt = parseProtocolLine(meshRxBuf[c]);
            if (pkt.isValid) {
              handleIncomingBusPacket(pkt, 3 /* PORT 3 = WIFI MESH */);
            }
          }
          meshRxBuf[c] = "";
        } else if (ch != '\r') {
          meshRxBuf[c] += ch;
          if (meshRxBuf[c].length() > PROTOCOL_MAX_LINE) meshRxBuf[c] = "";
        }
      }
    }
  }

  // 3. Evaluate Dynamic Rules & Notification Engine every 500ms
  if (millis() - lastRulePoll > 500) {
    lastRulePoll = millis();
    evaluateDynamicRules();
    evaluateNotificationRules();
  }

  // 4. Broadcast Poll to active slaves on RS-422 bus every 500ms (sub-second real-time responsiveness)
  if (millis() - lastBusPoll > 500) {
    lastBusPoll = millis();
    broadcastBusPacket(buildPacket("ALL", "M", "REQ", "POLL"));
  }

  // 5. Periodic Real-Time Clock Synchronization to Slaves (every 60 seconds)
  static unsigned long lastTimeSync = 0;
  if (millis() - lastTimeSync > 60000) {
    lastTimeSync = millis();
    time_t now = time(nullptr);
    if (now > 1700000000) {
      broadcastBusPacket(buildPacket("ALL", "M", "TIME", String((uint32_t)now)));
    }
  }
}
