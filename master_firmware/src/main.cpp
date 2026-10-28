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

// Unified Star Hub Dispatcher: Broadcasts full-duplex out all physical isolated UART star ports.
// (Each wired slave has its own dedicated physical UART line - zero bus contention)
void broadcastBusPacket(const String& pkt) {
  BusPort1.println(pkt);
#if !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(ESP32C3)
  BusPort2.println(pkt);
#endif
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

void handleIncomingBusPacket(const ParsedPacket& pkt);

void pollBusPort(HardwareSerial& port, String& buf) {
  while (port.available()) {
    char c = (char)port.read();
    if (c == '\n') {
      buf.trim();
      if (buf.length() > 0) {
        ParsedPacket pkt = parseProtocolLine(buf);
        if (pkt.isValid) {
          handleIncomingBusPacket(pkt);
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
    for (int s = 0; s < MAX_GPIO_SLOTS; s++) {
      slotsObj[String(s + 1)] = nodeStates[i].relayStates[s] ? 1 : 0;
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
    if (doc.containsKey("target") && doc.containsKey("slot") && doc.containsKey("state")) {
      String token = doc.containsKey("token") ? doc["token"].as<String>() : "";
      String target = doc["target"].as<String>();
      int slot = doc["slot"].as<int>();
      int state = doc["state"].as<int>();

      String username = "";
      UserRole role = validateToken(token, &username);
      if (role < ROLE_MEMBER) {
        Serial.printf("[SECURITY] Rejected command for '%s': User '%s' unauthorized (Role: %d)\n", 
                      target.c_str(), username.c_str(), role);
        return;
      }

      executeAction(target, slot, state, "MQTT by '" + username + "'");

      GenericNodeTelemetry* ns = getOrCreateNodeState(target);
      if (ns && slot >= 1 && slot <= MAX_GPIO_SLOTS) {
        ns->relayStates[slot - 1] = (state == 1);
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
void triggerProvisionNode(const String& mac, const String& newId, const String& name) {
  Serial.printf("[PROV] Dispatching BIND packet: MAC=%s -> ID=%s (%s)\n", mac.c_str(), newId.c_str(), name.c_str());
  broadcastBusPacket(buildPacket("NEW", "M", "BIND", "MAC:" + mac + ":SET_ID:" + newId));

  File file = LittleFS.open(NODES_CONFIG_PATH, "r");
  DynamicJsonDocument doc(4096);
  if (file) {
    deserializeJson(doc, file);
    file.close();
  }

  JsonArray nodes = doc["nodes"].as<JsonArray>();
  bool found = false;
  for (JsonObject node : nodes) {
    if (node["id"].as<String>() == newId) {
      found = true;
      node["mac"] = mac;
      node["name"] = name;
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
    n.createNestedArray("slots");
    n.createNestedArray("links");
    n.createNestedArray("schedules");
  }

  File outF = LittleFS.open(NODES_CONFIG_PATH, "w");
  if (outF) {
    serializeJson(doc, outF);
    outF.close();
  }
  mqttSchemaNeedsPublish = true;
}

// Bus Packet Handler (RS-422 and Wireless Mesh)
void handleIncomingBusPacket(const ParsedPacket& pkt) {
  if (pkt.to != "M") return;

  // 1. Factory Discovery Announcement
  if (pkt.verb == "ANN") {
    int mIdx = pkt.payload.indexOf("MAC:") + 4;
    int cIdx = pkt.payload.indexOf(":CHIP:");
    int gIdx = pkt.payload.indexOf(":GPIOS:");
    int sIdx = pkt.payload.indexOf(":SLOTS:");

    if (cIdx != -1 && gIdx != -1) {
      String mac = pkt.payload.substring(mIdx, cIdx);
      String chip = pkt.payload.substring(cIdx + 6, gIdx);
      String gpios = pkt.payload.substring(gIdx + 7, sIdx);
      uint8_t slots = pkt.payload.substring(sIdx + 7).toInt();
      registerPendingDevice(mac, chip, gpios, slots);
    }
  }
  // 2. Periodic Telemetry Reply
  else if (pkt.verb == "REP") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) {
      ns->lastSeen = millis();
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
        while (slotIdx < MAX_GPIO_SLOTS) {
          int nextColon = outs.indexOf(':', lastColon + 1);
          String valStr = (nextColon == -1) ? outs.substring(lastColon + 1) : outs.substring(lastColon + 1, nextColon);
          ns->relayStates[slotIdx] = (valStr.toInt() == 1);
          slotIdx++;
          if (nextColon == -1) break;
          lastColon = nextColon;
        }
      }
    }
  }
  // 3. Instant Slot State Event
  else if (pkt.verb == "EVT") {
    GenericNodeTelemetry* ns = getOrCreateNodeState(pkt.from);
    if (ns) {
      ns->lastSeen = millis();
      int sIdx = pkt.payload.indexOf("SLOT:");
      int stIdx = pkt.payload.indexOf(":STATE:");
      if (sIdx != -1 && stIdx != -1) {
        int slot = pkt.payload.substring(sIdx + 5, stIdx).toInt();
        int state = pkt.payload.substring(stIdx + 7).toInt();
        if (slot >= 0 && slot < MAX_GPIO_SLOTS) {
          ns->relayStates[slot] = (state == 1);
          publishMqttState();
        }
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.printf("\n[MASTER] Booting Mini-HomeAssistant Supervisor on %s...\n", MASTER_CHIP_NAME);
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
    Serial.printf("[WIFI] Connecting to Home Wi-Fi: %s...\n", sysSecurity.staSsid.c_str());
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(sysSecurity.staSsid.c_str(), sysSecurity.staPass.c_str());

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
  pollBusPort(BusPort1, busRxBuf1);
#if !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(ESP32C3)
  pollBusPort(BusPort2, busRxBuf2);
#endif

  // 3. Evaluate Dynamic Rules Engine every 500ms
  if (millis() - lastRulePoll > 500) {
    lastRulePoll = millis();
    evaluateDynamicRules();
  }

  // 4. Broadcast Poll to active slaves on RS-422 bus every 3 seconds
  if (millis() - lastBusPoll > 3000) {
    lastBusPoll = millis();
    broadcastBusPacket(buildPacket("ALL", "M", "REQ", "POLL"));
  }
}
