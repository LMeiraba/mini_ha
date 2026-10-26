#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <SuplaDevice.h>
#include <supla/control/relay.h>
#include <supla/control/virtual_relay.h>
#include <supla/sensor/general_purpose_measurement.h>
#include <supla/sensor/virtual_therm_hygro_meter.h>
#include <supla/network/esp_wifi.h>

#include "node_protocol.h"
#include "supla_config.h"
#include "storage_manager.h"
#include "rules_engine.h"
#include "web_dashboard.h"

// =========================================================================
// MINI-HOMEASSISTANT MASTER SUPERVISOR (ESP32-C3 & ESP32-DevKit)
// =========================================================================

// Silicon Hardware Pin Mapping
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
  #define MASTER_CHIP_NAME     "ESP32-C3"
  #define LOCAL_PUMP_PIN       8
  #define LOCAL_MANUAL_BTN     9
  #define S1_UART_RX_PIN       4
  #define S1_UART_TX_PIN       5
  #define SERIAL_BUS_UART_NUM  1
#else
  // Classic ESP32 Dev Board (Dual-Core Xtensa ESP32-WROOM-32)
  // Safe GPIOs avoiding SPI Flash (6-11) and Boot Strapping pins (0, 2, 12, 15)
  #define MASTER_CHIP_NAME     "ESP32-DevKit"
  #define LOCAL_PUMP_PIN       18   // Dedicated relay output
  #define LOCAL_MANUAL_BTN     19   // Dedicated manual button (pullup)
  #define S1_UART_RX_PIN       16   // Default Hardware RX2 on ESP32
  #define S1_UART_TX_PIN       17   // Default Hardware TX2 on ESP32
  #define SERIAL_BUS_UART_NUM  2
#endif

HardwareSerial SerialBus(SERIAL_BUS_UART_NUM);
WebServer webServer(80);

// Wireless Star-Mesh TCP Server
#define MAX_WIRELESS_SLAVES 8
WiFiServer meshServer(DEFAULT_MESH_PORT);
WiFiClient meshClients[MAX_WIRELESS_SLAVES];
String meshRxBuf[MAX_WIRELESS_SLAVES];

// Unified Packet Dispatcher: Broadcasts to RS-422 bus AND connected wireless slaves
void broadcastBusPacket(const String& pkt) {
  SerialBus.println(pkt);
  for (int i = 0; i < MAX_WIRELESS_SLAVES; i++) {
    if (meshClients[i] && meshClients[i].connected()) {
      meshClients[i].println(pkt);
    }
  }
}

// Global State & Storage instances
PendingNode pendingNodes[MAX_PENDING_NODES];
uint8_t numPendingNodes = 0;
MasterTelemetryCache sysState;

String busRxBuf = "";
unsigned long lastRulePoll = 0;
unsigned long lastBusPoll = 0;

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
    if (doc.containsKey("admin_user")) sysSecurity.adminUser = doc["admin_user"].as<String>();
    if (doc.containsKey("admin_pass")) sysSecurity.adminPass = doc["admin_pass"].as<String>();
    if (doc.containsKey("member_user")) sysSecurity.memberUser = doc["member_user"].as<String>();
    if (doc.containsKey("member_pass")) sysSecurity.memberPass = doc["member_pass"].as<String>();
    if (doc.containsKey("guest_user")) sysSecurity.guestUser = doc["guest_user"].as<String>();
    if (doc.containsKey("guest_pass")) sysSecurity.guestPass = doc["guest_pass"].as<String>();
  }
  if (sysSecurity.apSsid.length() == 0) sysSecurity.apSsid = "Mini-HA-Master";
  if (sysSecurity.apPass.length() < 8) sysSecurity.apPass = "12345678";
}

// =========================================================================
// SUPLA INTERFACE & OPTIONAL CLOUD BRIDGE
// =========================================================================
Supla::ESPWifi *suplaWifi = nullptr;
bool suplaActive = false;

Supla::Control::Relay *pumpRelay = nullptr;
Supla::Sensor::GeneralPurposeMeasurement *pumpHistoryGpm = nullptr;

Supla::Sensor::GeneralPurposeMeasurement *roofLevelGpm = nullptr;
Supla::Sensor::VirtualThermHygroMeter *roofWeather = nullptr;

void executeAction(const String& target, const String& cmd, int val, const String& reason) {
  if (target == "LOCAL" && cmd == "SET_PUMP") {
    bool state = (val == 1);
    if (state == sysState.pumpState) return;

    sysState.pumpState = state;
    digitalWrite(LOCAL_PUMP_PIN, state ? HIGH : LOW);
    if (state) sysState.pumpStartTime = millis();

    if (pumpRelay) {
      if (state) pumpRelay->turnOn(); else pumpRelay->turnOff();
    }
    if (pumpHistoryGpm) pumpHistoryGpm->setValue(state ? 1.0 : 0.0);

    Serial.printf("[ACTION] Pump turned %s | Reason: %s\n", state ? "ON" : "OFF", reason.c_str());
  } else if (target.startsWith("N")) {
    // Send command to remote slave node over bus
    broadcastBusPacket(buildPacket(target, "M", "SET", "SLOT:" + String(val) + ":STATE:1"));
  }
}

void triggerProvisionNode(const String& mac, const String& newId) {
  Serial.printf("[PROV] Dispatching BIND packet for MAC=%s -> ID=%s\n", mac.c_str(), newId.c_str());
  broadcastBusPacket(buildPacket("NEW", "M", "BIND", "MAC:" + mac + ":SET_ID:" + newId));

  // If newId is in nodes.json, stream its configured slots
  File file = LittleFS.open(NODES_CONFIG_PATH, "r");
  if (!file) return;

  DynamicJsonDocument doc(4096);
  deserializeJson(doc, file);
  file.close();

  for (JsonObject node : doc["nodes"].as<JsonArray>()) {
    if (node["id"].as<String>() == newId) {
      for (JsonObject slot : node["slots"].as<JsonArray>()) {
        delay(40);
        String p = "SLOT:" + String(slot["slot"].as<int>()) + 
                   ":GPIO:" + String(slot["gpio"].as<int>()) + 
                   ":TYPE:" + String(slot["type"].as<int>()) + 
                   ":INV:" + String(slot["activeLow"].as<int>());
        broadcastBusPacket(buildPacket(newId, "M", "CFG", p));
      }
      for (JsonObject link : node["links"].as<JsonArray>()) {
        delay(40);
        String p = "LINK:" + String(link["idx"].as<int>()) + 
                   ":TRIG:" + String(link["trig"].as<int>()) + 
                   ":TGT:" + String(link["tgt"].as<int>()) + 
                   ":ACT:" + String(link["act"].as<int>());
        broadcastBusPacket(buildPacket(newId, "M", "CFG", p));
      }
      break;
    }
  }
}

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
    if (pkt.from == "N01") {
      int lvlIdx = pkt.payload.indexOf("LVL:") + 4;
      int tmpIdx = pkt.payload.indexOf(":TMP:");
      int humIdx = pkt.payload.indexOf(":HUM:");
      int outIdx = pkt.payload.indexOf(":OUT:");

      if (tmpIdx != -1 && humIdx != -1) {
        sysState.rooftopLevel = pkt.payload.substring(lvlIdx, tmpIdx).toInt();
        sysState.rooftopTemp = pkt.payload.substring(tmpIdx + 5, humIdx).toFloat();
        sysState.rooftopHum = pkt.payload.substring(humIdx + 5, outIdx).toFloat();
        sysState.lastRooftopHeartbeat = millis();

        if (roofLevelGpm) roofLevelGpm->setValue(sysState.rooftopLevel);
        if (roofWeather) {
          roofWeather->setTemp(sysState.rooftopTemp);
          roofWeather->setHumi(sysState.rooftopHum);
        }
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.printf("\n[MASTER] Booting Mini-HomeAssistant Supervisor on %s...\n", MASTER_CHIP_NAME);
  Serial.printf("[MASTER] RS-422 Bus: UART%d (RX: GPIO%d, TX: GPIO%d)\n", SERIAL_BUS_UART_NUM, S1_UART_RX_PIN, S1_UART_TX_PIN);

  pinMode(LOCAL_PUMP_PIN, OUTPUT);
  pinMode(LOCAL_MANUAL_BTN, INPUT_PULLUP);
  digitalWrite(LOCAL_PUMP_PIN, LOW);

  // Initialize Isolated RS-422 Hardware Serial Bus
  SerialBus.begin(115200, SERIAL_8N1, S1_UART_RX_PIN, S1_UART_TX_PIN);

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
    Serial.printf("[AP] Isolated Star-Mesh SoftAP '%s' active at http://%s\n", 
                  sysSecurity.apSsid.c_str(), WiFi.softAPIP().toString().c_str());
  } else {
    Serial.printf("[AP] ERROR: Failed to start SoftAP '%s'!\n", sysSecurity.apSsid.c_str());
  }

  // Setup Web Endpoints with Digest Authentication
  setupWebEndpoints();
  webServer.begin();

  // Initialize Wireless Star-Mesh TCP Server
  meshServer.begin();
  Serial.printf("[MESH] Wireless Star-Mesh TCP Server live on port %d\n", DEFAULT_MESH_PORT);

  // Initialize Supla Cloud Client (Optional Bridge: only if STA is connected and real credentials exist)
  bool hasSuplaConfig = (connectedSTA &&
                         strcmp(SUPLA_SERVER, "svrX.supla.org") != 0 && 
                         strcmp(SUPLA_EMAIL, "your_email@example.com") != 0);
  if (hasSuplaConfig) {
    Serial.println("[SUPLA] Real Supla Cloud credentials detected. Initializing bridge...");
    suplaWifi = new Supla::ESPWifi(sysSecurity.staSsid.c_str(), sysSecurity.staPass.c_str());
    pumpRelay = new Supla::Control::Relay(LOCAL_PUMP_PIN, true);
    pumpHistoryGpm = new Supla::Sensor::GeneralPurposeMeasurement();
    roofLevelGpm = new Supla::Sensor::GeneralPurposeMeasurement();
    roofWeather = new Supla::Sensor::VirtualThermHygroMeter();
    SuplaDevice.begin();
    suplaActive = true;
  } else {
    Serial.println("[SUPLA] Offline Mode: Supla Cloud dormant (Local Star-Mesh & Web Dashboard Active).");
  }

  Serial.println("[MASTER] Supervisor initialization complete.");
}

void loop() {
  // 1. Maintain Web Server & Supla Cloud
  webServer.handleClient();
  if (suplaActive) {
    SuplaDevice.iterate();
  }

  // 2. Read incoming packets from isolated RS-422 bus
  while (SerialBus.available()) {
    char c = (char)SerialBus.read();
    if (c == '\n') {
      busRxBuf.trim();
      if (busRxBuf.length() > 0) {
        ParsedPacket pkt = parseProtocolLine(busRxBuf);
        if (pkt.isValid) {
          handleIncomingBusPacket(pkt);
        }
      }
      busRxBuf = "";
    } else if (c != '\r') {
      busRxBuf += c;
      if (busRxBuf.length() > PROTOCOL_MAX_LINE) busRxBuf = "";
    }
  }

  // 3. Accept incoming wireless mesh clients
  if (meshServer.hasClient()) {
    WiFiClient newClient = meshServer.available();
    bool accepted = false;
    for (int i = 0; i < MAX_WIRELESS_SLAVES; i++) {
      if (!meshClients[i] || !meshClients[i].connected()) {
        meshClients[i] = newClient;
        meshRxBuf[i] = "";
        Serial.printf("[MESH] Wireless slave connected on slot %d (IP: %s)\n", i, newClient.remoteIP().toString().c_str());
        accepted = true;
        break;
      }
    }
    if (!accepted) {
      newClient.stop();
    }
  }

  // 4. Read incoming packets from wireless mesh TCP clients
  for (int i = 0; i < MAX_WIRELESS_SLAVES; i++) {
    if (meshClients[i] && meshClients[i].connected()) {
      while (meshClients[i].available()) {
        char c = (char)meshClients[i].read();
        if (c == '\n') {
          meshRxBuf[i].trim();
          if (meshRxBuf[i].length() > 0) {
            ParsedPacket pkt = parseProtocolLine(meshRxBuf[i]);
            if (pkt.isValid) {
              handleIncomingBusPacket(pkt);
            }
          }
          meshRxBuf[i] = "";
        } else if (c != '\r') {
          meshRxBuf[i] += c;
          if (meshRxBuf[i].length() > PROTOCOL_MAX_LINE) meshRxBuf[i] = "";
        }
      }
    }
  }

  // 5. Evaluate Dynamic Rules Engine every 500ms
  if (millis() - lastRulePoll > 500) {
    lastRulePoll = millis();
    evaluateDynamicRules();
  }

  // 6. Poll active slaves every 2 seconds
  if (millis() - lastBusPoll > 2000) {
    lastBusPoll = millis();
    broadcastBusPacket(buildPacket("N01", "M", "REQ", "POLL"));
  }
}
