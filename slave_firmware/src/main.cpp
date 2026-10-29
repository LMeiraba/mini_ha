#include <Arduino.h>
#include <EEPROM.h>
#include <DHT.h>
#include "node_protocol.h"
#include "chip_capabilities.h"

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <ESP8266WebServer.h>
  #include <DNSServer.h>
  typedef ESP8266WebServer SlaveWebServer;
#else
  #include <WiFi.h>
  #include <WebServer.h>
  #include <DNSServer.h>
  typedef WebServer SlaveWebServer;
#endif

// =========================================================================
// UNIVERSAL GENERIC SLAVE FIRMWARE (v3.1)
// =========================================================================
// Features:
// 1. Dynamic Hardware Abstraction Layer (HAL) - zero hardcoded pins
// 2. Standalone robust local scheduling (runs even when Master is offline!)
// 3. Sub-millisecond local sensor-actuator link runner (instant wall switches)
// 4. Captive Portal Web Wizard (Option 1 Onboarding) on SLAVE-SETUP-XXXX
// 5. Dual Transport: Wired (RS-422 / Serial) or Wireless (Wi-Fi Mesh Client)
// 6. Transparent repeater bridge support (Wired slave hosts SoftAP for child nodes)
// =========================================================================

NodeStorageConfig config;

#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
  #if ARDUINO_USB_CDC_ON_BOOT
    #define BusSerial Serial0
  #else
    #define BusSerial Serial
  #endif
#else
  #define BusSerial Serial
#endif

// Timekeeping variables (Synced from Master, kept alive by millis())
uint32_t currentEpoch = 0;
unsigned long lastEpochSyncMillis = 0;

// Hardware Components & Telemetry Metric Cache
DHT* dhtSensors[MAX_COMPONENTS] = {nullptr};
float compValues[MAX_COMPONENTS] = {0.0};
float compSecondary[MAX_COMPONENTS] = {0.0};
float lastReportedValues[MAX_COMPONENTS] = { -9999.0f };
float lastReportedSecondary[MAX_COMPONENTS] = { -9999.0f };
bool compOutputStates[MAX_COMPONENTS] = {false};
int lastInputStates[MAX_COMPONENTS] = {LOW};
unsigned long lastToggleTime[MAX_COMPONENTS] = {0};
unsigned long lastFastSensorPoll = 0;
unsigned long lastSlowSensorPoll = 0;
unsigned long lastAnnounceTime = 0;

// Buffers & Networking
String rxBuffer = "";
String netRxBuffer = "";
WiFiClient tcpClient;
WiFiServer* bridgeServer = nullptr;
WiFiClient bridgeClient;
unsigned long lastTcpRetry = 0;

// Captive Portal Objects
DNSServer* dnsServer = nullptr;
SlaveWebServer* portalServer = nullptr;
bool inCaptivePortal = false;
const byte DNS_PORT = 53;

// Forward declarations
void applyHardwareConfiguration();
void saveConfig();
void sendAnnouncement();
void setComponentOutput(uint8_t compIdx, bool state, bool pushNotify = true);
void toggleComponentOutput(uint8_t compIdx, bool pushNotify = true);
void startCaptivePortal();
void stopCaptivePortal();

inline uint32_t getLocalEpoch() {
  if (currentEpoch == 0) return 0;
  return currentEpoch + ((millis() - lastEpochSyncMillis) / 1000);
}

void loadConfigFromStorage() {
  EEPROM.begin(sizeof(NodeStorageConfig));
  EEPROM.get(0, config);

  if (config.magic != SCHEMA_MAGIC) {
    Serial.println("[STORAGE] Invalid magic or schema mismatch! Initializing factory defaults...");
    memset(&config, 0, sizeof(NodeStorageConfig));
    config.magic = SCHEMA_MAGIC;
    memset(config.nodeId, 0, sizeof(config.nodeId));
    strncpy(config.nodeId, "UNBOUND", sizeof(config.nodeId));
    config.transportMode = MODE_WIRED; // Default to wired RS-422 star bus
    config.wifiSsid[0] = '\0';
    config.wifiPass[0] = '\0';
    strncpy(config.masterHost, "192.168.4.1", sizeof(config.masterHost) - 1);
    config.masterPort = DEFAULT_MESH_PORT;
    config.apEnabled = 0;
    strncpy(config.apSsid, "SlaveNet-01", sizeof(config.apSsid) - 1);
    strncpy(config.apPass, "12345678", sizeof(config.apPass) - 1);
    config.numConfiguredComponents = 0;
    config.numConfiguredLinks = 0;
    config.numConfiguredSchedules = 0;
    saveConfig();
  } else {
    Serial.printf("[STORAGE] Loaded config for Node: %s | Mode: %s (Comps: %d, Links: %d, Scheds: %d)\n", 
      config.nodeId, (config.transportMode == MODE_WIRELESS ? "WIRELESS" : "WIRED"),
      config.numConfiguredComponents, config.numConfiguredLinks, config.numConfiguredSchedules);
  }
}

void saveConfig() {
  EEPROM.put(0, config);
  EEPROM.commit();
}

void applyHardwareConfiguration() {
  for (int i = 0; i < MAX_COMPONENTS; i++) {
    if (dhtSensors[i]) {
      delete dhtSensors[i];
      dhtSensors[i] = nullptr;
    }
    compValues[i] = 0;
    compSecondary[i] = 0;
    lastReportedValues[i] = -9999.0f;
    lastReportedSecondary[i] = -9999.0f;
    compOutputStates[i] = false;
    lastInputStates[i] = LOW;
    lastToggleTime[i] = 0;

    ComponentConfig& c = config.components[i];
    if (c.type == COMP_UNUSED) continue;

    if (c.type == COMP_RELAY && isSafeGpio(c.pin1)) {
      pinMode(c.pin1, OUTPUT);
      bool activeLow = (c.flags & 1);
      digitalWrite(c.pin1, activeLow ? HIGH : LOW); // Default OFF
    } else if ((c.type == COMP_BUTTON || c.type == COMP_TOUCH || c.type == COMP_TOGGLE_SWITCH) && isSafeGpio(c.pin1)) {
      bool pullup = (c.flags & 1) || (c.type == COMP_BUTTON) || (c.type == COMP_TOGGLE_SWITCH);
      pinMode(c.pin1, pullup ? INPUT_PULLUP : INPUT);
      lastInputStates[i] = digitalRead(c.pin1);
      compValues[i] = lastInputStates[i];
    } else if (c.type == COMP_ULTRASONIC && isSafeGpio(c.pin1) && isSafeGpio(c.pin2)) {
      pinMode(c.pin1, OUTPUT); // Trig
      digitalWrite(c.pin1, LOW);
      pinMode(c.pin2, INPUT);  // Echo
      compValues[i] = -1;
    } else if (c.type == COMP_DHT && isSafeGpio(c.pin1)) {
      bool isDht22 = (c.flags & 2);
      dhtSensors[i] = new DHT(c.pin1, isDht22 ? DHT22 : DHT11);
      dhtSensors[i]->begin();
    }
  }
  Serial.println("[HAL] Applied peripheral components hardware configuration.");
}

// Unified packet transmitter: Sends to Serial and/or active TCP connection
void sendPacketToMaster(const String& verb, const String& payload) {
  String pkt = buildPacket("M", config.nodeId, verb, payload);
  
  // 1. Output to Hardware Serial Bus (always available for wired bus)
  BusSerial.println(pkt);
  #if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
    #if ARDUINO_USB_CDC_ON_BOOT
      Serial.println(pkt); // Also echo to USB console if separate
    #endif
  #endif

  // 2. Output to Wireless TCP Client if in wireless mode
  if (config.transportMode == MODE_WIRELESS && tcpClient.connected()) {
    tcpClient.println(pkt);
  }
}

void setComponentOutput(uint8_t compIdx, bool state, bool pushNotify) {
  if (compIdx >= MAX_COMPONENTS) return;
  ComponentConfig& c = config.components[compIdx];
  if (c.type != COMP_RELAY || !isSafeGpio(c.pin1)) return;

  compOutputStates[compIdx] = state;
  bool activeLow = (c.flags & 1);
  bool level = activeLow ? (!state) : state;
  digitalWrite(c.pin1, level ? HIGH : LOW);
  compValues[compIdx] = state ? 1 : 0;
  lastToggleTime[compIdx] = millis();

  if (pushNotify) {
    String cid = (strlen(c.id) > 0) ? String(c.id) : String(compIdx);
    sendPacketToMaster("EVT", "COMP:" + cid + ":STATE:" + String(state ? 1 : 0));
  }
}

void toggleComponentOutput(uint8_t compIdx, bool pushNotify) {
  setComponentOutput(compIdx, !compOutputStates[compIdx], pushNotify);
}

// Standalone Local Schedule Evaluation (Runs in silicon even if Master is disconnected!)
void evaluateLocalSchedules() {
  uint32_t epoch = getLocalEpoch();
  if (epoch == 0) return;

  uint32_t secondsInDay = epoch % 86400;
  uint8_t curHour = secondsInDay / 3600;
  uint8_t curMin = (secondsInDay % 3600) / 60;
  float curTimeFloat = curHour + (curMin / 60.0);

  for (int s = 0; s < MAX_SCHEDULES; s++) {
    if (!config.schedules[s].enabled) continue;

    float onTimeFloat = config.schedules[s].onHour + (config.schedules[s].onMinute / 60.0);
    float offTimeFloat = config.schedules[s].offHour + (config.schedules[s].offMinute / 60.0);
    bool shouldBeActive = false;

    // Handle midnight-crossing windows (e.g. 18:00 to 06:00) vs same-day (08:00 to 17:00)
    if (onTimeFloat > offTimeFloat) {
      if (curTimeFloat >= onTimeFloat || curTimeFloat < offTimeFloat) shouldBeActive = true;
    } else {
      if (curTimeFloat >= onTimeFloat && curTimeFloat < offTimeFloat) shouldBeActive = true;
    }

    uint16_t mask = config.schedules[s].targetCompsMask;
    if (mask == 0 && config.schedules[s].targetComp < MAX_COMPONENTS) {
      mask = (1 << config.schedules[s].targetComp);
    }

    for (uint8_t comp = 0; comp < MAX_COMPONENTS; comp++) {
      if ((mask & (1 << comp)) != 0 && config.components[comp].type == COMP_RELAY) {
        if (shouldBeActive && !compOutputStates[comp]) {
          setComponentOutput(comp, true, true);
        } else if (!shouldBeActive && compOutputStates[comp]) {
          setComponentOutput(comp, false, true);
        }
      }
    }
  }
}

void checkPhysicalInputs() {
  for (int i = 0; i < MAX_COMPONENTS; i++) {
    ComponentConfig& c = config.components[i];
    if (c.type != COMP_BUTTON && c.type != COMP_TOUCH && c.type != COMP_TOGGLE_SWITCH) continue;
    if (!isSafeGpio(c.pin1)) continue;

    int current = digitalRead(c.pin1);
    int last = lastInputStates[i];

    bool triggered = false;
    if (c.type == COMP_TOUCH && current == HIGH && last == LOW) triggered = true;
    if (c.type == COMP_BUTTON && current == LOW && last == HIGH) triggered = true;
    if (c.type == COMP_TOGGLE_SWITCH && current != last) triggered = true; // Toggle / Rocker switch: triggers on ANY flip
    if ((c.flags & 2) && current != last) triggered = true; // Two-way wall rocker switch (toggle on any flip)

    if (triggered && (millis() - lastToggleTime[i] > 200)) {
      lastToggleTime[i] = millis();

      // Instant sub-millisecond local link ties!
      for (int l = 0; l < MAX_LINKS; l++) {
        if (config.links[l].triggerComp == i && config.links[l].action != LINK_NONE) {
          uint8_t target = config.links[l].targetComp;
          if (config.links[l].action == LINK_TOGGLE) {
            toggleComponentOutput(target, true);
          } else if (config.links[l].action == LINK_TURN_ON) {
            setComponentOutput(target, true, true);
          } else if (config.links[l].action == LINK_TURN_OFF) {
            setComponentOutput(target, false, true);
          }
        }
      }

      String cid = (strlen(c.id) > 0) ? String(c.id) : String(i);
      sendPacketToMaster("INPUT", "COMP:" + cid + ":STATE:" + String(current));
    }
    lastInputStates[i] = current;
    compValues[i] = current;
  }

  // Periodic multi-sensor readings with push-on-change delta reporting
  // 1. Fast polling sensors (Ultrasonic distance, ADC) every 200ms
  if (millis() - lastFastSensorPoll >= 200) {
    lastFastSensorPoll = millis();

    for (int i = 0; i < MAX_COMPONENTS; i++) {
      ComponentConfig& c = config.components[i];
      if (c.type == COMP_ULTRASONIC && isSafeGpio(c.pin1) && isSafeGpio(c.pin2)) {
        digitalWrite(c.pin1, LOW); delayMicroseconds(2);
        digitalWrite(c.pin1, HIGH); delayMicroseconds(10);
        digitalWrite(c.pin1, LOW);
        long dur = pulseIn(c.pin2, HIGH, 25000);
        float dist = (dur > 0) ? (dur * 0.034f / 2.0f) : -1.0f;
        compValues[i] = dist;
        float depth = (c.param1 > 0) ? (float)c.param1 : 200.0f;
        compSecondary[i] = (dist >= 0) ? max(0, min(100, (int)(((depth - dist) / depth) * 100))) : 0;

        // Push-on-Change: Send DATA to Master if distance delta >= 2cm or initial report
        if (dist >= 0 && (fabs(dist - lastReportedValues[i]) >= 2.0f || lastReportedValues[i] < -9000.0f)) {
          lastReportedValues[i] = dist;
          lastReportedSecondary[i] = compSecondary[i];
          String cid = (strlen(c.id) > 0) ? String(c.id) : String(i);
          sendPacketToMaster("DATA", cid + "=" + String((int)dist) + "," + String((int)compSecondary[i]));
        }
      } else if (c.type == COMP_ANALOG_ADC && isSafeGpio(c.pin1)) {
        compValues[i] = analogRead(c.pin1);
        // Push-on-Change: Send DATA to Master if ADC delta >= 25 or initial report
        if (fabs(compValues[i] - lastReportedValues[i]) >= 25.0f || lastReportedValues[i] < -9000.0f) {
          lastReportedValues[i] = compValues[i];
          String cid = (strlen(c.id) > 0) ? String(c.id) : String(i);
          sendPacketToMaster("DATA", cid + "=" + String((int)compValues[i]));
        }
      }
    }
  }

  // 2. Slow polling sensors (DHT11/DHT22) every 1500ms
  if (millis() - lastSlowSensorPoll >= 1500) {
    lastSlowSensorPoll = millis();

    for (int i = 0; i < MAX_COMPONENTS; i++) {
      ComponentConfig& c = config.components[i];
      if (c.type == COMP_DHT && dhtSensors[i]) {
        float h = dhtSensors[i]->readHumidity();
        float t = dhtSensors[i]->readTemperature();
        if (!isnan(t) && !isnan(h)) {
          compValues[i] = t;
          compSecondary[i] = h;
          // Push-on-Change: Send DATA if temperature delta >= 0.5°C or humidity delta >= 2% or initial report
          if (fabs(t - lastReportedValues[i]) >= 0.5f || fabs(h - lastReportedSecondary[i]) >= 2.0f || lastReportedValues[i] < -9000.0f) {
            lastReportedValues[i] = t;
            lastReportedSecondary[i] = h;
            String cid = (strlen(c.id) > 0) ? String(c.id) : String(i);
            sendPacketToMaster("DATA", cid + "=" + String(t, 1) + "," + String(h, 0));
          }
        }
      } else if (c.type == COMP_RELAY) {
        compValues[i] = compOutputStates[i] ? 1 : 0;
      }
    }
  }
}

void sendAnnouncement() {
  String mac = getDeviceMacAddress();
  String payload = "MAC:" + mac + 
                   ":CHIP:" + String(CHIP_NAME_STR) + 
                   ":GPIOS:" + String(SAFE_GPIOS_CSV) + 
                   ":COMPS:" + String(MAX_COMPONENTS) + 
                   ":MODE:" + String(config.transportMode == MODE_WIRELESS ? "WIFI" : "WIRED") +
                   ":AP:" + String(config.apEnabled ? 1 : 0) +
                   ":FW:0.1.1-beta";
  Serial.println("[BUS TX] Sending ANN to Master: " + payload);
  sendPacketToMaster("ANN", payload);
}

void processIncomingPacket(const ParsedPacket& pkt) {
  // If in repeater bridge mode and packet is addressed to our connected child, forward it!
  if (config.transportMode == MODE_WIRED && config.apEnabled && bridgeClient && bridgeClient.connected()) {
    if (pkt.to != config.nodeId && pkt.to != "M") {
      bridgeClient.println(buildPacket(pkt.to, pkt.from, pkt.verb, pkt.payload));
    }
  }

  if (pkt.to != config.nodeId && pkt.to != "ALL" && pkt.to != "NEW") return;

  // Verb 1: REQ (e.g. REQ:POLL)
  if (pkt.verb == "REQ" && pkt.payload == "POLL") {
    String rep = "";
    int count = 0;
    for (int i = 0; i < MAX_COMPONENTS; i++) {
      ComponentConfig& c = config.components[i];
      if (c.type == COMP_UNUSED) continue;
      if (count > 0) rep += ":";
      String cid = (strlen(c.id) > 0) ? String(c.id) : ("c" + String(i));
      if (c.type == COMP_RELAY) {
        rep += cid + "=" + String(compOutputStates[i] ? 1 : 0);
      } else if (c.type == COMP_ULTRASONIC) {
        rep += cid + "=" + String((int)compValues[i]) + "," + String((int)compSecondary[i]);
      } else if (c.type == COMP_DHT) {
        rep += cid + "=" + String(compValues[i], 1) + "," + String(compSecondary[i], 0);
      } else if (c.type == COMP_BUTTON || c.type == COMP_TOUCH || c.type == COMP_TOGGLE_SWITCH) {
        rep += cid + "=" + String((int)compValues[i]);
      } else if (c.type == COMP_ANALOG_ADC) {
        rep += cid + "=" + String((int)compValues[i]);
      }
      count++;
    }
    if (count > 0) rep += ":";
    rep += "ap=" + String(config.apEnabled ? 1 : 0);
    rep += ":heap=" + String(ESP.getFreeHeap());
    sendPacketToMaster("REP", rep);
  }
  // Verb 2: SET (e.g. SET:<comp_id>:<0|1> or SET:SLOT:<id>:STATE:<0|1>)
  else if (pkt.verb == "SET") {
    int colon = pkt.payload.indexOf(':');
    if (colon != -1) {
      String firstToken = pkt.payload.substring(0, colon);
      if (firstToken == "SLOT") {
        int stIdx = pkt.payload.indexOf(":STATE:");
        if (stIdx != -1) {
          int slot = pkt.payload.substring(5, stIdx).toInt();
          int st = pkt.payload.substring(stIdx + 7).toInt();
          if (st == 2) {
            toggleComponentOutput(slot, true);
          } else {
            setComponentOutput(slot, (st == 1), true);
          }
        }
      } else {
        String compId = firstToken;
        int state = pkt.payload.substring(colon + 1).toInt();
        for (int i = 0; i < MAX_COMPONENTS; i++) {
          if (config.components[i].type == COMP_RELAY) {
            if (String(config.components[i].id) == compId || String(i) == compId) {
              if (state == 2) {
                toggleComponentOutput(i, true);
              } else {
                setComponentOutput(i, (state == 1), true);
              }
              break;
            }
          }
        }
      }
    }
  }
  // Verb 3: BIND (Assigns permanent Node ID to this node matching MAC)
  else if (pkt.verb == "BIND") {
    String myMac = getDeviceMacAddress();
    if (pkt.payload.indexOf("MAC:" + myMac) != -1) {
      int idIdx = pkt.payload.indexOf(":SET_ID:");
      if (idIdx != -1) {
        int endId = pkt.payload.indexOf(':', idIdx + 8);
        String newId = (endId == -1) ? pkt.payload.substring(idIdx + 8) : pkt.payload.substring(idIdx + 8, endId);
        strncpy(config.nodeId, newId.c_str(), sizeof(config.nodeId) - 1);
        config.nodeId[sizeof(config.nodeId) - 1] = '\0';
        if (config.transportMode != MODE_WIRELESS) {
          config.transportMode = MODE_WIRED;
        }

        // Provision Downstream Wi-Fi SoftAP Bridge if provided in BIND packet
        int apIdx = pkt.payload.indexOf(":AP:");
        if (apIdx != -1) {
          int apEnd = pkt.payload.indexOf(':', apIdx + 4);
          int en = (apEnd == -1) ? pkt.payload.substring(apIdx + 4).toInt() : pkt.payload.substring(apIdx + 4, apEnd).toInt();
          config.apEnabled = (en == 1) ? 1 : 0;
          int sIdx = pkt.payload.indexOf(":AP_SSID:");
          if (sIdx != -1) {
            int sEnd = pkt.payload.indexOf(':', sIdx + 9);
            String apS = (sEnd == -1) ? pkt.payload.substring(sIdx + 9) : pkt.payload.substring(sIdx + 9, sEnd);
            strncpy(config.apSsid, apS.c_str(), sizeof(config.apSsid) - 1);
            config.apSsid[sizeof(config.apSsid) - 1] = '\0';
          }
          int pIdx = pkt.payload.indexOf(":AP_PASS:");
          if (pIdx != -1) {
            int pEnd = pkt.payload.indexOf(':', pIdx + 9);
            String apP = (pEnd == -1) ? pkt.payload.substring(pIdx + 9) : pkt.payload.substring(pIdx + 9, pEnd);
            strncpy(config.apPass, apP.c_str(), sizeof(config.apPass) - 1);
            config.apPass[sizeof(config.apPass) - 1] = '\0';
          }
          int hIdx = pkt.payload.indexOf(":AP_HIDDEN:");
          if (hIdx != -1) {
            int hEnd = pkt.payload.indexOf(':', hIdx + 11);
            config.apHidden = (hEnd == -1) ? pkt.payload.substring(hIdx + 11).toInt() : pkt.payload.substring(hIdx + 11, hEnd).toInt();
          }
        }

        saveConfig();
        stopCaptivePortal();

        // If Downstream SoftAP is provisioned, activate bridge server immediately!
        if (config.apEnabled) {
          Serial.printf("[AP] Activating Downstream SoftAP '%s' (Hidden: %d)...\n", config.apSsid, config.apHidden);
          if (config.transportMode == MODE_WIRELESS) WiFi.mode(WIFI_AP_STA);
          else WiFi.mode(WIFI_AP);
          const char* passPtr = (strlen(config.apPass) >= 8) ? config.apPass : NULL;
          WiFi.softAP(config.apSsid, passPtr, 1, config.apHidden ? 1 : 0);
          if (!bridgeServer) {
            bridgeServer = new WiFiServer(DEFAULT_MESH_PORT);
            bridgeServer->begin();
          }
        }

        sendPacketToMaster("ACK", "BOUND_OK");
        Serial.printf("[BIND] Slave successfully bound as Node ID: %s | Mode: %s | AP: %s\n",
                      config.nodeId, config.transportMode == MODE_WIRELESS ? "WIRELESS" : "WIRED",
                      config.apEnabled ? config.apSsid : "DISABLED");
      }
    }
  }
  // Verb 4: CFG (Declarative component / link / schedule configuration from Master)
  else if (pkt.verb == "CFG") {
    if (pkt.payload.startsWith("COMP:")) {
      // CFG:COMP:<idx>:<type>:<pin1>:<pin2>:<flags>:<param1>:<id>
      int parts[6];
      int cur = 5;
      for (int p = 0; p < 6; p++) {
        int nextColon = pkt.payload.indexOf(':', cur);
        if (nextColon == -1) {
          parts[p] = pkt.payload.substring(cur).toInt();
          cur = pkt.payload.length();
        } else {
          parts[p] = pkt.payload.substring(cur, nextColon).toInt();
          cur = nextColon + 1;
        }
      }
      String compId = (cur < pkt.payload.length()) ? pkt.payload.substring(cur) : "";
      int cIdx = parts[0];
      if (cIdx >= 0 && cIdx < MAX_COMPONENTS) {
        config.components[cIdx].type = parts[1];
        config.components[cIdx].pin1 = parts[2];
        config.components[cIdx].pin2 = parts[3];
        config.components[cIdx].flags = parts[4];
        config.components[cIdx].param1 = parts[5];
        memset(config.components[cIdx].id, 0, sizeof(config.components[cIdx].id));
        strncpy(config.components[cIdx].id, compId.c_str(), sizeof(config.components[cIdx].id) - 1);
        config.numConfiguredComponents = max((int)config.numConfiguredComponents, cIdx + 1);
        saveConfig();
        applyHardwareConfiguration();
        sendPacketToMaster("ACK", "COMP_CONFIGURED:" + String(cIdx));
      }
    } else if (pkt.payload.startsWith("AP:")) {
      // CFG:AP:<1|0>:<ssid>:<pass>:<hidden>
      int c1 = pkt.payload.indexOf(':', 3);
      if (c1 != -1) {
        int en = pkt.payload.substring(3, c1).toInt();
        int c2 = pkt.payload.indexOf(':', c1 + 1);
        String apSsid = (c2 != -1) ? pkt.payload.substring(c1 + 1, c2) : pkt.payload.substring(c1 + 1);
        int c3 = (c2 != -1) ? pkt.payload.indexOf(':', c2 + 1) : -1;
        String apPass = (c3 != -1) ? pkt.payload.substring(c2 + 1, c3) : ((c2 != -1) ? pkt.payload.substring(c2 + 1) : "");
        if (c3 != -1) {
          config.apHidden = pkt.payload.substring(c3 + 1).toInt() ? 1 : 0;
        }

        config.apEnabled = (en == 1) ? 1 : 0;
        if (apSsid.length() > 0) {
          strncpy(config.apSsid, apSsid.c_str(), sizeof(config.apSsid) - 1);
          config.apSsid[sizeof(config.apSsid) - 1] = '\0';
        }
        strncpy(config.apPass, apPass.c_str(), sizeof(config.apPass) - 1);
        config.apPass[sizeof(config.apPass) - 1] = '\0';
        saveConfig();

        if (config.apEnabled) {
          Serial.printf("[AP] Starting downstream SoftAP '%s' (Hidden: %d)...\n", config.apSsid, config.apHidden);
          if (config.transportMode == MODE_WIRELESS) WiFi.mode(WIFI_AP_STA);
          else WiFi.mode(WIFI_AP);
          const char* passPtr = (strlen(config.apPass) >= 8) ? config.apPass : NULL;
          WiFi.softAP(config.apSsid, passPtr, 1, config.apHidden ? 1 : 0);
          if (!bridgeServer) {
            bridgeServer = new WiFiServer(DEFAULT_MESH_PORT);
            bridgeServer->begin();
          }
          sendPacketToMaster("ACK", "AP_CONFIGURED:ENABLED:" + String(config.apSsid));
        } else {
          Serial.println("[AP] Disabling downstream SoftAP...");
          WiFi.softAPdisconnect(true);
          if (config.transportMode == MODE_WIRED) {
            #if defined(ESP8266)
              WiFi.mode(WIFI_OFF);
              WiFi.forceSleepBegin();
            #else
              WiFi.mode(WIFI_OFF);
            #endif
          } else {
            WiFi.mode(WIFI_STA);
          }
          if (bridgeServer) {
            delete bridgeServer;
            bridgeServer = nullptr;
          }
          sendPacketToMaster("ACK", "AP_CONFIGURED:DISABLED");
        }
      }
    } else if (pkt.payload.startsWith("LINK:CLEAR")) {
      for (int l = 0; l < MAX_LINKS; l++) {
        config.links[l].triggerComp = 255;
        config.links[l].targetComp = 255;
        config.links[l].action = LINK_NONE;
      }
      config.numConfiguredLinks = 0;
      saveConfig();
      sendPacketToMaster("ACK", "LINKS_CLEARED");
    } else if (pkt.payload.startsWith("LINK:")) {
      int idx  = pkt.payload.substring(5, pkt.payload.indexOf(":TRIG:")).toInt();
      int trig = pkt.payload.substring(pkt.payload.indexOf(":TRIG:") + 6, pkt.payload.indexOf(":TGT:")).toInt();
      int tgt  = pkt.payload.substring(pkt.payload.indexOf(":TGT:") + 5, pkt.payload.indexOf(":ACT:")).toInt();
      int act  = pkt.payload.substring(pkt.payload.indexOf(":ACT:") + 5).toInt();

      if (idx >= 0 && idx < MAX_LINKS) {
        config.links[idx].triggerComp = trig;
        config.links[idx].targetComp = tgt;
        config.links[idx].action = act;
        config.numConfiguredLinks = max((int)config.numConfiguredLinks, idx + 1);
        saveConfig();
        sendPacketToMaster("ACK", "LINK_CONFIGURED:" + String(idx));
      }
    } else if (pkt.payload.startsWith("SCHED:")) {
      int p[8];
      int lastPos = 6;
      for (int i = 0; i < 8; i++) {
        int nextColon = pkt.payload.indexOf(':', lastPos);
        if (nextColon == -1 && i == 7) nextColon = pkt.payload.length();
        p[i] = pkt.payload.substring(lastPos, nextColon).toInt();
        lastPos = nextColon + 1;
      }
      int sIdx = p[0];
      if (sIdx >= 0 && sIdx < MAX_SCHEDULES) {
        config.schedules[sIdx].enabled = p[1];
        config.schedules[sIdx].targetComp = (p[2] < MAX_COMPONENTS) ? p[2] : 0;
        config.schedules[sIdx].targetCompsMask = p[2];
        config.schedules[sIdx].action = p[3];
        config.schedules[sIdx].onHour = p[4];
        config.schedules[sIdx].onMinute = p[5];
        config.schedules[sIdx].offHour = p[6];
        config.schedules[sIdx].offMinute = p[7];
        config.schedules[sIdx].daysOfWeekMask = 0x7F;
        config.numConfiguredSchedules = max((int)config.numConfiguredSchedules, sIdx + 1);
        saveConfig();
        sendPacketToMaster("ACK", "SCHED_CONFIGURED:" + String(sIdx));
      }
    }
  }
  // Verb 5: TIME (Sync Unix epoch from Master: TIME:<epoch>)
  else if (pkt.verb == "TIME") {
    currentEpoch = pkt.payload.toInt();
    lastEpochSyncMillis = millis();
    sendPacketToMaster("ACK", "TIME_SYNCED:" + String(currentEpoch));
  }
  // Verb 6: CMD:RESET_PORTAL (Forces slave into captive portal mode)
  else if (pkt.verb == "CMD" && pkt.payload == "RESET_PORTAL") {
    startCaptivePortal();
  }
}

// =========================================================================
// OPTION 1: CAPTIVE PORTAL ONBOARDING WIZARD & DUAL-LISTEN HANDLER
// =========================================================================
void startCaptivePortal() {
  if (inCaptivePortal) return; // Already running
  inCaptivePortal = true;
  Serial.println("\n[PORTAL] Launching Captive Portal Setup Wizard...");

  WiFi.disconnect();
  WiFi.mode(WIFI_AP);

  String mac = getDeviceMacAddress();
  String setupSsid = "SLAVE-SETUP-" + (mac.length() >= 4 ? mac.substring(mac.length() - 4) : "NODE");
  IPAddress apIP(192, 168, 4, 1);
  IPAddress netMsk(255, 255, 255, 0);

  WiFi.softAPConfig(apIP, apIP, netMsk);
  WiFi.softAP(setupSsid.c_str());

  Serial.printf("[PORTAL] AP Active! Connect to SSID: %s (Open) | IP: 192.168.4.1\n", setupSsid.c_str());

  if (dnsServer) delete dnsServer;
  dnsServer = new DNSServer();
  dnsServer->setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer->start(DNS_PORT, "*", apIP);

  if (portalServer) delete portalServer;
  portalServer = new SlaveWebServer(80);

  portalServer->on("/", HTTP_GET, []() {
    String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Mini-HA Slave Onboarding</title><style>";
    html += "body{font-family:-apple-system,sans-serif;background:#0f172a;color:#f8fafc;padding:20px;margin:0}";
    html += ".card{max-width:480px;margin:0 auto;background:#1e293b;border-radius:12px;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.5)}";
    html += "h2{color:#38bdf8;margin-top:0;font-size:22px}";
    html += ".info{background:#334155;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:18px;color:#94a3b8}";
    html += "label{display:block;margin:12px 0 4px;font-size:13px;font-weight:600;color:#cbd5e1}";
    html += "input,select{width:100%;box-sizing:border-box;padding:10px;background:#0f172a;border:1px solid #475569;border-radius:6px;color:#fff;font-size:14px}";
    html += "input:focus,select:focus{border-color:#38bdf8;outline:none}";
    html += ".btn{margin-top:22px;width:100%;padding:12px;background:#0284c7;color:#fff;border:none;border-radius:6px;font-size:15px;font-weight:700;cursor:pointer}";
    html += ".btn:hover{background:#0369a1}";
    html += ".row{display:flex;gap:10px}.row>div{flex:1}";
    html += "</style></head><body><div class='card'>";
    html += "<h2>Mini-HA Slave Setup</h2>";
    html += "<div class='info'><strong>Chip:</strong> " + String(CHIP_NAME_STR) + "<br><strong>MAC:</strong> " + getDeviceMacAddress() + "<br><strong>Current ID:</strong> " + String(config.nodeId) + "</div>";
    html += "<form method='POST' action='/save'>";
    
    html += "<label>Transport Mode</label>";
    html += "<select name='mode' id='mode' onchange='toggleMode()'>";
    bool selectWireless = (config.transportMode == MODE_WIRELESS || strcmp(config.nodeId, "UNBOUND") == 0);
    html += "<option value='1'" + String(selectWireless ? " selected" : "") + ">Wireless (Wi-Fi Star-Mesh Client)</option>";
    html += "<option value='0'" + String(!selectWireless ? " selected" : "") + ">Wired (RS-422 / Serial Star Hub)</option>";
    html += "</select>";

    html += "<div id='wifi_fields'>";
    html += "<label>Scan & Select Parent Wi-Fi (Master AP or Wired Slave AP)</label>";
    html += "<select name='scanned_ssid' onchange='document.getElementById(\"ssid\").value=this.value'>";
    html += "<option value=''>-- Tap to select detected network --</option>";
    
    int n = WiFi.scanNetworks();
    for (int i = 0; i < n; ++i) {
      String s = WiFi.SSID(i);
      if (s.length() > 0) {
        html += "<option value='" + s + "'>" + s + " (" + String(WiFi.RSSI(i)) + " dBm)</option>";
      }
    }
    html += "</select>";

    html += "<label>Parent Wi-Fi SSID</label>";
    html += "<input type='text' id='ssid' name='ssid' value='" + String(config.wifiSsid) + "' placeholder='e.g. Mini-HA-Master or SlaveNet-01'>";

    html += "<label>Parent Wi-Fi Password</label>";
    html += "<input type='password' name='pass' value='" + String(config.wifiPass) + "' placeholder='Leave blank if open network'>";

    html += "<div class='row'>";
    html += "<div><label>Master/Gateway IP</label><input type='text' name='host' value='" + (strlen(config.masterHost) > 0 ? String(config.masterHost) : "192.168.4.1") + "'></div>";
    html += "<div><label>TCP Port</label><input type='number' name='port' value='" + String(config.masterPort > 0 ? config.masterPort : DEFAULT_MESH_PORT) + "'></div>";
    html += "</div>";
    html += "</div>";

    html += "<hr style='border:0;border-top:1px solid #334155;margin:20px 0'>";
    html += "<label><input type='checkbox' name='ap_en' value='1'" + String(config.apEnabled ? " checked" : "") + " style='width:auto;margin-right:8px'>Host Downstream SoftAP (Repeater mode for nearby child slaves)</label>";
    html += "<label style='margin:4px 0 10px;font-size:12px;color:#94a3b8'><input type='checkbox' name='ap_hidden' value='1'" + String(config.apHidden ? " checked" : "") + " style='width:auto;margin-right:8px'>Hide SoftAP Network (Hidden SSID)</label>";
    html += "<div class='row'>";
    html += "<div><label>Downstream SSID</label><input type='text' name='ap_ssid' value='" + (strlen(config.apSsid) > 0 ? String(config.apSsid) : "SlaveNet-01") + "'></div>";
    html += "<div><label>Downstream Password</label><input type='text' name='ap_pass' value='" + String(config.apPass) + "' placeholder='Min 8 chars'></div>";
    html += "</div>";

    html += "<button type='submit' class='btn'>Save Configuration & Connect</button>";
    html += "</form></div>";
    html += "<script>function toggleMode(){var m=document.getElementById('mode').value;document.getElementById('wifi_fields').style.display=(m==='1')?'block':'none';}toggleMode();</script>";
    html += "</body></html>";

    portalServer->send(200, "text/html", html);
  });

  portalServer->on("/save", HTTP_POST, []() {
    config.transportMode = portalServer->arg("mode").toInt();
    strncpy(config.wifiSsid, portalServer->arg("ssid").c_str(), sizeof(config.wifiSsid) - 1);
    config.wifiSsid[sizeof(config.wifiSsid) - 1] = '\0';

    if (portalServer->arg("pass").length() > 0) {
      strncpy(config.wifiPass, portalServer->arg("pass").c_str(), sizeof(config.wifiPass) - 1);
      config.wifiPass[sizeof(config.wifiPass) - 1] = '\0';
    }

    if (portalServer->arg("host").length() > 0) {
      strncpy(config.masterHost, portalServer->arg("host").c_str(), sizeof(config.masterHost) - 1);
      config.masterHost[sizeof(config.masterHost) - 1] = '\0';
    }

    int p = portalServer->arg("port").toInt();
    config.masterPort = (p > 0) ? p : DEFAULT_MESH_PORT;

    config.apEnabled = portalServer->hasArg("ap_en") ? 1 : 0;
    config.apHidden = portalServer->hasArg("ap_hidden") ? 1 : 0;
    if (portalServer->arg("ap_ssid").length() > 0) {
      strncpy(config.apSsid, portalServer->arg("ap_ssid").c_str(), sizeof(config.apSsid) - 1);
      config.apSsid[sizeof(config.apSsid) - 1] = '\0';
    }
    if (portalServer->arg("ap_pass").length() > 0) {
      strncpy(config.apPass, portalServer->arg("ap_pass").c_str(), sizeof(config.apPass) - 1);
      config.apPass[sizeof(config.apPass) - 1] = '\0';
    }

    saveConfig();

    String html = "<!DOCTYPE html><html><body style='background:#0f172a;color:#38bdf8;font-family:sans-serif;text-align:center;padding-top:50px;'>";
    html += "<h2>Configuration Saved!</h2><p style='color:#cbd5e1'>Rebooting node to join the mesh network...</p></body></html>";
    portalServer->send(200, "text/html", html);

    delay(1000);
    ESP.restart();
  });

  // Common Captive Portal detection probes
  portalServer->on("/generate_204", HTTP_GET, []() { portalServer->sendHeader("Location", "/", true); portalServer->send(302, "text/plain", ""); });
  portalServer->on("/fwlink", HTTP_GET, []() { portalServer->sendHeader("Location", "/", true); portalServer->send(302, "text/plain", ""); });
  portalServer->on("/hotspot-detect.html", HTTP_GET, []() { portalServer->sendHeader("Location", "/", true); portalServer->send(302, "text/plain", ""); });
  portalServer->onNotFound([]() {
    portalServer->sendHeader("Location", "/", true);
    portalServer->send(302, "text/plain", "");
  });

  portalServer->begin();
}

void stopCaptivePortal() {
  if (!inCaptivePortal) return;
  inCaptivePortal = false;
  Serial.println("[PORTAL] Stopping Captive Portal setup wizard...");
  if (dnsServer) {
    dnsServer->stop();
    delete dnsServer;
    dnsServer = nullptr;
  }
  if (portalServer) {
    delete portalServer;
    portalServer = nullptr;
  }
  if (!config.apEnabled) {
    WiFi.softAPdisconnect(true);
    #if defined(ESP8266)
      WiFi.mode(WIFI_OFF);
      WiFi.forceSleepBegin();
    #else
      WiFi.mode(WIFI_OFF);
    #endif
  }
  Serial.println("[PORTAL] Captive Portal stopped successfully.");
}

void setup() {
  Serial.begin(115200);
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
  #if ARDUINO_USB_CDC_ON_BOOT
    BusSerial.begin(115200, SERIAL_8N1, 20, 21); // Explicitly pin GPIO 20 (RX) and GPIO 21 (TX)
  #endif
#endif
  delay(200);

  loadConfigFromStorage();
  applyHardwareConfiguration();

  Serial.println("\n==========================================");
  Serial.printf(" [MINI-HA SLAVE] Node: %s | Chip: %s (v0.1.1-beta)\n", config.nodeId, CHIP_NAME_STR);
  Serial.printf(" Transport: %s | Bus: 115200 baud\n", config.transportMode == MODE_WIRELESS ? "WIRELESS" : "WIRED");
  Serial.println("==========================================\n");

  // Check if onboard Boot/Flash button is held down (forces Captive Portal)
  bool forcePortal = false;
  if (isBootButtonPressed()) {
    Serial.println("[BOOT] Button pressed! Checking for 2-second hold...");
    unsigned long btnStart = millis();
    while (isBootButtonPressed() && (millis() - btnStart < 2000)) {
      delay(50);
    }
    if (millis() - btnStart >= 2000) {
      Serial.println("[BOOT] Force setup portal confirmed!");
      forcePortal = true;
    }
  }

  bool isUnbound = (strcmp(config.nodeId, "UNBOUND") == 0);

  // OPTION 1: UNBOUND DUAL-LISTEN
  // If the node is unbound (factory state) or portal was forced:
  // Concurrently run Captive Portal SoftAP AND keep RS-422 Serial bus active!
  if (forcePortal || isUnbound) {
    startCaptivePortal();
    Serial.printf("[SETUP] %s: Listening on RS-422 Serial AND Wi-Fi SoftAP (%s)\n",
                  isUnbound ? "UNBOUND FACTORY STATE (Dual-Listen)" : "FORCED SETUP",
                  ("SLAVE-SETUP-" + (getDeviceMacAddress().length() >= 4 ? getDeviceMacAddress().substring(getDeviceMacAddress().length() - 4) : "NODE")).c_str());
  } else if (config.transportMode == MODE_WIRELESS) {
    if (strlen(config.wifiSsid) == 0) {
      Serial.println("[WIFI] Wireless mode configured but no SSID! Launching Captive Portal...");
      startCaptivePortal();
    } else {
      Serial.printf("[WIFI] Connecting to Parent AP '%s'...\n", config.wifiSsid);
      WiFi.mode(WIFI_STA);
      WiFi.begin(config.wifiSsid, config.wifiPass);

      unsigned long startAttempt = millis();
      while (WiFi.status() != WL_CONNECTED && millis() - startAttempt < 15000) {
        delay(300);
        Serial.print(".");
      }

      if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\n[WIFI] Connected! Assigned IP: %s\n", WiFi.localIP().toString().c_str());
      } else {
        Serial.println("\n[WIFI] Could not connect to parent AP! Falling back to Captive Portal...");
        startCaptivePortal();
      }
    }
  } else {
    // Bound Wired Mode
    Serial.println("[WIRED] Operating on Isolated RS-422 Hardware Serial Star Bus.");
    if (config.apEnabled) {
      Serial.printf("[AP] Starting downstream SoftAP '%s' (Hidden: %d)...\n", config.apSsid, config.apHidden);
      WiFi.mode(WIFI_AP);
      const char* passPtr = (strlen(config.apPass) >= 8) ? config.apPass : NULL;
      WiFi.softAP(config.apSsid, passPtr, 1, config.apHidden ? 1 : 0);
      bridgeServer = new WiFiServer(DEFAULT_MESH_PORT);
      bridgeServer->begin();
    } else {
      #if defined(ESP8266)
        WiFi.mode(WIFI_OFF);
        WiFi.forceSleepBegin();
      #else
        WiFi.mode(WIFI_OFF);
      #endif
    }
  }

  sendAnnouncement();
  lastAnnounceTime = millis();
}

void loop() {
  // If in Captive Portal mode, handle DNS and HTTP requests concurrently
  if (inCaptivePortal) {
    if (dnsServer) dnsServer->processNextRequest();
    if (portalServer) portalServer->handleClient();
  }

  // Periodic heartbeat on USB Serial so monitor is never blank
  static unsigned long lastHeartbeat = 0;
  if (millis() - lastHeartbeat > 3000) {
    lastHeartbeat = millis();
    Serial.printf("[SLAVE ALIVE] Node: %s | Mode: %s%s | Bus: 115200 baud\n",
                  config.nodeId, 
                  config.transportMode == MODE_WIRELESS ? "WIRELESS" : "WIRED",
                  inCaptivePortal ? " (PORTAL ACTIVE)" : "");
  }

  // 1. Monitor physical inputs with sub-ms local link execution
  checkPhysicalInputs();

  // 2. Standalone Local Schedule Evaluation (Even when offline!)
  static unsigned long lastSchedCheck = 0;
  if (millis() - lastSchedCheck > 1000) {
    lastSchedCheck = millis();
    evaluateLocalSchedules();
  }

  // 3. Read incoming serial stream (RS-422 bus)
  while (BusSerial.available()) {
    char c = (char)BusSerial.read();
    if (c == '\n') {
      rxBuffer.trim();
      if (rxBuffer.length() > 0) {
        ParsedPacket pkt = parseProtocolLine(rxBuffer);
        if (pkt.isValid) {
          processIncomingPacket(pkt);
        }
      }
      rxBuffer = "";
    } else if (c != '\r') {
      rxBuffer += c;
      if (rxBuffer.length() > PROTOCOL_MAX_LINE) rxBuffer = "";
    }
  }

  // Also read from USB Serial if separate (allows debugging via serial monitor)
  #if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
    #if ARDUINO_USB_CDC_ON_BOOT
      while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n') {
          rxBuffer.trim();
          if (rxBuffer.length() > 0) {
            ParsedPacket pkt = parseProtocolLine(rxBuffer);
            if (pkt.isValid) {
              processIncomingPacket(pkt);
            }
          }
          rxBuffer = "";
        } else if (c != '\r') {
          rxBuffer += c;
          if (rxBuffer.length() > PROTOCOL_MAX_LINE) rxBuffer = "";
        }
      }
    #endif
  #endif

  // 4. Wireless Mode: Maintain TCP socket to Master or Parent AP
  if (config.transportMode == MODE_WIRELESS) {
    if (WiFi.status() == WL_CONNECTED) {
      if (!tcpClient.connected()) {
        if (millis() - lastTcpRetry > 3000) {
          lastTcpRetry = millis();
          Serial.printf("[TCP] Connecting to Master socket at %s:%d...\n", config.masterHost, config.masterPort);
          if (tcpClient.connect(config.masterHost, config.masterPort)) {
            Serial.println("[TCP] Socket connected successfully!");
            sendAnnouncement();
          }
        }
      } else {
        while (tcpClient.available()) {
          char c = (char)tcpClient.read();
          if (c == '\n') {
            netRxBuffer.trim();
            if (netRxBuffer.length() > 0) {
              ParsedPacket pkt = parseProtocolLine(netRxBuffer);
              if (pkt.isValid) {
                processIncomingPacket(pkt);
              }
            }
            netRxBuffer = "";
          } else if (c != '\r') {
            netRxBuffer += c;
            if (netRxBuffer.length() > PROTOCOL_MAX_LINE) netRxBuffer = "";
          }
        }
      }
    }
  }

  // 5. Wired Repeater Mode: Bridge child wireless slaves to RS-422 Serial
  if (config.transportMode == MODE_WIRED && config.apEnabled && bridgeServer) {
    #if defined(ESP8266)
      if (bridgeServer->hasClient()) {
        if (!bridgeClient || !bridgeClient.connected()) {
          bridgeClient = bridgeServer->available();
          Serial.println("[BRIDGE] Wireless child slave connected to local SoftAP!");
        }
      }
    #else
      WiFiClient newCl = bridgeServer->available();
      if (newCl) {
        bridgeClient = newCl;
        Serial.println("[BRIDGE] Wireless child slave connected to local SoftAP!");
      }
    #endif

    if (bridgeClient && bridgeClient.connected()) {
      while (bridgeClient.available()) {
        char c = (char)bridgeClient.read();
        BusSerial.write(c); // Forward child packet directly over RS-422 bus to Master
      }
    }
  }

  // 6. If unprovisioned, repeat announcement every 5 seconds until bound
  if (strcmp(config.nodeId, "UNBOUND") == 0) {
    if (millis() - lastAnnounceTime > 5000) {
      lastAnnounceTime = millis();
      sendAnnouncement();
    }
  }
}
