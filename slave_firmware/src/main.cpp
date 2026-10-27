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
bool outputStates[MAX_GPIO_SLOTS];
int lastInputStates[MAX_GPIO_SLOTS];
unsigned long lastToggleTime[MAX_GPIO_SLOTS];

// Timekeeping variables (Synced from Master, kept alive by millis())
uint32_t currentEpoch = 0;
unsigned long lastEpochSyncMillis = 0;

// Sensor Peripherals
DHT* dhtSensor = nullptr;
int dhtSlotIndex = -1;
int trigSlotIndex = -1;
int echoSlotIndex = -1;
int cachedDistance = -1;
float cachedTemperature = 0.0;
float cachedHumidity = 0.0;
unsigned long lastSensorPoll = 0;
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
void setOutputSlot(uint8_t slot, bool state, bool pushNotify = true);
void toggleOutputSlot(uint8_t slot, bool pushNotify = true);
void startCaptivePortal();

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
    strncpy(config.nodeId, "UNBOUND", sizeof(config.nodeId) - 1);
    config.transportMode = MODE_WIRELESS; // Default to wireless onboarding
    config.wifiSsid[0] = '\0';
    config.wifiPass[0] = '\0';
    strncpy(config.masterHost, "192.168.4.1", sizeof(config.masterHost) - 1);
    config.masterPort = DEFAULT_MESH_PORT;
    config.apEnabled = 0;
    strncpy(config.apSsid, "SlaveNet-01", sizeof(config.apSsid) - 1);
    strncpy(config.apPass, "12345678", sizeof(config.apPass) - 1);
    config.numConfiguredSlots = 0;
    config.numConfiguredLinks = 0;
    config.numConfiguredSchedules = 0;
    saveConfig();
  } else {
    Serial.printf("[STORAGE] Loaded config for Node: %s | Mode: %s (Slots: %d, Links: %d, Scheds: %d)\n", 
      config.nodeId, (config.transportMode == MODE_WIRELESS ? "WIRELESS" : "WIRED"),
      config.numConfiguredSlots, config.numConfiguredLinks, config.numConfiguredSchedules);
  }
}

void saveConfig() {
  EEPROM.put(0, config);
  EEPROM.commit();
}

void applyHardwareConfiguration() {
  dhtSlotIndex = -1;
  trigSlotIndex = -1;
  echoSlotIndex = -1;
  if (dhtSensor) { delete dhtSensor; dhtSensor = nullptr; }

  for (int i = 0; i < MAX_GPIO_SLOTS; i++) {
    outputStates[i] = false;
    lastInputStates[i] = LOW;
    lastToggleTime[i] = 0;

    uint8_t pin = config.slots[i].gpio;
    uint8_t type = config.slots[i].type;

    if (type == SLOT_UNUSED || !isSafeGpio(pin)) continue;

    if (type == SLOT_OUTPUT_RELAY) {
      pinMode(pin, OUTPUT);
      digitalWrite(pin, config.slots[i].activeLow ? HIGH : LOW); // Default OFF
    } else if (type == SLOT_INPUT_TOUCH || type == SLOT_INPUT_BUTTON) {
      pinMode(pin, (type == SLOT_INPUT_BUTTON) ? INPUT_PULLUP : INPUT);
      lastInputStates[i] = digitalRead(pin);
    } else if (type == SLOT_SENSOR_ULTRASONIC_TRIG) {
      pinMode(pin, OUTPUT);
      digitalWrite(pin, LOW);
      trigSlotIndex = i;
    } else if (type == SLOT_SENSOR_ULTRASONIC_ECHO) {
      pinMode(pin, INPUT);
      echoSlotIndex = i;
    } else if (type == SLOT_SENSOR_DHT11 || type == SLOT_SENSOR_DHT22) {
      dhtSlotIndex = i;
      dhtSensor = new DHT(pin, (type == SLOT_SENSOR_DHT11) ? DHT11 : DHT22);
      dhtSensor->begin();
    }
  }
  Serial.println("[HAL] Applied hardware configuration successfully.");
}

// Unified packet transmitter: Sends to Serial and/or active TCP connection
void sendPacketToMaster(const String& verb, const String& payload) {
  String pkt = buildPacket("M", config.nodeId, verb, payload);
  
  // 1. Output to Hardware Serial (always available for wired bus or diagnostics)
  Serial.println(pkt);

  // 2. Output to Wireless TCP Client if in wireless mode
  if (config.transportMode == MODE_WIRELESS && tcpClient.connected()) {
    tcpClient.println(pkt);
  }
}

void setOutputSlot(uint8_t slot, bool state, bool pushNotify) {
  if (slot >= MAX_GPIO_SLOTS) return;
  if (config.slots[slot].type != SLOT_OUTPUT_RELAY) return;

  outputStates[slot] = state;
  uint8_t pin = config.slots[slot].gpio;
  bool level = config.slots[slot].activeLow ? (!state) : state;
  digitalWrite(pin, level ? HIGH : LOW);
  lastToggleTime[slot] = millis();

  if (pushNotify) {
    sendPacketToMaster("EVT", "SLOT:" + String(slot) + ":STATE:" + String(state ? 1 : 0));
  }
}

void toggleOutputSlot(uint8_t slot, bool pushNotify) {
  setOutputSlot(slot, !outputStates[slot], pushNotify);
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

    uint8_t target = config.schedules[s].targetSlot;
    if (target < MAX_GPIO_SLOTS) {
      if (shouldBeActive && !outputStates[target]) {
        setOutputSlot(target, true, true);
      } else if (!shouldBeActive && outputStates[target]) {
        setOutputSlot(target, false, true);
      }
    }
  }
}

void checkPhysicalInputs() {
  for (int i = 0; i < MAX_GPIO_SLOTS; i++) {
    uint8_t type = config.slots[i].type;
    if (type != SLOT_INPUT_TOUCH && type != SLOT_INPUT_BUTTON) continue;

    int current = digitalRead(config.slots[i].gpio);
    int last = lastInputStates[i];

    bool triggered = false;
    if (type == SLOT_INPUT_TOUCH && current == HIGH && last == LOW) triggered = true;
    if (type == SLOT_INPUT_BUTTON && current == LOW && last == HIGH) triggered = true;

    if (triggered && (millis() - lastToggleTime[i] > 350)) {
      lastToggleTime[i] = millis();

      // Execute instantaneous local link ties!
      for (int l = 0; l < MAX_LINKS; l++) {
        if (config.links[l].triggerSlot == i && config.links[l].action != LINK_NONE) {
          uint8_t target = config.links[l].targetSlot;
          if (config.links[l].action == LINK_TOGGLE) {
            toggleOutputSlot(target, true);
          } else if (config.links[l].action == LINK_TURN_ON) {
            setOutputSlot(target, true, true);
          } else if (config.links[l].action == LINK_TURN_OFF) {
            setOutputSlot(target, false, true);
          }
        }
      }

      sendPacketToMaster("INPUT", "SLOT:" + String(i) + ":STATE:" + String(current));
    }
    lastInputStates[i] = current;
  }

  // Periodic sensor readings
  if (millis() - lastSensorPoll > 1000) {
    lastSensorPoll = millis();

    if (trigSlotIndex != -1 && echoSlotIndex != -1) {
      uint8_t trig = config.slots[trigSlotIndex].gpio;
      uint8_t echo = config.slots[echoSlotIndex].gpio;
      digitalWrite(trig, LOW); delayMicroseconds(2);
      digitalWrite(trig, HIGH); delayMicroseconds(10);
      digitalWrite(trig, LOW);
      long dur = pulseIn(echo, HIGH, 30000);
      cachedDistance = (dur > 0) ? (dur * 0.034 / 2) : -1;
    }

    if (dhtSensor) {
      float h = dhtSensor->readHumidity();
      float t = dhtSensor->readTemperature();
      if (!isnan(h) && !isnan(t)) {
        cachedHumidity = h;
        cachedTemperature = t;
      }
    }
  }
}

void sendAnnouncement() {
  String mac = getDeviceMacAddress();
  String payload = "MAC:" + mac + 
                   ":CHIP:" + String(CHIP_NAME_STR) + 
                   ":GPIOS:" + String(SAFE_GPIOS_CSV) + 
                   ":SLOTS:" + String(MAX_GPIO_SLOTS) + 
                   ":MODE:" + String(config.transportMode == MODE_WIRELESS ? "WIFI" : "WIRED") +
                   ":FW:3.1.0";
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
    String stateStr = "";
    int maxSlots = config.numConfiguredSlots > 0 ? config.numConfiguredSlots : MAX_GPIO_SLOTS;
    if (maxSlots > MAX_GPIO_SLOTS) maxSlots = MAX_GPIO_SLOTS;
    for (int i = 0; i < maxSlots; i++) {
      stateStr += (i > 0 ? ":" : "") + String(outputStates[i] ? 1 : 0);
    }
    String rep = "LVL:" + String(cachedDistance) + 
                 ":TMP:" + String(cachedTemperature, 1) + 
                 ":HUM:" + String(cachedHumidity, 1) + 
                 ":OUT:" + stateStr;
    sendPacketToMaster("REP", rep);
  }
  // Verb 2: SET (e.g. SET:SLOT:<id>:STATE:<0|1>)
  else if (pkt.verb == "SET") {
    if (pkt.payload.startsWith("SLOT:")) {
      int sIdx = pkt.payload.indexOf("SLOT:") + 5;
      int stIdx = pkt.payload.indexOf(":STATE:");
      if (stIdx != -1) {
        int slot = pkt.payload.substring(sIdx, stIdx).toInt();
        int st = pkt.payload.substring(stIdx + 7).toInt();
        setOutputSlot(slot, (st == 1), true);
      }
    }
  }
  // Verb 3: BIND (Assigns permanent Node ID to this node matching MAC)
  else if (pkt.verb == "BIND") {
    String myMac = getDeviceMacAddress();
    if (pkt.payload.indexOf("MAC:" + myMac) != -1) {
      int idIdx = pkt.payload.indexOf(":SET_ID:");
      if (idIdx != -1) {
        String newId = pkt.payload.substring(idIdx + 8);
        strncpy(config.nodeId, newId.c_str(), sizeof(config.nodeId) - 1);
        config.nodeId[sizeof(config.nodeId) - 1] = '\0';
        saveConfig();
        sendPacketToMaster("ACK", "BOUND_OK");
      }
    }
  }
  // Verb 4: CFG (Declarative slot / link / schedule configuration from Master)
  else if (pkt.verb == "CFG") {
    if (pkt.payload.startsWith("SLOT:")) {
      int pSlot = pkt.payload.substring(5, pkt.payload.indexOf(":GPIO:")).toInt();
      int pGpio = pkt.payload.substring(pkt.payload.indexOf(":GPIO:") + 6, pkt.payload.indexOf(":TYPE:")).toInt();
      int pType = pkt.payload.substring(pkt.payload.indexOf(":TYPE:") + 6, pkt.payload.indexOf(":INV:")).toInt();
      int pInv  = pkt.payload.substring(pkt.payload.indexOf(":INV:") + 5).toInt();

      if (pSlot >= 0 && pSlot < MAX_GPIO_SLOTS && isSafeGpio(pGpio)) {
        config.slots[pSlot].gpio = pGpio;
        config.slots[pSlot].type = pType;
        config.slots[pSlot].activeLow = pInv;
        config.numConfiguredSlots = max((int)config.numConfiguredSlots, pSlot + 1);
        saveConfig();
        applyHardwareConfiguration();
        sendPacketToMaster("ACK", "SLOT_CONFIGURED:" + String(pSlot));
      }
    } else if (pkt.payload.startsWith("LINK:")) {
      int idx  = pkt.payload.substring(5, pkt.payload.indexOf(":TRIG:")).toInt();
      int trig = pkt.payload.substring(pkt.payload.indexOf(":TRIG:") + 6, pkt.payload.indexOf(":TGT:")).toInt();
      int tgt  = pkt.payload.substring(pkt.payload.indexOf(":TGT:") + 5, pkt.payload.indexOf(":ACT:")).toInt();
      int act  = pkt.payload.substring(pkt.payload.indexOf(":ACT:") + 5).toInt();

      if (idx >= 0 && idx < MAX_LINKS) {
        config.links[idx].triggerSlot = trig;
        config.links[idx].targetSlot = tgt;
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
        config.schedules[sIdx].targetSlot = p[2];
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
// OPTION 1: CAPTIVE PORTAL ONBOARDING WIZARD
// =========================================================================
void startCaptivePortal() {
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
    html += "<option value='1'" + String(config.transportMode == MODE_WIRELESS ? " selected" : "") + ">Wireless (Wi-Fi Star-Mesh Client)</option>";
    html += "<option value='0'" + String(config.transportMode == MODE_WIRED ? " selected" : "") + ">Wired (RS-422 / Serial Star Hub)</option>";
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

void setup() {
  Serial.begin(115200);
  delay(100);

  loadConfigFromStorage();
  applyHardwareConfiguration();

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

  // If force requested or wireless mode without configured Wi-Fi credentials -> Start Captive Portal
  if (forcePortal || (config.transportMode == MODE_WIRELESS && strlen(config.wifiSsid) == 0)) {
    startCaptivePortal();
    return;
  }

  // Initialize Wireless Mode
  if (config.transportMode == MODE_WIRELESS) {
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
      return;
    }
  } 
  // Initialize Wired Mode
  else {
    Serial.println("[WIRED] Operating on Isolated RS-422 Hardware Serial Star Bus.");
    if (config.apEnabled) {
      Serial.printf("[AP] Starting downstream SoftAP '%s' for child nodes...\n", config.apSsid);
      WiFi.mode(WIFI_AP);
      WiFi.softAP(config.apSsid, config.apPass);
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
  // If in Captive Portal mode, handle DNS and HTTP requests
  if (inCaptivePortal) {
    if (dnsServer) dnsServer->processNextRequest();
    if (portalServer) portalServer->handleClient();
    checkPhysicalInputs();
    return;
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
        Serial.write(c); // Forward child packet directly over RS-422 bus to Master
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
