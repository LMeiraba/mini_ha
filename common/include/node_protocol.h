#pragma once
#include <Arduino.h>

// =========================================================================
// MINI-HOMEASSISTANT STAR-MESH PROTOCOL SPECIFICATION (v2.0)
// =========================================================================
// All messages follow the deterministic ASCII delimiter format:
// TO:<TargetId>:FROM:<SenderId>:<Verb>:<Payload>\n
//
// Key Invariants:
// - Universal string length limit: 128 bytes to prevent memory fragmentation
// - Schema Version: Tracked via SCHEMA_MAGIC
// =========================================================================

#define PROTOCOL_MAX_LINE       128
#define MAX_COMPONENTS          16    // Max peripheral components per node
#define MAX_GPIO_SLOTS          16    // Backward compatibility alias
#define MAX_LINKS               16    // Max local sensor-actuator link rules per node
#define MAX_SCHEDULES           8     // Max standalone local schedule slots per node
#define PROTOCOL_SCHEMA_VERSION 0x0008
#define SCHEMA_MAGIC            (0xAA550000 | PROTOCOL_SCHEMA_VERSION)
#define DEFAULT_MESH_PORT       8266

// Transport mode for the node
enum NodeTransportMode : uint8_t {
  MODE_WIRED    = 0,  // Hardware Serial (UART / RS-422 isolated star hub)
  MODE_WIRELESS = 1   // Wi-Fi Station (TCP socket to Master or Parent Slave AP)
};

// Hardware Architecture / Chip Type reported during handshake
enum NodeChipModel : uint8_t {
  MODEL_UNKNOWN   = 0,
  MODEL_ESP8266   = 1,
  MODEL_ESP32     = 2,
  MODEL_ESP32C3   = 3,
  MODEL_ESP32S3   = 4,
  MODEL_RP2040    = 5,
  MODEL_STM32     = 6,
  MODEL_WCH_CH32V = 7
};

// Declarative Hardware Component Types (Decoupled from raw pin count)
enum ComponentType : uint8_t {
  COMP_UNUSED = 0,
  COMP_RELAY = 1,           // Output pin (pin1), activeLow (flags & 1)
  COMP_BUTTON = 2,          // Momentary Push Button: pin1, pullup, triggers on press / active LOW
  COMP_TOUCH = 3,           // Momentary Capacitive Touch: pin1, triggers on touch / active HIGH
  COMP_TOGGLE_SWITCH = 4,   // Wall Rocker / Toggle Switch: pin1, triggers on ANY state change (flip UP/DOWN)
  COMP_ULTRASONIC = 5,      // Trig pin (pin1), Echo pin (pin2), tankDepth (param1)
  COMP_DHT = 6,             // Data pin (pin1), DHT11 (flags=0) vs DHT22 (flags=1)
  COMP_ANALOG_ADC = 7,      // ADC pin (pin1)
  COMP_DS18B20 = 8          // OneWire pin (pin1)
};

// Legacy Slot Pin Aliases for backward compatibility
enum SlotPinType : uint8_t {
  SLOT_UNUSED = 0,
  SLOT_OUTPUT_RELAY = 1,
  SLOT_INPUT_TOUCH = 3,
  SLOT_INPUT_BUTTON = 2,
  SLOT_SENSOR_ULTRASONIC_TRIG = 4,
  SLOT_SENSOR_ULTRASONIC_ECHO = 10,
  SLOT_SENSOR_DHT11 = 5,
  SLOT_SENSOR_DHT22 = 11,
  SLOT_SENSOR_DS18B20 = 6,
  SLOT_ANALOG_IN = 7
};

// Sub-millisecond Local Sensor-Actuator Ties (Instant local response)
enum LinkRuleAction : uint8_t {
  LINK_NONE = 0,
  LINK_TOGGLE,                // Toggle output component
  LINK_TURN_ON,               // Force output component ON
  LINK_TURN_OFF               // Force output component OFF
};

// Peripheral Component Definition
struct ComponentConfig {
  uint8_t type;               // ComponentType
  uint8_t pin1;               // Primary GPIO pin (Relay pin, DHT data pin, Trig pin, Button pin)
  uint8_t pin2;               // Secondary GPIO pin (Echo pin for Ultrasonic, 255 if unused)
  uint8_t flags;              // bit 0: activeLow / pullup, bit 1: DHT22 (1) vs DHT11 (0)
  uint16_t param1;            // Custom parameter: e.g. tank depth in cm (default 200)
  char id[12];                // Unique key: e.g. "pump", "tank", "climate"
};

// Single Sensor-Actuator Link Rule
struct LinkRuleDef {
  uint8_t triggerComp;        // Input component that triggers event
  uint8_t targetComp;         // Output component to actuate
  uint8_t action;             // LinkRuleAction (e.g. LINK_TOGGLE)
  uint8_t reserved;
};

// Standalone Local Time Schedule (Runs locally on slave even if Master is dead/disconnected!)
struct LocalScheduleDef {
  uint8_t enabled;            // 1 = Active, 0 = Disabled
  uint8_t targetComp;         // Output component to actuate (legacy single)
  uint8_t action;             // LinkRuleAction (e.g. LINK_TURN_ON or LINK_TURN_OFF)
  uint8_t onHour;             // 0-23
  uint8_t onMinute;           // 0-59
  uint8_t offHour;            // 0-23
  uint8_t offMinute;          // 0-59
  uint8_t daysOfWeekMask;     // Bitmask: bit 0 = Sun, bit 1 = Mon ... bit 6 = Sat (0x7F = Everyday)
  uint16_t targetCompsMask;   // Bitmask of target components to actuate (multi-actuator: bit 0 = Comp 0...)
};

// Complete Persistent Storage Layout (Stored in Slave EEPROM / Flash Sector)
struct NodeStorageConfig {
  uint32_t magic;             // SCHEMA_MAGIC (0xAA550007)
  char nodeId[16];            // Assigned Node ID (e.g. "N01", "N01-esp32c3") or "UNBOUND"
  
  uint8_t transportMode;      // 0 = MODE_WIRED, 1 = MODE_WIRELESS
  char wifiSsid[33];          // Target Parent AP SSID (Master AP, Wired Slave AP, or Home Wi-Fi)
  char wifiPass[65];          // Wi-Fi Password
  char masterHost[33];        // Master/Parent IP or Hostname (e.g. "192.168.4.1")
  uint16_t masterPort;        // Master Port (default 8266)

  uint8_t apEnabled;          // 1 = hosts downstream SoftAP (Repeater mode)
  uint8_t apHidden;           // 1 = hidden SSID broadcast
  char apSsid[33];            // Downstream SoftAP SSID (e.g. "SlaveNet-01")
  char apPass[65];            // Downstream SoftAP Password

  uint8_t numConfiguredComponents; // Count of active components
  uint8_t numConfiguredLinks;      // Count of active links
  uint8_t numConfiguredSchedules;  // Count of active local schedules
  ComponentConfig components[MAX_COMPONENTS];
  LinkRuleDef links[MAX_LINKS];
  LocalScheduleDef schedules[MAX_SCHEDULES];
};

// Protocol Parser Result
struct ParsedPacket {
  bool isValid;
  String to;
  String from;
  String verb;
  String payload;
};

// Helper: Fast zero-copy / minimal heap protocol line parser
inline ParsedPacket parseProtocolLine(const String& line) {
  ParsedPacket pkt;
  pkt.isValid = false;

  if (!line.startsWith("TO:")) return pkt;

  int c1 = 2; // Index of first ':'
  int c2 = line.indexOf(':', c1 + 1);
  if (c2 == -1) return pkt;
  pkt.to = line.substring(c1 + 1, c2);

  if (!line.substring(c2 + 1).startsWith("FROM:")) return pkt;
  int c3 = c2 + 5; // Index of ':' in "FROM:"
  int c4 = line.indexOf(':', c3 + 1);
  if (c4 == -1) return pkt;
  pkt.from = line.substring(c3 + 1, c4);

  int c5 = line.indexOf(':', c4 + 1);
  if (c5 == -1) {
    pkt.verb = line.substring(c4 + 1);
    pkt.payload = "";
  } else {
    pkt.verb = line.substring(c4 + 1, c5);
    pkt.payload = line.substring(c5 + 1);
  }

  pkt.isValid = true;
  return pkt;
}

// Helper: Formatter for standard outgoing packet
inline String buildPacket(const String& to, const String& from, const String& verb, const String& payload = "") {
  String out = "TO:" + to + ":FROM:" + from + ":" + verb;
  if (payload.length() > 0) {
    out += ":" + payload;
  }
  return out;
}
