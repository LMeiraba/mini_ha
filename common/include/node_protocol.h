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
#define MAX_GPIO_SLOTS          16    // Max virtual slots per node
#define MAX_LINKS               16    // Max local sensor-actuator link rules per node
#define MAX_SCHEDULES           8     // Max standalone local schedule slots per node
#define PROTOCOL_SCHEMA_VERSION 0x0006
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

// Declarative Virtual Slot Types (Assigned dynamically by Master)
enum SlotPinType : uint8_t {
  SLOT_UNUSED = 0,
  SLOT_OUTPUT_RELAY,          // Binary output actuator (relay, light, valve)
  SLOT_INPUT_TOUCH,           // Momentary touch sensor (e.g. TTP224)
  SLOT_INPUT_BUTTON,          // Momentary button with internal pullup
  SLOT_SENSOR_ULTRASONIC_TRIG,// Ultrasonic trigger pulse output
  SLOT_SENSOR_ULTRASONIC_ECHO,// Ultrasonic echo duration input
  SLOT_SENSOR_DHT11,          // Single-wire DHT11 Temp/Humidity
  SLOT_SENSOR_DHT22,          // Single-wire DHT22 Temp/Humidity
  SLOT_SENSOR_DS18B20,        // OneWire temperature
  SLOT_ANALOG_IN              // ADC voltage/pressure input
};

// Sub-millisecond Local Sensor-Actuator Ties (Instant local response)
enum LinkRuleAction : uint8_t {
  LINK_NONE = 0,
  LINK_TOGGLE,                // Toggle output slot
  LINK_TURN_ON,               // Force output slot ON
  LINK_TURN_OFF               // Force output slot OFF
};

// Single Pin Slot Descriptor
struct GpioSlotDef {
  uint8_t gpio;               // Physical GPIO pin number on the MCU
  uint8_t type;               // SlotPinType
  uint8_t activeLow;          // 1 = active low (most relays), 0 = active high
  uint8_t reserved;           // For alignment / future expansion
};

// Single Sensor-Actuator Link Rule
struct LinkRuleDef {
  uint8_t triggerSlot;        // Input slot that triggers event (e.g. Touch Slot 4)
  uint8_t targetSlot;         // Output slot to actuate (e.g. Relay Slot 0)
  uint8_t action;             // LinkRuleAction (e.g. LINK_TOGGLE)
  uint8_t reserved;
};

// Standalone Local Time Schedule (Runs locally on slave even if Master is dead/disconnected!)
struct LocalScheduleDef {
  uint8_t enabled;            // 1 = Active, 0 = Disabled
  uint8_t targetSlot;         // Output slot to actuate (legacy single slot)
  uint8_t action;             // LinkRuleAction (e.g. LINK_TURN_ON or LINK_TURN_OFF)
  uint8_t onHour;             // 0-23
  uint8_t onMinute;           // 0-59
  uint8_t offHour;            // 0-23
  uint8_t offMinute;          // 0-59
  uint8_t daysOfWeekMask;     // Bitmask: bit 0 = Sun, bit 1 = Mon ... bit 6 = Sat (0x7F = Everyday)
  uint16_t targetSlotsMask;   // Bitmask of target slots to actuate (multi-actuator: bit 0 = Slot 0, bit 1 = Slot 1...)
};

// Complete Persistent Storage Layout (Stored in Slave EEPROM / Flash Sector)
struct NodeStorageConfig {
  uint32_t magic;             // SCHEMA_MAGIC (0xAA550004)
  char nodeId[16];            // Assigned Node ID (e.g. "N01", "N01-esp32c3") or "UNBOUND"
  
  uint8_t transportMode;      // 0 = MODE_WIRED, 1 = MODE_WIRELESS
  char wifiSsid[33];          // Target Parent AP SSID (Master AP, Wired Slave AP, or Home Wi-Fi)
  char wifiPass[65];          // Wi-Fi Password
  char masterHost[33];        // Master/Parent IP or Hostname (e.g. "192.168.4.1")
  uint16_t masterPort;        // Master Port (default 8266)

  uint8_t apEnabled;          // 1 = hosts downstream SoftAP (Repeater mode)
  char apSsid[33];            // Downstream SoftAP SSID (e.g. "SlaveNet-01")
  char apPass[65];            // Downstream SoftAP Password

  uint8_t numConfiguredSlots; // Count of active slots
  uint8_t numConfiguredLinks; // Count of active links
  uint8_t numConfiguredSchedules; // Count of active local schedules
  GpioSlotDef slots[MAX_GPIO_SLOTS];
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
