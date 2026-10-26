# Mini-HA: Deterministic Offline-First Smart Home Star-Mesh Platform

[![PlatformIO Registry](https://img.shields.io/badge/PlatformIO-Compatible-orange?logo=platformio)](https://platformio.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Hardware: ESP32-C3 / ESP8266](https://img.shields.io/badge/Hardware-ESP32--C3%20%7C%20ESP8266-green)](https://www.espressif.com/)

**Mini-HA** is a high-reliability, decentralized, offline-first smart home platform designed for microcontrollers (ESP32-C3, ESP8266, ESP32). It combines **full-duplex isolated RS-422 wired star networking** with an **autonomous Wi-Fi star-mesh** under a unified, lightweight ASCII protocol.

Unlike monolithic or cloud-dependent solutions, Mini-HA provides an on-chip web dashboard, declarative JSON rules engine, autonomous slave schedules, and sub-millisecond local sensor-actuator link ties that run directly in silicon even if the network or central supervisor fails.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |             HOME WI-FI / ROUTER             |
                                      |   (Optional Internet & Supla Cloud Bridge)   |
                                      +---------------------------------------------+
                                                             |
                                                             v (STA Mode)
+-------------------------------------------------------------------------------------------------------------------+
| MASTER SUPERVISOR (ESP32-C3)                                                                                      |
| - Onboard Web Dashboard & Setup Wizard (Port 80)                                                                  |
| - LittleFS Persistent Storage (/config/nodes.json, /config/rules.json, /config/system.json)                       |
| - Declarative JSON Rules Engine (Evaluated every 500ms)                                                           |
| - Multi-Client Wireless Star-Mesh TCP Server (Port 8266)                                                          |
| - Isolated RS-422 Hardware Serial Bus (115200 baud, UART1)                                                        |
| - Optional Supla Cloud Bridge with 10-minute History Logging Hack (GPM)                                            |
+-------------------------------------------------------------------------------------------------------------------+
             |                                                                      |
             | Full-Duplex RS-422 Star Hub                                          | Direct Wi-Fi
             | (74HC08 Logic Isolation)                                             | (TCP Socket :8266)
             v                                                                      v
+------------------------------------------+                      +------------------------------------------+
| WIRED SLAVE 1: ROOFTOP TANK (ESP8266)     |                      | WIRELESS SLAVE 3: REMOTE ROOM (ESP8266)  |
| - Mode: MODE_WIRED                       |                      | - Mode: MODE_WIRELESS                    |
| - Peripheral: Ultrasonic, DHT11          |                      | - Onboarded via: Captive Portal Wizard   |
| - 8-Slot Standalone Daily Schedules      |                      | - Connects to: Master AP or Home Router  |
| - Hosts SoftAP: "SlaveNet-01" (Repeater) |                      | - Autonomous Local Schedules & Links     |
+------------------------------------------+                      +------------------------------------------+
             |
             | Downstream Wi-Fi SoftAP ("SlaveNet-01")
             | TCP Bridge on Port 8266
             v
+-----------------------------------------------------------------------------------+
| WIRELESS SLAVE 4: EXTENDED MESH (ESP8266 / ESP32-C3)                              |
| - Mode: MODE_WIRELESS                                                             |
| - Onboarded via: Option 1 Captive Portal                                          |
| - Parent: Connected to "SlaveNet-01" (Wired Slave AP!)                           |
| - Transparently bridged by Slave 1 over RS-422 to Master                         |
+-----------------------------------------------------------------------------------+
```

---

## Key Features

1. **100% Offline Autonomy**:
   - Master runs a full administrative web UI, role-based digest authentication (`Admin`, `Member`, `Guest`), and dynamic rules engine directly from LittleFS.
   - Zero internet connection or external servers required.

2. **Universal Generic Slaves (HAL)**:
   - Slaves contain **no hardcoded pin assignments, sensor math, or tank formulas**.
   - Upon power-up, slaves announce their MAC, chip architecture, and safe GPIOs.
   - Master dynamically assigns pins to virtual slots (relays, touch sensors, ultrasonic, DHT11/22, OneWire, ADC) via declarative protocol packets.

3. **Sub-Millisecond Sensor-Actuator Link Ties**:
   - Wall switches and touch buttons trigger relay actions locally on the slave in $<1$ ms without waiting for a round-trip to the Master.

4. **Standalone 8-Slot Local Schedules**:
   - Up to 8 daily schedules (with midnight-crossing support and day-of-week masks) are stored in the slave's EEPROM.
   - Actuators switch on/off on schedule even if the RS-422 bus is severed or the Master is powered off.

5. **Option 1: Captive Portal Wireless Onboarding**:
   - When unconfigured or upon holding the BOOT/FLASH button for 2 seconds, wireless slaves launch an open setup AP (`SLAVE-SETUP-XXXX`).
   - The built-in DNS server captures the connection and opens the setup wizard.
   - Users can scan and select **any parent network** (the Master AP, a wired slave's repeater AP, or a home router).

6. **Transparent Star-Mesh Bridging**:
   - Wired slaves can host a downstream SoftAP (`SlaveNet`) on TCP port 8266.
   - Packets from child wireless nodes are transparently forwarded across the RS-422 bus to the Master.

---

## Directory Structure

```text
mini_ha/
├── common/
│   └── include/
│       └── node_protocol.h        # Unified ASCII delimiter protocol & storage layouts
├── master_firmware/
│   ├── platformio.ini             # PlatformIO config for Master (ESP32-C3)
│   ├── data/                      # LittleFS storage (nodes.json, rules.json, system.json)
│   ├── include/                   # Web dashboard, rules engine, storage manager
│   └── src/
│       └── main.cpp               # Master supervisor firmware
├── slave_firmware/
│   ├── platformio.ini             # PlatformIO config for Slaves (ESP8266 & ESP32-C3)
│   ├── include/                   # Chip capabilities & safe GPIO mapping
│   └── src/
│       └── main.cpp               # Universal generic slave firmware
├── mini_ha.code-workspace         # VS Code multi-project workspace
└── README.md
```

---

## Protocol Specification

All communication occurs via compact, human-readable ASCII packets terminated by `\n`:

```text
TO:<TargetId>:FROM:<SenderId>:<Verb>:<Payload>\n
```

### Core Verbs:
| Verb | Direction | Description | Example Payload |
| :--- | :--- | :--- | :--- |
| `ANN` | Slave $\rightarrow$ Master | Factory Announcement | `MAC:B4E62D1A:CHIP:ESP8266:GPIOS:4,5,12,13,14,16:SLOTS:16:MODE:WIRED:FW:3.1.0` |
| `BIND` | Master $\rightarrow$ Slave | Assign Permanent ID | `MAC:B4E62D1A:SET_ID:N01` |
| `CFG` | Master $\rightarrow$ Slave | Declarative Slot / Link Setup | `SLOT:0:GPIO:14:TYPE:6:INV:0` (Slot 0, GPIO 14, DHT11) |
| `REQ` | Master $\rightarrow$ Slave | Telemetry Poll Request | `POLL` |
| `REP` | Slave $\rightarrow$ Master | Telemetry Data Reply | `LVL:185:TMP:27.4:HUM:68.0:OUT:0:0:0:0` |
| `SET` | Master $\rightarrow$ Slave | Direct Actuation Command | `SLOT:0:STATE:1` (Turn Slot 0 ON) |
| `TIME` | Master $\rightarrow$ Slave | Unix Epoch Synchronization | `1729864200` |
| `EVT` | Slave $\rightarrow$ Master | Unsolicited State Event | `SLOT:0:STATE:1` |

---

## Getting Started

### 1. Prerequisites
* [Visual Studio Code](https://code.visualstudio.com/)
* [PlatformIO IDE Extension](https://platformio.org/install/ide?install=vscode)

### 2. Opening the Workspace
In VS Code, go to **File $\rightarrow$ Open Workspace from File...** and select:
```text
mini_ha/mini_ha.code-workspace
```

### 3. Flashing Master
* **For ESP32-C3**: Select `Default (master_firmware)` or `env:esp32c3` in the bottom status bar and click **Upload**.
* **For ESP32 Dev Board (Classic Dual-Core)**: Select `env:esp32dev` in the bottom status bar and click **Upload**.
* *(First time only)*: Under PlatformIO Project Tasks $\rightarrow$ Platform $\rightarrow$ Click **Upload Filesystem Image** to write the `/config/` JSON files to LittleFS.

### 4. Flashing Slaves
1. In the bottom status bar, switch to `env:esp8266_d1mini (slave_firmware)` or `env:esp32_c3 (slave_firmware)`.
2. Connect your board via USB and click **Upload**.

---

## Onboarding a Wireless Slave (Option 1)
1. Power up the unconfigured slave.
2. Connect your phone/PC to the open Wi-Fi network: `SLAVE-SETUP-XXXX`.
3. The setup page will automatically pop up (or visit `http://192.168.4.1`).
4. Select your Parent Network (Master AP, Wired Slave AP `SlaveNet`, or Home Wi-Fi).
5. Enter the Wi-Fi password and click **Save Configuration & Connect**.
6. The node will commit settings to flash, reboot, join the network, and register with the Master supervisor!

---

## Hardware Pinout Reference

### Master Node Pinouts (Dual Silicon Architecture)
| Function | ESP32-C3 DevKit | ESP32 Dev Board (Classic) | Description |
| :--- | :--- | :--- | :--- |
| **RS-422 RX** | GPIO 4 | GPIO 16 (RX2) | Receives data from 74HC08 star hub |
| **RS-422 TX** | GPIO 5 | GPIO 17 (TX2) | Transmits data to RS-422 driver |
| **Local Pump Relay** | GPIO 8 | GPIO 18 | Dedicated active-high relay output |
| **Local Manual Button** | GPIO 9 | GPIO 19 | Momentary button (internal pullup) |

### Wired Slave: Rooftop Tank (ESP8266 D1 Mini)
| Function | ESP8266 Pin | Physical GPIO |
| :--- | :--- | :--- |
| Ultrasonic Trigger | D1 | GPIO 5 |
| Ultrasonic Echo | D2 | GPIO 4 |
| DHT11 Temp/Humidity | D5 | GPIO 14 |
| Hardware Serial TX/RX | TX / RX | GPIO 1 / GPIO 3 |

---

## License
This project is open-source under the [MIT License](LICENSE).
