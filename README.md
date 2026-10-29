# Home Assistant - Mini

[![PlatformIO Registry](https://img.shields.io/badge/PlatformIO-Compatible-orange?logo=platformio)](https://platformio.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Hardware: ESP32 / ESP32-C3 / ESP8266](https://img.shields.io/badge/Hardware-ESP32%20%7C%20ESP32--C3%20%7C%20ESP8266-green)](https://www.espressif.com/)

**Home Assistant - Mini** is a high-reliability, decentralized, offline-first home automation supervisor and microcontroller star-mesh platform. It combines **isolated full-duplex RS-422 hardware star ports** with an **autonomous Wi-Fi star-mesh** under a lightweight, deterministic ASCII delimiter protocol.

Unlike cloud-dependent commercial systems, **Home Assistant - Mini** runs entirely on-chip: an embedded glassmorphic web dashboard, a declarative JSON multi-condition automation rules engine, independent sensor alert feeds, autonomous slave EEPROM schedules, and sub-millisecond local hardware links that execute directly in silicon even if the central supervisor or network bus is severed.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |             HOME WI-FI / ROUTER             |
                                      |   (Optional Internet & Cloud MQTT Bridge)   |
                                      +---------------------------------------------+
                                                             |
                                                             v (STA Client Mode)
+-------------------------------------------------------------------------------------------------------------------+
| MASTER SUPERVISOR (ESP32-DevKit Dual-Core / ESP32-C3)                                                             |
| - Onboard Glassmorphic Web Dashboard (Port 80) with RBAC (Admin, Member, Guest)                                    |
| - Persistent LittleFS Flash Registry (/config/nodes.json, /config/rules.json, /config/notifications.json)          |
| - Dynamic Multi-Condition (AND/OR) Rules Engine & Independent Sensor Alert Feed                                    |
| - Star Port 1: UART1 (RX: GPIO 4, TX: GPIO 5)                                                                     |
| - Star Port 2: UART2 (RX: GPIO 16, TX: GPIO 17) [ESP32 DevKit Dual-Core]                                          |
| - Multi-Client Wireless Star-Mesh TCP Server (Port 8266) & SoftAP 'Mini-HA-Master'                                 |
| - Real-World Time Sync (Browser auto-syncs Unix epoch without NTP/Internet)                                       |
+-------------------------------------------------------------------------------------------------------------------+
             |                                                  |                                  |
             | Star Port 1: RS-422                              | Star Port 2: RS-422              | Direct Wi-Fi Mesh
             | (Full-Duplex Hardware Bus)                       | (Isolated Line Port)             | (TCP Socket :8266)
             v                                                  v                                  v
+------------------------------------------+       +----------------------------------+   +-------------------------+
| WIRED SLAVE 1: TANK & PUMP (ESP8266)     |       | WIRED SLAVE 2: SWITCHBOARD (C3)  |   | WIRELESS SLAVE 3: ROOM  |
| - Transport: MODE_WIRED (UART)           |       | - Transport: MODE_WIRED (UART)   |   | - Transport: WIRELESS   |
| - Peripherals: HC-SR04, Pump Relay       |       | - Peripherals: 4x Wall Rockers,  |   | - Autonomous Schedules  |
| - Sub-ms Local Link Ties (<1ms)          |       |   4x Relays, DHT Climate         |   | - Direct Wi-Fi to Hub   |
| - Hosts SoftAP: "MiniHA_AP_N01" (Bridge) |       | - Sub-ms Local Silicon Links     |   +-------------------------+
+------------------------------------------+       +----------------------------------+
             |
             | Downstream SoftAP Bridge ("MiniHA_AP_N01")
             | TCP Bridge on Port 8266 (Optional Stealth SSID)
             v
+-----------------------------------------------------------------------------------+
| WIRELESS SLAVE 4: REMOTE GARDEN / PERIMETER (ESP8266 / ESP32-C3)                  |
| - Mode: MODE_WIRELESS                                                             |
| - Connected to: Slave 1 Repeater SoftAP ("MiniHA_AP_N01")                         |
| - Transparently bridged by Slave 1 over RS-422 to Master Hub                      |
+-----------------------------------------------------------------------------------+
```

---

## Key Features

1. **100% Offline Standalone Operation**:
   - Master serves a high-performance modern web dashboard with sidebar navigation, realtime hardware diagnostics (RAM, LittleFS partition usage, uptime, bus ports), and modal-driven configuration directly from flash.
   - Zero external CDNs, external fonts, or internet connectivity required.

2. **Universal Generic Slaves (Decoupled Peripheral Model)**:
   - Slaves contain **no hardcoded pin assignments, sensor math, or tank formulas**.
   - Upon boot, slaves broadcast factory announcements (`ANN`) specifying their architecture and safe GPIOs.
   - Master assigns peripherals (`COMP_RELAY`, `COMP_BUTTON`, `COMP_TOUCH`, `COMP_TOGGLE_SWITCH`, `COMP_ULTRASONIC`, `COMP_DHT`, `COMP_ADC`) through declarative protocol packets.

3. **Sub-Millisecond Direct Hardware Links**:
   - Wall switches, push buttons, and capacitive touch sensors trigger relays locally on the slave microcontroller in $<1$ ms without waiting for bus communication.

4. **Edge-Triggered Wall Rocker Switch Support**:
   - Mechanical 2-way wall switches (`COMP_TOGGLE_SWITCH`) trigger on **any mechanical flip** (up or down).
   - Instant push-on-change event reporting (`INPUT` packet) triggers Master automations in $<5$ ms.

5. **Standalone 8-Slot Local Schedules**:
   - Up to 8 daily schedules (with midnight-crossing support and multi-actuator bitmasks) are stored directly in slave EEPROM.
   - Relays turn ON/OFF reliably even if the bus cable is cut or the Master is powered down.

6. **Automations & Independent Notifications**:
   - **Automations Tab**: Multi-condition (`AND` / `OR`) logic triggers multi-action relay state changes.
   - **Notifications Tab**: Independent sensor threshold warnings (e.g. Tank overflow, high heat) generate real-time alerts without altering actuator states.

7. **Downstream Wi-Fi SoftAP Bridge (Stealth Repeater)**:
   - Wired slaves can broadcast a local Wi-Fi SoftAP (with optional hidden/stealth SSID).
   - Wireless slaves out of range of the Master hub connect to the nearest wired slave and route transparently over RS-422.

---

## Directory Structure

```text
mini_ha/
├── common/
│   └── include/
│       └── node_protocol.h        # Compact ASCII delimiter protocol, structs & HAL definitions
├── master_firmware/
│   ├── platformio.ini             # PlatformIO config for Master (ESP32 DevKit & ESP32-C3)
│   ├── data/                      # Initial LittleFS flash structure
│   ├── include/                   # Web dashboard, rules engine, storage manager
│   └── src/
│       └── main.cpp               # Master supervisor firmware & bus coordinators
├── slave_firmware/
│   ├── platformio.ini             # PlatformIO config for Slaves (ESP8266 & ESP32-C3)
│   ├── include/                   # Chip capabilities, pin safety & HAL mappings
│   └── src/
│       └── main.cpp               # Universal generic slave firmware
├── pwa/                           # Progressive Web App source files
├── docs/                          # GitHub Pages static mirror of the PWA
├── COMMANDS_REFERENCE.md          # Comprehensive packet verbs, REST API & MQTT reference
└── README.md
```

> **Why both `pwa/` and `docs/`?**
> The `docs/` folder is a direct mirror of `pwa/` configured to serve the Progressive Web App live via **GitHub Pages** (which serves root or `/docs` by default) without requiring an external build server.

---

## Getting Started

### 1. Prerequisites
* [Visual Studio Code](https://code.visualstudio.com/)
* [PlatformIO IDE Extension](https://platformio.org/install/ide?install=vscode)

### 2. Flashing the Master Supervisor
* **ESP32 DevKit (Dual-Core Classic)**: Select `env:esp32dev` in PlatformIO and click **Upload**.
* **ESP32-C3**: Select `env:esp32c3` in PlatformIO and click **Upload**.

### 3. Flashing Slave Microcontrollers
* **WEMOS D1 Mini (ESP8266)**: Select `env:esp8266_d1mini` and click **Upload**.
* **ESP32-C3 DevKit**: Select `env:esp32_c3` and click **Upload**.
* **NodeMCU 1.0 (ESP-12E)**: Select `env:nodemcuv2` and click **Upload**.

### 4. Accessing the Dashboard
1. Connect to the Master's Wi-Fi access point: `Mini-HA-Master` (Password: `12345678`).
2. Open your browser and navigate to:
   ```text
   http://192.168.4.1   or   http://miniha.local
   ```
3. Sign in with the default credentials:
   * **Username**: `admin`
   * **Password**: `admin123`

---

## Hardware Pinout Reference

### Master Supervisor (Dual Silicon Support)
| Function | ESP32 DevKit (Classic Dual-Core) | ESP32-C3 DevKit | Description |
| :--- | :--- | :--- | :--- |
| **Star Port 1 RX** | GPIO 4 | GPIO 4 | Hardware UART1 Receive from Star Port 1 |
| **Star Port 1 TX** | GPIO 5 | GPIO 5 | Hardware UART1 Transmit to Star Port 1 |
| **Star Port 2 RX** | GPIO 16 (RX2) | — | Hardware UART2 Receive from Star Port 2 |
| **Star Port 2 TX** | GPIO 17 (TX2) | — | Hardware UART2 Transmit to Star Port 2 |

### Slave Microcontrollers (Safe GPIO Allocation)
The Web UI strictly filters pin selection based on detected chip architecture:

* **ESP32-C3**: `GPIO 0, 1, 3, 4, 5, 6, 7, 8, 10, 20, 21` (avoiding strapping pins 2, 8, 9).
* **ESP8266 (D1 Mini / NodeMCU)**: `D1 (GPIO 5), D2 (GPIO 4), D5 (GPIO 14), D6 (GPIO 12), D7 (GPIO 13)` (avoiding boot pins D3, D4, D8).
* **ESP32 (Classic DevKit)**: `GPIO 4, 5, 12, 13, 14, 15, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33`.

---

## License
Open-source under the [MIT License](LICENSE).
