# Mini-HA Protocol & Commands Reference

This document provides a comprehensive specification of all communication protocols, command verbs, payload combinations, and MQTT topics used throughout the **Home Assistant - Mini** ecosystem.

---

## 1. Physical Layer: RS-422 / Serial & Mesh Protocol

All communication between the **Master Hub** and **Slave Nodes** (whether over RS-422 balanced differential wire or local slave repeater TCP socket) uses deterministic, delimiter-separated ASCII frames terminated by `\n`.

### Frame Format
```text
TO:<TargetId>:FROM:<SenderId>:<Verb>:<Payload>\n
```

* **Maximum Frame Length**: 128 bytes (strictly bounded to eliminate heap fragmentation on small MCUs).
* **Target / Sender Identifiers**:
  * `M`: Master Hub
  * `N01`, `N02`, ... `N16`: Assigned Slave Node IDs
  * `NEW`: Uncommissioned node awaiting binding
  * `ALL`: Bus broadcast to every connected node

---

### Verbs & Command Combinations

| Verb | Direction | Payload Structure | Example | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`ANN`** | Slave $\rightarrow$ Master | `MAC:<mac>:CHIP:<chip>:GPIOS:<csv>:COMPS:<max>:MODE:<mode>:AP:<0\|1>:FW:<ver>` | `TO:M:FROM:NEW:ANN:MAC:1463936F30B0:CHIP:ESP32C3:GPIOS:0,1,3,4,5,6,7,8,10,20,21:COMPS:16:MODE:WIRED:AP:0:FW:0.1.1-beta` | Periodic factory announcement from unassigned or rebooted slave node. |
| **`BIND`**| Master $\rightarrow$ Slave | `MAC:<mac>:SET_ID:<newNodeId>[:AP:<en>:AP_SSID:<ssid>:AP_PASS:<pass>:AP_HIDDEN:<0\|1>]` | `TO:NEW:FROM:M:BIND:MAC:1463936F30B0:SET_ID:N01:AP:1:AP_SSID:MiniHA_N01:AP_PASS:secret123:AP_HIDDEN:0` | Matches hardware MAC and permanently assigns Node ID and optional repeater AP into slave EEPROM. |
| **`CFG`** | Master $\rightarrow$ Slave | `COMP:<idx>:<type>:<pin1>:<pin2>:<flags>:<param1>:<id>` | `TO:N01:FROM:M:CFG:COMP:0:1:8:255:0:0:relay1` | Dynamically configures a decoupled peripheral component entity on the slave. |
| **`CFG`** | Master $\rightarrow$ Slave | `AP:<en>:<ssid>:<pass>:<hidden>` | `TO:N01:FROM:M:CFG:AP:1:MiniHA_N01:secret123:1` | Configures downstream Wi-Fi SoftAP Bridge (with stealth/hidden SSID toggle). |
| **`CFG`** | Master $\rightarrow$ Slave | `LINK:<idx>:TRIG:<comp>:TGT:<comp>:ACT:<act>` | `TO:N01:FROM:M:CFG:LINK:0:TRIG:1:TGT:0:ACT:1` | Programs **sub-millisecond instant hardware link** (e.g. Wall Rocker Comp 1 toggles Relay Comp 0 directly in silicon). |
| **`CFG`** | Master $\rightarrow$ Slave | `SCHED:<idx>:<en>:<targetCompsMask>:<act>:<onH>:<onM>:<offH>:<offM>` | `TO:N01:FROM:M:CFG:SCHED:0:1:1:1:18:00:06:00` | Stores autonomous clock timer in slave EEPROM with multi-actuator bitmask support. |
| **`REQ`** | Master $\rightarrow$ Slave | `POLL` | `TO:N01:FROM:M:REQ:POLL` | Requests immediate telemetry & state report from the slave node. |
| **`REP`** | Slave $\rightarrow$ Master | `<id1>=<val1>:<id2>=<v1>,<v2>:heap=<bytes>:mode=<m>:fw=<ver>` | `TO:M:FROM:N01:REP:relay1=1:tank=142,71:heap=256000:mode=WIRED:fw=v0.1.1-beta` | Dynamic entity telemetry report with live heap, link mode, and firmware version. |
| **`INPUT`**| Slave $\rightarrow$ Master | `COMP:<id>:STATE:<0\|1>` | `TO:M:FROM:N01:INPUT:COMP:switch1:STATE:1` | Unsolicited instant push event when a wall rocker switch, button, or touch sensor flips state. Triggers real-time Master rules (<5ms). |
| **`DATA`** | Slave $\rightarrow$ Master | `<cid>=<val1>[,<val2>]` | `TO:M:FROM:N01:DATA:tank=138,73` | Push-on-change sensor delta report (dispatched when distance delta $\ge$ 2 cm or temp changes). |
| **`SET`** | Master $\rightarrow$ Slave | `<compId>:<0\|1\|2>` | `TO:N01:FROM:M:SET:relay1:1` | Drives output relay immediately (`0` = OFF, `1` = ON, `2` = Toggle). |
| **`TIME`**| Master $\rightarrow$ Slave | `<unix_epoch>` | `TO:ALL:FROM:M:TIME:1793304122` | Broadcasts real-world Unix epoch to sync slave local RTC clocks for schedule execution. |
| **`CMD`** | Master $\rightarrow$ Slave | `RESET_PORTAL` | `TO:N01:FROM:M:CMD:RESET_PORTAL` | Forces slave node into Wi-Fi Captive Portal mode for network reconfiguration. |
| **`ACK`** | Slave $\rightarrow$ Master | `<ResponseText>` | `TO:M:FROM:N01:ACK:BOUND_OK` | Acknowledges successful execution of a configuration or bind operation. |

---

### Decoupled Peripheral Component Types (`type`)
* `0`: `COMP_UNUSED`
* `1`: `COMP_RELAY` (Binary actuator, lights, pumps, motorized valves)
* `2`: `COMP_BUTTON` (Momentary tactile push button, active-low with internal pullup)
* `3`: `COMP_TOUCH` (Capacitive touch switch, active-high)
* `4`: `COMP_TOGGLE_SWITCH` (Edge-triggered two-way wall rocker switch: triggers on **any mechanical flip**)
* `5`: `COMP_ULTRASONIC` (HC-SR04 ultrasonic sensor: `pin1` = Trig, `pin2` = Echo, `param1` = tank depth in cm)
* `6`: `COMP_DHT` (DHT11 / DHT22 temperature & humidity probe: `pin1` = Data)
* `7`: `COMP_ADC` (Analog-to-digital converter input: `pin1` = ADC GPIO)

### Local Link Actions (`act`)
* `0`: `LINK_NONE`
* `1`: `LINK_TOGGLE` (Invert current output state)
* `2`: `LINK_TURN_ON` (Force output energized)
* `3`: `LINK_TURN_OFF` (Force output de-energized)

---

## 2. Master Hub REST API Specification

The Master Supervisor runs a standalone embedded HTTP server on port 80 with role-based access control (`admin`, `member`, `guest`):

| Endpoint | Method | Role | Description |
| :--- | :--- | :--- | :--- |
| `/api/login` | `POST` | Public | Authenticates username & password, returns session cookie + bearer token. |
| `/api/logout` | `POST` | Public | Invalidates session and clears credentials. |
| `/api/session` | `GET` | Public | Returns current user session identity and authorization level. |
| `/api/system` | `GET` | Guest+ | Real-time supervisor health (RAM, LittleFS partition, uptime, chip, port diagnostics). |
| `/api/state` | `GET` | Guest+ | Live entity states, telemetry, and online health of all registered slaves. |
| `/api/control` | `POST` | Member+ | Immediate manual control of any actuator (`target`, `comp`, `val`). |
| `/api/nodes` | `GET` | Member+ | Retrieves declarative node configuration registry from LittleFS (`nodes.json`). |
| `/api/pending` | `GET` | Admin | Real-time list of discovered uncommissioned slaves on RS-422 and Wi-Fi mesh. |
| `/api/bind` | `POST` | Admin | Binds an unprovisioned slave MAC to a permanent Node ID and optional SoftAP repeater. |
| `/api/nodes/components` | `POST` | Admin | Configures decoupled peripheral entities on a slave node. |
| `/api/nodes/links` | `POST` | Admin | Configures zero-latency direct hardware links on a slave node. |
| `/api/nodes/ap` | `POST` | Admin | Configures downstream Wi-Fi SoftAP repeater parameters. |
| `/api/nodes/schedules` | `POST` | Admin | Pushes standalone 8-slot daily schedules into slave EEPROM. |
| `/api/nodes/delete` | `POST` | Admin | Deletes and unbinds a hardware node from the system. |
| `/api/rules` | `GET` / `POST` | Admin | Reads or writes dynamic automation rules (`rules.json`). |
| `/api/notifications` | `GET` / `POST` | Admin | Reads or writes independent sensor threshold alerts (`notifications.json`). |
| `/api/alerts` | `GET` / `DELETE`| Admin | Hub alert log buffer (reads or flushes recent system alerts). |
| `/api/time` | `POST` | Public | Browser clock synchronization endpoint (syncs Unix epoch without NTP/Internet). |

---

## 3. Cloud & Local MQTT Protocol

All cloud communication via EMQX Serverless (or local Mosquitto broker) uses topics namespaced under the unique `home_id`.

**Base Topic Structure**: `miniha/<home_id>/<channel>`

### Topic 1: `miniha/<home_id>/status`
* **Purpose**: Real-time Master Hub connection status.
* **QoS**: 1, **Retained**: `true`
* **Payload (Birth / Online)**: `{"online": true}`
* **Payload (Last Will & Testament / Offline)**: `{"online": false}`

### Topic 2: `miniha/<home_id>/schema`
* **Purpose**: Declarative node and component hierarchy. Used by the PWA to dynamically render UI without hardcoded configurations.
* **QoS**: 1, **Retained**: `true`

### Topic 3: `miniha/<home_id>/state`
* **Purpose**: Live telemetry broadcasts (every 3 seconds or immediately on physical state change).
* **QoS**: 0
* **Payload Structure**:
  ```json
  {
    "N01": {
      "components": {
        "relay1": { "v1": 1 },
        "tank": { "v1": 142, "v2": 71 },
        "climate": { "v1": 27.4, "v2": 62 }
      },
      "lastSeen": 1,
      "freeHeap": 256000
    }
  }
  ```

### Topic 4: `miniha/<home_id>/set`
* **Purpose**: Command dispatch from PWA to toggle actuators. Guarded by session token.
* **QoS**: 1
* **Payload Structure**:
  ```json
  {
    "target": "N01",
    "comp": "relay1",
    "val": 1,
    "token": "3a8f9024cde..."
  }
  ```

### Topic 5: `miniha/<home_id>/auth/login` & `auth/reply/<clientId>`
* **Purpose**: Isolated remote user login and session token distribution.
* **Request (`.../auth/login`)**:
  ```json
  {
    "client": "pwa_9a2b41",
    "user": "admin",
    "pass": "admin123"
  }
  ```
* **Reply (`.../auth/reply/pwa_9a2b41`)** (Targeted exclusively to the requesting client):
  ```json
  {
    "status": "ok",
    "token": "4f9a0c71...",
    "user": "admin",
    "role": "admin"
  }
  ```

### Topic 6: `miniha/<home_id>/notify`
* **Purpose**: Real-time push notifications from Master Hub notification rules (e.g. Tank Overflow, Critical Temperature).
* **QoS**: 1
* **Payload Structure**:
  ```json
  {
    "title": "Water Tank Warning",
    "msg": "Overhead water tank reached 95%. Pump disabled.",
    "level": "warning"
  }
  ```
