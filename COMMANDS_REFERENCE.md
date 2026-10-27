# Mini-HA Protocol & Commands Reference

This document provides a comprehensive specification of all communication protocols, command verbs, payload combinations, and MQTT topics used throughout the **Mini-HA** ecosystem.

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
| **`REQ`** | Master $\rightarrow$ Slave | `POLL` | `TO:N01:FROM:M:REQ:POLL` | Requests instant telemetry & state report from the slave node. |
| **`REP`** | Slave $\rightarrow$ Master | `LVL:<dist>:TMP:<t>:HUM:<h>:OUT:<s0>:<s1>...` | `TO:M:FROM:N01:REP:LVL:145:TMP:28.4:HUM:62.1:OUT:1:0:0:0` | Telemetry response with distance (cm), DHT temp (°C), humidity (%), and output slot bit states. |
| **`SET`** | Master $\rightarrow$ Slave | `SLOT:<slot>:STATE:<0\|1>` | `TO:N01:FROM:M:SET:SLOT:0:STATE:1` | Drives output slot immediately (e.g. Turn ON Relay at Slot 0). |
| **`BIND`** | Master $\rightarrow$ Slave | `MAC:<mac>:SET_ID:<newNodeId>` | `TO:NEW:FROM:M:BIND:MAC:48:55:19:CA:3F:10:SET_ID:N02` | Matches hardware MAC and permanently assigns Node ID into slave flash memory. |
| **`CFG`** | Master $\rightarrow$ Slave | `SLOT:<slot>:GPIO:<pin>:TYPE:<t>:INV:<0\|1>` | `TO:N01:FROM:M:CFG:SLOT:0:GPIO:2:TYPE:1:INV:1` | Dynamically binds physical GPIO to virtual slot (`TYPE:1` = Relay, `INV:1` = Active Low). |
| **`CFG`** | Master $\rightarrow$ Slave | `LINK:<idx>:TRIG:<slot>:TGT:<slot>:ACT:<act>` | `TO:N01:FROM:M:CFG:LINK:0:TRIG:4:TGT:0:ACT:1` | Programs **sub-millisecond instant hardware link** (e.g. Touch Slot 4 triggers Relay Slot 0 Toggle). |
| **`CFG`** | Master $\rightarrow$ Slave | `SCHED:<idx>:<en>:<tgt>:<act>:<onH>:<onM>:<offH>:<offM>` | `TO:N01:FROM:M:CFG:SCHED:0:1:0:1:06:00:18:30` | Stores standalone clock timer directly in slave EEPROM (works even if Master is offline). |
| **`TIME`**| Master $\rightarrow$ Slave | `<unix_epoch>` | `TO:ALL:FROM:M:TIME:1730000000` | Broadcasts real-time Unix epoch to sync slave local RTC clocks for schedule execution. |
| **`CMD`** | Master $\rightarrow$ Slave | `RESET_PORTAL` | `TO:N01:FROM:M:CMD:RESET_PORTAL` | Forces slave node into Wi-Fi Captive Portal mode for reconfiguration. |
| **`ACK`** | Slave $\rightarrow$ Master | `<ResponseText>` | `TO:M:FROM:N01:ACK:SLOT_CONFIGURED:0` | Acknowledges successful execution of a configuration or bind operation. |

#### Virtual Slot Types (`TYPE:<t>`)
* `0`: `SLOT_UNUSED`
* `1`: `SLOT_OUTPUT_RELAY` (Binary actuator, lights, pumps, valves)
* `2`: `SLOT_INPUT_TOUCH` (Capacitive touch switch e.g. TTP224)
* `3`: `SLOT_INPUT_BUTTON` (Push button with internal pull-up)
* `4`: `SLOT_SENSOR_ULTRASONIC_TRIG` (Ultrasonic trigger pulse)
* `5`: `SLOT_SENSOR_ULTRASONIC_ECHO` (Ultrasonic echo duration)
* `6`: `SLOT_SENSOR_DHT11` (Temp/Humidity)
* `7`: `SLOT_SENSOR_DHT22` (High-accuracy Temp/Humidity)
* `8`: `SLOT_SENSOR_DS18B20` (OneWire waterproof probe)
* `9`: `SLOT_ANALOG_IN` (ADC pressure / analog level)

#### Local Link Actions (`ACT:<act>`)
* `0`: `LINK_NONE`
* `1`: `LINK_TOGGLE` (Toggle current state)
* `2`: `LINK_TURN_ON` (Force output HIGH)
* `3`: `LINK_TURN_OFF` (Force output LOW)

---

## 2. Cloud & Local MQTT Protocol

All cloud communication via EMQX Serverless (or local Mosquitto broker) uses topics namespaced under the unique `home_id`.

**Base Topic Structure**: `miniha/<home_id>/<channel>`

---

### Topic 1: `miniha/<home_id>/status`
* **Purpose**: Real-time Master Hub connection status.
* **QoS**: 1
* **Retained**: `true`
* **Paylod (Online - Birth Message)**:
  ```json
  {"online": true}
  ```
* **Payload (Offline - Last Will & Testament)**:
  ```json
  {"online": false}
  ```

---

### Topic 2: `miniha/<home_id>/schema`
* **Purpose**: Declarative room and node hierarchy. Used by PWA to dynamically build UI controls without hardcoding.
* **QoS**: 1
* **Retained**: `true`
* **Payload Structure**:
  ```json
  {
    "homeId": "home_yum",
    "nodes": [
      {
        "id": "node_1",
        "name": "Living Room Switchboard",
        "slots": [
          {"slot": 1, "name": "Ceiling Light", "type": 1},
          {"slot": 2, "name": "Fan", "type": 1},
          {"slot": 3, "name": "Room Temp", "type": 6}
        ]
      }
    ]
  }
  ```

---

### Topic 3: `miniha/<home_id>/state`
* **Purpose**: Live telemetry broadcasts (every 3 seconds or immediately on physical pin change).
* **QoS**: 0
* **Payload Structure**:
  ```json
  {
    "node_1": {
      "relays": [1, 0, 0, 0],
      "temp": 27.5,
      "hum": 64.0,
      "distance": 132
    }
  }
  ```

---

### Topic 4: `miniha/<home_id>/set`
* **Purpose**: Command dispatch from PWA to toggle relays. Cryptographically guarded by session token.
* **QoS**: 1
* **Payload Structure**:
  ```json
  {
    "target": "node_1",
    "slot": 1,
    "state": 1,
    "token": "3a8f9024cde..."
  }
  ```

---

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

---

### Topic 6: `miniha/<home_id>/notify`
* **Purpose**: Real-time push notifications from Master Hub automation rules (e.g. Tank Full, High Temperature Alert).
* **QoS**: 1
* **Payload Structure**:
  ```json
  {
    "title": "Water Tank Alert",
    "msg": "Overhead tank reached 95%. Pump turned OFF automatically."
  }
  ```
