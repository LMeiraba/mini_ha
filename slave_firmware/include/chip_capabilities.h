#pragma once
#include <Arduino.h>

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #define CURRENT_CHIP MODEL_ESP8266
  #define CHIP_NAME_STR "ESP8266"
  #define BOOT_BUTTON_PIN 0  // D3 / FLASH button
  // Usable GPIOs on ESP8266: D3(0), D4(2), D2(4), D1(5), D6(12), D7(13), D5(14), D8(15), D0(16)
  const uint8_t SAFE_GPIOS[] = {0, 2, 4, 5, 12, 13, 14, 15, 16};
  const uint8_t NUM_SAFE_GPIOS = 9;
  const char* SAFE_GPIOS_CSV = "0,2,4,5,12,13,14,15,16";

#elif defined(CONFIG_IDF_TARGET_ESP32C3) || defined(ESP32C3)
  #include <WiFi.h>
  #define CURRENT_CHIP MODEL_ESP32C3
  #define CHIP_NAME_STR "ESP32C3"
  #define BOOT_BUTTON_PIN 9  // Onboard BOOT button
  // Usable GPIOs on ESP32-C3: ADC/IO 0,1,3,4,5,6,7, IO 8,10, secondary UART/IO 20,21
  const uint8_t SAFE_GPIOS[] = {0, 1, 3, 4, 5, 6, 7, 8, 10, 20, 21};
  const uint8_t NUM_SAFE_GPIOS = 11;
  const char* SAFE_GPIOS_CSV = "0,1,3,4,5,6,7,8,10,20,21";

#elif defined(ESP32)
  #include <WiFi.h>
  #define CURRENT_CHIP MODEL_ESP32
  #define CHIP_NAME_STR "ESP32"
  #define BOOT_BUTTON_PIN 0  // Onboard BOOT button
  // Usable GPIOs on ESP32 DevKit: Bidirectional IO + Input-only ADC (34,35,36,39)
  const uint8_t SAFE_GPIOS[] = {4, 5, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33, 34, 35, 36, 39};
  const uint8_t NUM_SAFE_GPIOS = 22;
  const char* SAFE_GPIOS_CSV = "4,5,12,13,14,15,16,17,18,19,21,22,23,25,26,27,32,33,34,35,36,39";

#else
  #define CURRENT_CHIP MODEL_UNKNOWN
  #define CHIP_NAME_STR "UNKNOWN"
  #define BOOT_BUTTON_PIN 255
  const uint8_t SAFE_GPIOS[] = {};
  const uint8_t NUM_SAFE_GPIOS = 0;
  const char* SAFE_GPIOS_CSV = "";
#endif

inline bool isBootButtonPressed() {
#if defined(BOOT_BUTTON_PIN) && (BOOT_BUTTON_PIN != 255)
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  return (digitalRead(BOOT_BUTTON_PIN) == LOW);
#else
  return false;
#endif
}

inline String getDeviceMacAddress() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char buf[16];
  snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

inline bool isSafeGpio(uint8_t pin) {
  for (uint8_t i = 0; i < NUM_SAFE_GPIOS; i++) {
    if (SAFE_GPIOS[i] == pin) return true;
  }
  return false;
}
