#pragma once
#include <SuplaDevice.h>

// ==========================================
// OPTIONAL SUPLA CLOUD BRIDGE CONFIGURATION
// ==========================================
// To enable mobile remote access via the official Supla app:
// 1. Create a free account at https://cloud.supla.org
// 2. Note your assigned server address (e.g., "svr12.supla.org") and account email.
// 3. Generate a 16-byte GUID & AUTHKEY at https://www.supla.org/arduino/get-guid-and-authkey/
// 4. In cloud.supla.org, turn ON "Device registration ACTIVE" before booting the board.

#define SUPLA_SERVER  "svrX.supla.org"          // e.g. "svr12.supla.org"
#define SUPLA_EMAIL   "your_email@example.com"  // Your Supla account email

// 16-byte Unique Hardware Fingerprint
const char SUPLA_GUID[SUPLA_GUID_SIZE] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// 16-byte Device Authorization Key
const char SUPLA_AUTHKEY[SUPLA_AUTHKEY_SIZE] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
