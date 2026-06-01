#pragma once

#include <Arduino.h>

#include "AmoledUx.h"
#include "BuildConfig.h"
#include "Ctap2.h"
#include "LabRecorder.h"

class CtapHid {
 public:
  using SendPacketCallback = bool (*)(void *ctx, const uint8_t packet[BuildConfig::kHidReportSize]);

  CtapHid(Ctap2 &ctap2, AmoledUx &ux, LabRecorder &recorder);

  void begin(SendPacketCallback sender, void *senderCtx);
  void receivePacket(const uint8_t packet[BuildConfig::kHidReportSize]);
  void sendKeepalive(uint8_t status);

 private:
  static void keepaliveThunk(void *ctx, uint8_t status);

  void resetRx();
  void handleInitPacket(const uint8_t packet[BuildConfig::kHidReportSize]);
  void handleContinuationPacket(const uint8_t packet[BuildConfig::kHidReportSize]);
  void dispatchMessage();
  void sendMessage(uint32_t cid, uint8_t cmd, const uint8_t *payload, size_t payloadLen);
  void sendError(uint32_t cid, uint8_t error);
  static uint32_t readCid(const uint8_t *packet);
  static void writeCid(uint8_t *packet, uint32_t cid);
  void recordEvent(const char *kind, const char *cmd, const char *status, const char *note = "");

  Ctap2 &ctap2_;
  AmoledUx &ux_;
  LabRecorder &recorder_;
  SendPacketCallback sender_ = nullptr;
  void *senderCtx_ = nullptr;
  uint32_t activeCid_ = 0;
  uint32_t rxCid_ = 0;
  uint8_t rxCmd_ = 0;
  uint16_t rxExpected_ = 0;
  uint16_t rxLen_ = 0;
  uint8_t nextSeq_ = 0;
  uint8_t rxBuffer_[BuildConfig::kMaxCtapMessageSize];
  uint8_t txBuffer_[BuildConfig::kMaxCtapMessageSize];
};
