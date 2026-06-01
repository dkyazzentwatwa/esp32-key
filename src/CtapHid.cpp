#include "CtapHid.h"

#include <string.h>

#include "Diagnostics.h"

static constexpr uint32_t kBroadcastCid = 0xffffffffUL;
static constexpr uint8_t kCmdPing = 0x01;
static constexpr uint8_t kCmdMsg = 0x03;
static constexpr uint8_t kCmdInit = 0x06;
static constexpr uint8_t kCmdWink = 0x08;
static constexpr uint8_t kCmdCbor = 0x10;
static constexpr uint8_t kCmdCancel = 0x11;
static constexpr uint8_t kCmdKeepalive = 0x3b;
static constexpr uint8_t kCmdError = 0x3f;

static constexpr uint8_t kCapCbor = 0x04;
static constexpr uint8_t kCapNoMsg = 0x08;

static constexpr uint8_t kErrInvalidCmd = 0x01;
static constexpr uint8_t kErrInvalidPar = 0x02;
static constexpr uint8_t kErrInvalidLen = 0x03;
static constexpr uint8_t kErrInvalidSeq = 0x04;
static constexpr uint8_t kErrMsgTimeout = 0x05;
static constexpr uint8_t kErrChannelBusy = 0x06;
static constexpr uint8_t kErrInvalidCid = 0x0b;

CtapHid::CtapHid(Ctap2 &ctap2, AmoledUx &ux, LabRecorder &recorder)
    : ctap2_(ctap2), ux_(ux), recorder_(recorder) {}

void CtapHid::recordEvent(const char *kind, const char *cmd, const char *status, const char *note) {
  LabRecorder::Event event{};
  event.kind = kind;
  event.cmd = cmd;
  event.status = status;
  event.note = note;
  recorder_.record(event);
  ux_.recorderStatus(recorder_.statusLine(), recorder_.lastSummary());
}

void CtapHid::begin(SendPacketCallback sender, void *senderCtx) {
  sender_ = sender;
  senderCtx_ = senderCtx;
  ctap2_.setKeepaliveCallback(keepaliveThunk, this);
  resetRx();
}

uint32_t CtapHid::readCid(const uint8_t *packet) {
  return (static_cast<uint32_t>(packet[0]) << 24) | (static_cast<uint32_t>(packet[1]) << 16) |
         (static_cast<uint32_t>(packet[2]) << 8) | packet[3];
}

void CtapHid::writeCid(uint8_t *packet, uint32_t cid) {
  packet[0] = (cid >> 24) & 0xff;
  packet[1] = (cid >> 16) & 0xff;
  packet[2] = (cid >> 8) & 0xff;
  packet[3] = cid & 0xff;
}

void CtapHid::resetRx() {
  rxCid_ = 0;
  rxCmd_ = 0;
  rxExpected_ = 0;
  rxLen_ = 0;
  nextSeq_ = 0;
}

void CtapHid::receivePacket(const uint8_t packet[BuildConfig::kHidReportSize]) {
  if (packet[4] & 0x80) {
    handleInitPacket(packet);
  } else {
    handleContinuationPacket(packet);
  }
}

void CtapHid::handleInitPacket(const uint8_t packet[BuildConfig::kHidReportSize]) {
  const uint32_t cid = readCid(packet);
  const uint8_t cmd = packet[4] & 0x7f;
  const uint16_t len = (static_cast<uint16_t>(packet[5]) << 8) | packet[6];

  if (cid == 0) {
    ux_.diagnosticError("HID error", "Invalid CID", "cid=0");
    recordEvent("error", "ctaphid", "invalid-cid 0x0b", "cid=0");
    sendError(kBroadcastCid, kErrInvalidCid);
    return;
  }
  if (rxLen_ != 0 && rxLen_ < rxExpected_ && cid != rxCid_) {
    ux_.diagnosticError("HID error", "Channel busy", "while receiving");
    recordEvent("error", "ctaphid", "channel-busy 0x06", "while receiving");
    sendError(cid, kErrChannelBusy);
    return;
  }
  if (len > BuildConfig::kMaxCtapMessageSize) {
    ux_.diagnosticError("HID error", "Invalid length", "message too large");
    recordEvent("error", "ctaphid", "invalid-length 0x03", "message too large");
    sendError(cid, kErrInvalidLen);
    resetRx();
    return;
  }

  rxCid_ = cid;
  rxCmd_ = cmd;
  rxExpected_ = len;
  rxLen_ = min<uint16_t>(len, 57);
  memcpy(rxBuffer_, packet + 7, rxLen_);
  nextSeq_ = 0;

  if (rxLen_ >= rxExpected_) {
    dispatchMessage();
    resetRx();
  }
}

void CtapHid::handleContinuationPacket(const uint8_t packet[BuildConfig::kHidReportSize]) {
  const uint32_t cid = readCid(packet);
  const uint8_t seq = packet[4] & 0x7f;
  if (rxLen_ == 0 || cid != rxCid_) {
    ux_.diagnosticError("HID error", "Invalid sequence", "unexpected cont");
    recordEvent("error", "ctaphid", "invalid-seq 0x04", "unexpected continuation");
    sendError(cid, kErrInvalidSeq);
    resetRx();
    return;
  }
  if (seq != nextSeq_) {
    ux_.diagnosticError("HID error", "Invalid sequence", "sequence mismatch");
    recordEvent("error", "ctaphid", "invalid-seq 0x04", "sequence mismatch");
    sendError(cid, kErrInvalidSeq);
    resetRx();
    return;
  }
  const uint16_t remaining = rxExpected_ - rxLen_;
  const uint16_t copyLen = min<uint16_t>(remaining, 59);
  memcpy(rxBuffer_ + rxLen_, packet + 5, copyLen);
  rxLen_ += copyLen;
  nextSeq_++;
  if (rxLen_ >= rxExpected_) {
    dispatchMessage();
    resetRx();
  }
}

void CtapHid::dispatchMessage() {
  switch (rxCmd_) {
    case kCmdInit: {
      if (rxExpected_ != 8) {
        ux_.diagnosticError("HID INIT", "Invalid length", "expected 8");
        recordEvent("error", "ctaphidInit", "invalid-length 0x03", "expected nonce");
        sendError(rxCid_, kErrInvalidLen);
        return;
      }
      ux_.diagnostic("HID INIT", "Host allocated CID", "FIDO channel ready");
      recordEvent("trace", "ctaphidInit", "ok 0x00", "host allocated CID");
      uint8_t response[17];
      memcpy(response, rxBuffer_, 8);
      activeCid_ = 0xface0001UL;
      response[8] = (activeCid_ >> 24) & 0xff;
      response[9] = (activeCid_ >> 16) & 0xff;
      response[10] = (activeCid_ >> 8) & 0xff;
      response[11] = activeCid_ & 0xff;
      response[12] = 2;  // CTAPHID protocol version.
      response[13] = BuildConfig::kVersionMajor;
      response[14] = BuildConfig::kVersionMinor;
      response[15] = BuildConfig::kVersionBuild;
      response[16] = kCapCbor | kCapNoMsg;  // Prefer CTAP2/CBOR; do not advertise U2F MSG.
      sendMessage(rxCid_, kCmdInit, response, sizeof(response));
      break;
    }
    case kCmdPing:
      ux_.diagnostic("HID PING", "Host ping", "transport alive");
      recordEvent("trace", "ctaphidPing", "ok 0x00", "transport alive");
      sendMessage(rxCid_, kCmdPing, rxBuffer_, rxExpected_);
      break;
    case kCmdCbor: {
      if (rxCid_ != activeCid_) {
        ux_.diagnosticError("CBOR error", "Invalid CID", "host channel mismatch");
        recordEvent("error", "ctaphidCbor", "invalid-cid 0x0b", "host channel mismatch");
        sendError(rxCid_, kErrInvalidCid);
        return;
      }
      if (rxExpected_ == 0) {
        ux_.diagnosticError("CBOR error", "Invalid length", "empty command");
        recordEvent("error", "ctaphidCbor", "invalid-length 0x03", "empty command");
      } else if (rxBuffer_[0] == 0x01) {
        // Defer the screen to handleMakeCredential: it can tell a real RP from a
        // synthetic .dummy probe, which this transport layer cannot.
        Diagnostics::log("CBOR makeCredential (screen deferred to CTAP2)");
      } else if (rxBuffer_[0] == 0x02) {
        // Defer the screen to handleGetAssertion so a silent up=false pre-flight
        // or .dummy probe never repaints over an active real-RP prompt.
        Diagnostics::log("CBOR getAssertion (screen deferred to CTAP2)");
      } else if (rxBuffer_[0] == 0x04) {
        ux_.diagnostic("CBOR cmd 0x04", "getInfo", "browser probe");
      } else if (rxBuffer_[0] == 0x06) {
        ux_.diagnostic("CBOR cmd 0x06", "clientPin", "browser PIN");
      } else if (rxBuffer_[0] == 0x07) {
        ux_.diagnostic("CBOR cmd 0x07", "reset", "host request");
      } else if (rxBuffer_[0] == 0x08) {
        ux_.diagnostic("CBOR cmd 0x08", "getNextAssertion", "resident login");
      } else if (rxBuffer_[0] == 0x0a) {
        ux_.diagnostic("CBOR cmd 0x0A", "credMgmt", "resident admin");
      } else {
        char detail[24];
        snprintf(detail, sizeof(detail), "cmd=0x%02x", rxBuffer_[0]);
        ux_.diagnostic("CBOR command", detail, "unsupported?");
      }
      const size_t responseLen = ctap2_.handle(rxBuffer_, rxExpected_, txBuffer_, sizeof(txBuffer_));
      sendMessage(rxCid_, kCmdCbor, txBuffer_, responseLen);
      break;
    }
    case kCmdCancel:
      ux_.diagnostic("HID CANCEL", "Host canceled", "browser stopped");
      recordEvent("cancel", "ctaphidCancel", "canceled", "browser stopped");
      ctap2_.cancel();
      break;
    case kCmdWink:
      ux_.diagnostic("HID WINK", "Host wink", "ack");
      recordEvent("trace", "ctaphidWink", "ok 0x00", "host wink");
      sendMessage(rxCid_, kCmdWink, nullptr, 0);
      break;
    case kCmdMsg:
      ux_.diagnostic("HID MSG", "CTAP1/U2F", "legacy request");
      recordEvent("trace", "ctaphidMsg", "legacy", "CTAP1/U2F");
      sendMessage(rxCid_, kCmdMsg, txBuffer_, ctap2_.handleCtap1(rxBuffer_, rxExpected_, txBuffer_, sizeof(txBuffer_)));
      break;
    default:
      ux_.diagnosticError("HID error", "Invalid command", "unsupported HID cmd");
      recordEvent("error", "ctaphid", "invalid-command 0x01", "unsupported HID cmd");
      sendError(rxCid_, kErrInvalidCmd);
      break;
  }
}

void CtapHid::sendMessage(uint32_t cid, uint8_t cmd, const uint8_t *payload, size_t payloadLen) {
  if (!sender_ || payloadLen > BuildConfig::kMaxCtapMessageSize) return;
  uint8_t packet[BuildConfig::kHidReportSize] = {};
  writeCid(packet, cid);
  packet[4] = cmd | 0x80;
  packet[5] = (payloadLen >> 8) & 0xff;
  packet[6] = payloadLen & 0xff;
  size_t sent = min(payloadLen, static_cast<size_t>(57));
  if (sent && payload) memcpy(packet + 7, payload, sent);
  if (!sender_(senderCtx_, packet)) {
    ux_.diagnosticError("HID send", "Initial packet failed", "host did not accept");
    return;
  }

  uint8_t seq = 0;
  while (sent < payloadLen) {
    delay(2);
    memset(packet, 0, sizeof(packet));
    writeCid(packet, cid);
    packet[4] = seq++;
    const size_t chunk = min(payloadLen - sent, static_cast<size_t>(59));
    memcpy(packet + 5, payload + sent, chunk);
    if (!sender_(senderCtx_, packet)) {
      ux_.diagnosticError("HID send", "Continuation failed", "host did not accept");
      return;
    }
    sent += chunk;
  }
}

void CtapHid::sendError(uint32_t cid, uint8_t error) {
  uint8_t value = error;
  sendMessage(cid, kCmdError, &value, 1);
}

void CtapHid::sendKeepalive(uint8_t status) {
  if (activeCid_ == 0) return;
  sendMessage(activeCid_, kCmdKeepalive, &status, 1);
}

void CtapHid::keepaliveThunk(void *ctx, uint8_t status) {
  static_cast<CtapHid *>(ctx)->sendKeepalive(status);
}
