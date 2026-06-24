#include "UsbFidoHid.h"

#include <USB.h>
#include <USBHID.h>
#include <class/hid/hid_device.h>
#include <string.h>

#include "Diagnostics.h"

#ifndef ARDUINO_USB_MODE
#error This firmware requires an ESP32-S3 native USB board.
#elif ARDUINO_USB_MODE == 1
#error Use USB-OTG TinyUSB mode, not Hardware CDC/JTAG mode, for the FIDO HID profile.
#endif

static USBHID hid;

static const uint8_t fidoReportDescriptor[] = {TUD_HID_REPORT_DESC_FIDO_U2F(BuildConfig::kHidReportSize)};

struct QueuedReport {
  uint8_t data[BuildConfig::kHidReportSize];
};

class FidoHidDevice final : public USBHIDDevice {
 public:
  FidoHidDevice() {
    static bool added = false;
    if (!added) {
      added = true;
      hid.addDevice(this, sizeof(fidoReportDescriptor));
    }
  }

  void setCtap(CtapHid *ctap) {
    ctap_ = ctap;
  }

  void begin() {
    hid.begin();
  }

  uint16_t _onGetDescriptor(uint8_t *buffer) override {
    memcpy(buffer, fidoReportDescriptor, sizeof(fidoReportDescriptor));
    return sizeof(fidoReportDescriptor);
  }

  void _onOutput(uint8_t report_id, const uint8_t *buffer, uint16_t len) override {
    (void)report_id;
    if (!ctap_ || len != BuildConfig::kHidReportSize) {
      return;
    }
    QueuedReport report;
    memcpy(report.data, buffer, BuildConfig::kHidReportSize);
    const size_t next = (writeIndex_ + 1) % kQueueDepth;
    if (next == readIndex_) {
      dropped_++;
      return;
    }
    queue_[writeIndex_] = report;
    writeIndex_ = next;
  }

  void poll() {
    while (readIndex_ != writeIndex_) {
      QueuedReport report = queue_[readIndex_];
      readIndex_ = (readIndex_ + 1) % kQueueDepth;
      ctap_->receivePacket(report.data);
    }
  }

 private:
  static constexpr size_t kQueueDepth = 8;
  CtapHid *ctap_ = nullptr;
  volatile size_t readIndex_ = 0;
  volatile size_t writeIndex_ = 0;
  volatile uint32_t dropped_ = 0;
  QueuedReport queue_[kQueueDepth];
};

static FidoHidDevice fidoDevice;

UsbFidoHid::UsbFidoHid(CtapHid &ctap) : ctap_(ctap) {}

void UsbFidoHid::begin() {
  fidoDevice.setCtap(&ctap_);
  ctap_.begin(sendThunk, this);
  fidoDevice.begin();
  if (BuildConfig::kOverrideUsbIdentity) {
    USB.VID(BuildConfig::kUsbVid);
    USB.PID(BuildConfig::kUsbPid);
  }
  USB.manufacturerName(BuildConfig::kManufacturer);
  USB.productName(BuildConfig::kDeviceName);
  USB.begin();
  Diagnostics::log("USB FIDO HID started");
}

void UsbFidoHid::poll() {
  fidoDevice.poll();
}

bool UsbFidoHid::sendPacket(const uint8_t packet[BuildConfig::kHidReportSize]) {
  if (!hid.ready()) {
    return false;
  }
  return hid.SendReport(0, packet, BuildConfig::kHidReportSize, 100);
}

bool UsbFidoHid::sendThunk(void *ctx, const uint8_t packet[BuildConfig::kHidReportSize]) {
  return static_cast<UsbFidoHid *>(ctx)->sendPacket(packet);
}
