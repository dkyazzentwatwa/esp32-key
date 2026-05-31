#include "CborCodec.h"

#include <string.h>

CborWriter::CborWriter(uint8_t *buffer, size_t capacity) : buffer_(buffer), capacity_(capacity) {}

bool CborWriter::ok() const {
  return ok_;
}

size_t CborWriter::size() const {
  return offset_;
}

bool CborWriter::writeByte(uint8_t value) {
  if (!ok_ || offset_ >= capacity_) {
    ok_ = false;
    return false;
  }
  buffer_[offset_++] = value;
  return true;
}

bool CborWriter::writeRaw(const uint8_t *data, size_t len) {
  if (!ok_ || len > capacity_ - offset_) {
    ok_ = false;
    return false;
  }
  memcpy(buffer_ + offset_, data, len);
  offset_ += len;
  return true;
}

bool CborWriter::writeType(uint8_t major, uint64_t value) {
  if (value < 24) {
    return writeByte((major << 5) | static_cast<uint8_t>(value));
  }
  if (value <= 0xff) {
    return writeByte((major << 5) | 24) && writeByte(static_cast<uint8_t>(value));
  }
  if (value <= 0xffff) {
    return writeByte((major << 5) | 25) && writeByte(value >> 8) && writeByte(value);
  }
  if (value <= 0xffffffffULL) {
    return writeByte((major << 5) | 26) && writeByte(value >> 24) && writeByte(value >> 16) && writeByte(value >> 8) && writeByte(value);
  }
  ok_ = false;
  return false;
}

bool CborWriter::writeUInt(uint64_t value) {
  return writeType(0, value);
}

bool CborWriter::writeNint(int64_t value) {
  if (value >= 0) {
    ok_ = false;
    return false;
  }
  return writeType(1, static_cast<uint64_t>(-1 - value));
}

bool CborWriter::writeInt(int64_t value) {
  return value >= 0 ? writeUInt(value) : writeNint(value);
}

bool CborWriter::writeBytes(const uint8_t *data, size_t len) {
  return writeType(2, len) && writeRaw(data, len);
}

bool CborWriter::writeText(const char *text) {
  return writeText(text, strlen(text));
}

bool CborWriter::writeText(const char *text, size_t len) {
  return writeType(3, len) && writeRaw(reinterpret_cast<const uint8_t *>(text), len);
}

bool CborWriter::writeArray(size_t count) {
  return writeType(4, count);
}

bool CborWriter::writeMap(size_t count) {
  return writeType(5, count);
}

bool CborWriter::writeBool(bool value) {
  return writeByte(value ? 0xf5 : 0xf4);
}

bool CborWriter::writeNull() {
  return writeByte(0xf6);
}

CborReader::CborReader(const uint8_t *buffer, size_t len) : buffer_(buffer), len_(len) {}

size_t CborReader::remaining() const {
  return len_ - offset_;
}

bool CborReader::consume(size_t count) {
  if (count > remaining()) {
    return false;
  }
  offset_ += count;
  return true;
}

bool CborReader::readLength(uint8_t addl, uint64_t &value) {
  if (addl < 24) {
    value = addl;
    return true;
  }
  if (addl == 24) {
    if (remaining() < 1) return false;
    value = buffer_[offset_++];
    return true;
  }
  if (addl == 25) {
    if (remaining() < 2) return false;
    value = (static_cast<uint16_t>(buffer_[offset_]) << 8) | buffer_[offset_ + 1];
    offset_ += 2;
    return true;
  }
  if (addl == 26) {
    if (remaining() < 4) return false;
    value = (static_cast<uint32_t>(buffer_[offset_]) << 24) | (static_cast<uint32_t>(buffer_[offset_ + 1]) << 16) |
            (static_cast<uint32_t>(buffer_[offset_ + 2]) << 8) | buffer_[offset_ + 3];
    offset_ += 4;
    return true;
  }
  return false;
}

bool CborReader::readHeader(uint8_t &major, uint64_t &value) {
  if (remaining() < 1) {
    return false;
  }
  const uint8_t initial = buffer_[offset_++];
  major = initial >> 5;
  return readLength(initial & 0x1f, value);
}

bool CborReader::readMap(size_t &count) {
  uint8_t major;
  uint64_t value;
  if (!readHeader(major, value) || major != 5 || value > 64) return false;
  count = value;
  return true;
}

bool CborReader::readArray(size_t &count) {
  uint8_t major;
  uint64_t value;
  if (!readHeader(major, value) || major != 4 || value > 64) return false;
  count = value;
  return true;
}

bool CborReader::readUInt(uint64_t &value) {
  uint8_t major;
  if (!readHeader(major, value) || major != 0) return false;
  return true;
}

bool CborReader::readInt(int64_t &value) {
  uint8_t major;
  uint64_t raw;
  if (!readHeader(major, raw)) return false;
  if (major == 0) {
    value = raw;
    return true;
  }
  if (major == 1) {
    value = -1 - static_cast<int64_t>(raw);
    return true;
  }
  return false;
}

bool CborReader::readBytes(const uint8_t *&data, size_t &len) {
  uint8_t major;
  uint64_t value;
  if (!readHeader(major, value) || major != 2 || value > remaining()) return false;
  data = buffer_ + offset_;
  len = value;
  offset_ += len;
  return true;
}

bool CborReader::readTextView(const uint8_t *&data, size_t &len) {
  uint8_t major;
  uint64_t value;
  if (!readHeader(major, value) || major != 3 || value > remaining()) return false;
  data = buffer_ + offset_;
  len = value;
  offset_ += len;
  return true;
}

bool CborReader::readText(char *out, size_t outSize) {
  const uint8_t *data;
  size_t len;
  if (!readTextView(data, len) || len >= outSize) return false;
  memcpy(out, data, len);
  out[len] = 0;
  return true;
}

bool CborReader::readBool(bool &value) {
  if (remaining() < 1) return false;
  const uint8_t raw = buffer_[offset_++];
  if (raw == 0xf4) {
    value = false;
    return true;
  }
  if (raw == 0xf5) {
    value = true;
    return true;
  }
  return false;
}

bool CborReader::skip() {
  uint8_t major;
  uint64_t value;
  const size_t start = offset_;
  if (!readHeader(major, value)) {
    offset_ = start;
    if (remaining() >= 1) {
      const uint8_t simple = buffer_[offset_++];
      return simple == 0xf4 || simple == 0xf5 || simple == 0xf6;
    }
    return false;
  }
  if (major == 0 || major == 1 || major == 7) return true;
  if (major == 2 || major == 3) return consume(value);
  if (major == 4) {
    for (uint64_t i = 0; i < value; ++i) {
      if (!skip()) return false;
    }
    return true;
  }
  if (major == 5) {
    for (uint64_t i = 0; i < value * 2; ++i) {
      if (!skip()) return false;
    }
    return true;
  }
  return false;
}
