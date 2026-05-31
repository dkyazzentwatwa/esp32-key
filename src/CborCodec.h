#pragma once

#include <Arduino.h>

class CborWriter {
 public:
  CborWriter(uint8_t *buffer, size_t capacity);

  bool ok() const;
  size_t size() const;
  bool writeUInt(uint64_t value);
  bool writeNint(int64_t value);
  bool writeInt(int64_t value);
  bool writeBytes(const uint8_t *data, size_t len);
  bool writeText(const char *text);
  bool writeText(const char *text, size_t len);
  bool writeArray(size_t count);
  bool writeMap(size_t count);
  bool writeBool(bool value);
  bool writeNull();

 private:
  bool writeType(uint8_t major, uint64_t value);
  bool writeByte(uint8_t value);
  bool writeRaw(const uint8_t *data, size_t len);

  uint8_t *buffer_;
  size_t capacity_;
  size_t offset_ = 0;
  bool ok_ = true;
};

class CborReader {
 public:
  CborReader(const uint8_t *buffer, size_t len);

  bool readMap(size_t &count);
  bool readArray(size_t &count);
  bool readUInt(uint64_t &value);
  bool readInt(int64_t &value);
  bool readBytes(const uint8_t *&data, size_t &len);
  bool readText(char *out, size_t outSize);
  bool readTextView(const uint8_t *&data, size_t &len);
  bool readBool(bool &value);
  bool skip();
  size_t remaining() const;

 private:
  bool readHeader(uint8_t &major, uint64_t &value);
  bool readLength(uint8_t addl, uint64_t &value);
  bool consume(size_t count);

  const uint8_t *buffer_;
  size_t len_;
  size_t offset_ = 0;
};
