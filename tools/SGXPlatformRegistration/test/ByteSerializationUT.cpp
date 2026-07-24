/*
 * Copyright (C) 2026 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include <ByteSerialization.h>

using mp::parseBytesLE;
using mp::writeBytesLE;

// writeBytesLE must emit the least-significant byte first (little-endian),
// independent of the host's native byte order.
TEST(ByteSerializationUT, writeEmitsLittleEndianByteOrder)
{
  uint8_t buf[4] = {0, 0, 0, 0};

  writeBytesLE<uint32_t>(buf, 0x11223344u);

  EXPECT_EQ(buf[0], 0x44);
  EXPECT_EQ(buf[1], 0x33);
  EXPECT_EQ(buf[2], 0x22);
  EXPECT_EQ(buf[3], 0x11);
}

// parseBytesLE must read the least-significant byte first (little-endian).
TEST(ByteSerializationUT, parseReadsLittleEndianByteOrder)
{
  const uint8_t buf[4] = {0x44, 0x33, 0x22, 0x11};

  EXPECT_EQ(parseBytesLE<uint32_t>(buf), 0x11223344u);
}

// Writing then reading back the same offset/type must reproduce the value
// for representative widths.
TEST(ByteSerializationUT, roundTripsAcrossIntegralWidths)
{
  uint8_t buf[8] = {};

  writeBytesLE<uint8_t>(buf, static_cast<uint8_t>(0xA5));
  EXPECT_EQ(parseBytesLE<uint8_t>(buf), 0xA5);

  writeBytesLE<uint16_t>(buf, static_cast<uint16_t>(0xBEEF));
  EXPECT_EQ(parseBytesLE<uint16_t>(buf), 0xBEEF);

  writeBytesLE<uint32_t>(buf, 0xDEADBEEFu);
  EXPECT_EQ(parseBytesLE<uint32_t>(buf), 0xDEADBEEFu);

  writeBytesLE<uint64_t>(buf, 0x0123456789ABCDEFull);
  EXPECT_EQ(parseBytesLE<uint64_t>(buf), 0x0123456789ABCDEFull);
}

// The offset argument must position the field without disturbing neighboring
// bytes, and must round-trip from that same offset.
TEST(ByteSerializationUT, honorsOffsetAndLeavesNeighborsUntouched)
{
  uint8_t buf[8];
  for (size_t i = 0; i < sizeof(buf); ++i) {
    buf[i] = 0xCC;
  }

  constexpr size_t offset = 2;
  writeBytesLE<uint16_t>(buf, static_cast<uint16_t>(0x0102), offset);

  // Field bytes are little-endian at the requested offset.
  EXPECT_EQ(buf[offset + 0], 0x02);
  EXPECT_EQ(buf[offset + 1], 0x01);

  // Surrounding bytes are untouched.
  EXPECT_EQ(buf[0], 0xCC);
  EXPECT_EQ(buf[1], 0xCC);
  EXPECT_EQ(buf[4], 0xCC);

  // Round-trips from the same offset.
  EXPECT_EQ(parseBytesLE<uint16_t>(buf, offset), 0x0102);
}

// Signed integral values must round-trip bit-for-bit, including negative
// (two's-complement) bit patterns.
TEST(ByteSerializationUT, roundTripsSignedValues)
{
  uint8_t buf[4] = {};

  writeBytesLE<int32_t>(buf, -1);
  EXPECT_EQ(buf[0], 0xFF);
  EXPECT_EQ(buf[1], 0xFF);
  EXPECT_EQ(buf[2], 0xFF);
  EXPECT_EQ(buf[3], 0xFF);
  EXPECT_EQ(parseBytesLE<int32_t>(buf), -1);

  writeBytesLE<int32_t>(buf, -12345678);
  EXPECT_EQ(parseBytesLE<int32_t>(buf), -12345678);
}
