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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include <MPUefi.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

ConfigurationUEFI makeValidConfigurationUefi(uint16_t headerIdTrailerSize)
{
  ConfigurationUEFI cfg;
  std::memset(&cfg, 0, sizeof(cfg));

  cfg.version = MP_BIOS_UEFI_VARIABLE_VERSION_1;
  // outer size = total minus the version + size fields, matching the
  // MP_VERIFY_UEFI_STRUCT_READ consistency check in MPUefi::getRegistrationServerInfo.
  cfg.size = static_cast<uint16_t>(sizeof(ConfigurationUEFI) - sizeof(cfg.version) - sizeof(cfg.size));
  cfg.flags = 0;
  cfg.headerInfo.version = MP_STRUCTURE_VERSION;
  cfg.urlSize = 0;
  cfg.headerId.version = MP_STRUCTURE_VERSION;
  cfg.headerId.size = headerIdTrailerSize;
  return cfg;
}

} // namespace

// A malformed UEFI variable where headerId.size advertises a trailer that
// extends past the buffer actually returned by readUEFIVar() must be rejected
// before the function memcpy()'s headerId + trailer into the caller buffer.
// Without the bound check, the memcpy reads past the heap allocation
// (CWE-125).
TEST(MPUefiUT_getRegistrationServerInfo, rejectsHeaderIdTrailerLongerThanUefiVariable)
{
  // GIVEN
  // headerId trailer claims 1000 bytes of data, but varDataSize equals only
  // sizeof(ConfigurationUEFI), so no trailer bytes are actually present.
  const uint16_t maliciousTrailerSize = 1000;
  auto uefiVar = test::createVariable<ConfigurationUEFI>();
  const ConfigurationUEFI cfg = makeValidConfigurationUefi(maliciousTrailerSize);
  std::memcpy(uefiVar.mem, &cfg, sizeof(cfg));

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          ::testing::SetArgReferee<1>(sizeof(ConfigurationUEFI)),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{static_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  uint16_t flags = 0;
  std::string serverAddress;
  uint8_t serverIdBuffer[2048] = {0};
  uint16_t serverIdSize = sizeof(serverIdBuffer);
  const auto actualResult =
      underTest.getRegistrationServerInfo(flags, serverAddress, serverIdBuffer, serverIdSize);

  // THEN
  EXPECT_EQ(actualResult, MpResult::MP_UEFI_INTERNAL_ERROR);
}

// Sanity check: a well-formed ConfigurationUEFI whose headerId trailer is zero
// bytes (i.e. requiredSize == sizeof(headerId)) still succeeds after the
// added bound check.
TEST(MPUefiUT_getRegistrationServerInfo, acceptsZeroLengthHeaderIdTrailer)
{
  // GIVEN
  auto uefiVar = test::createVariable<ConfigurationUEFI>();
  const ConfigurationUEFI cfg = makeValidConfigurationUefi(/*headerIdTrailerSize=*/0);
  std::memcpy(uefiVar.mem, &cfg, sizeof(cfg));

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          ::testing::SetArgReferee<1>(sizeof(ConfigurationUEFI)),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{static_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  uint16_t flags = 0xBEEF;
  std::string serverAddress = "unset";
  uint8_t serverIdBuffer[2048] = {0};
  uint16_t serverIdSize = sizeof(serverIdBuffer);
  const auto actualResult =
      underTest.getRegistrationServerInfo(flags, serverAddress, serverIdBuffer, serverIdSize);

  // THEN
  EXPECT_EQ(actualResult, MpResult::MP_SUCCESS);
  EXPECT_EQ(serverIdSize, sizeof(StructureHeader));
}
