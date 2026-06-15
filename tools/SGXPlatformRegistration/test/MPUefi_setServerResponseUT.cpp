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

#include <cassert>
#include <cstring>
#include <vector>

#include <MPUefi.h>
#include <MPConfigurations.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

// Build a valid StructureHeader for a PlatformMembership cert.
// payloadSize = number of bytes of payload that follow the header.
StructureHeader makeMembershipHeader(uint16_t payloadSize)
{
    StructureHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.guid, PlatformMemberShip_GUID, GUID_SIZE);
    hdr.version = MP_STRUCTURE_VERSION;
    hdr.size    = payloadSize;
    return hdr;
}

// Build a response buffer containing N certs each with the given payloadSize.
// Returns the buffer; *outSize is set to the total byte count.
std::vector<uint8_t> makeValidResponse(size_t numCerts, uint16_t payloadSize, uint16_t *outSize)
{
    // every caller relies on outSize being written; fail fast on a misuse
    assert(outSize != nullptr);

    const size_t certSize = sizeof(StructureHeader) + payloadSize;
    const size_t total    = numCerts * certSize;
    std::vector<uint8_t> buf(total, 0xAB);

    for (size_t i = 0; i < numCerts; ++i)
    {
        StructureHeader hdr = makeMembershipHeader(payloadSize);
        memcpy(buf.data() + i * certSize, &hdr, sizeof(hdr));
    }

    *outSize = static_cast<uint16_t>(total);
    return buf;
}

} // namespace

// ── Null / zero-length ──────────────────────────────────────────────────────

TEST(MPUefiUT_setServerResponse, NullResponseReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    uint16_t size = sizeof(StructureHeader);
    EXPECT_EQ(underTest.setServerResponse(nullptr, size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, ZeroSizeReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    uint8_t dummy = 0;
    uint16_t zero = 0;
    EXPECT_EQ(underTest.setServerResponse(&dummy, zero), MP_INVALID_PARAMETER);
}

// ── Size bound (S-38) ────────────────────────────────────────────────────────

TEST(MPUefiUT_setServerResponse, OversizedResponseReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    // MAX_RESPONSE_SIZE + 1 overflows the stack buffer
    std::vector<uint8_t> buf(MAX_RESPONSE_SIZE + 1, 0);
    uint16_t size = static_cast<uint16_t>(MAX_RESPONSE_SIZE + 1);
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

// ── Structural validation ────────────────────────────────────────────────────

TEST(MPUefiUT_setServerResponse, TooSmallForOneHeaderReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    std::vector<uint8_t> buf(sizeof(StructureHeader) - 1, 0);
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, WrongGuidReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    StructureHeader hdr = makeMembershipHeader(0);
    hdr.guid[0] ^= 0xFF; // corrupt first byte of GUID

    std::vector<uint8_t> buf(sizeof(hdr));
    memcpy(buf.data(), &hdr, sizeof(hdr));
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, WrongVersionReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    StructureHeader hdr = makeMembershipHeader(0);
    hdr.version = MP_STRUCTURE_VERSION + 1;

    std::vector<uint8_t> buf(sizeof(hdr));
    memcpy(buf.data(), &hdr, sizeof(hdr));
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, NonZeroReservedBytesReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    StructureHeader hdr = makeMembershipHeader(0);
    hdr.reserved[0] = 0x01; // reserved must be zero per UefiVar.h

    std::vector<uint8_t> buf(sizeof(hdr));
    memcpy(buf.data(), &hdr, sizeof(hdr));
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, HeaderSizeExceedsBufferReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    // header.size = 100 but only 0 bytes of payload follow
    StructureHeader hdr = makeMembershipHeader(100);

    std::vector<uint8_t> buf(sizeof(hdr)); // no payload bytes
    memcpy(buf.data(), &hdr, sizeof(hdr));
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

TEST(MPUefiUT_setServerResponse, TruncatedSecondHeaderReturnsInvalidParameter)
{
    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(0);

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    // First cert is valid (header + 0 payload), then only a partial second header
    StructureHeader hdr = makeMembershipHeader(0);
    std::vector<uint8_t> buf(sizeof(hdr) + sizeof(hdr) - 1, 0);
    memcpy(buf.data(), &hdr, sizeof(hdr));
    // second entry is intentionally incomplete
    uint16_t size = static_cast<uint16_t>(buf.size());
    EXPECT_EQ(underTest.setServerResponse(buf.data(), size), MP_INVALID_PARAMETER);
}

// ── Success paths ────────────────────────────────────────────────────────────

TEST(MPUefiUT_setServerResponse, SingleValidCertWritesToUefiVar)
{
    uint16_t size = 0;
    const auto response = makeValidResponse(1, 0, &size);

    // Expected write size: 4-byte UEFI header (version + size fields) + cert payload
    const int expectedWriteSize = 4 + size;

    const char *capturedVarName = nullptr;
    std::vector<uint8_t> capturedData;

    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, expectedWriteSize, true))
        .Times(1)
        .WillOnce(::testing::DoAll(
            ::testing::SaveArg<0>(&capturedVarName),
            ::testing::Invoke([&](const char*, const uint8_t* data, size_t dataSize, bool) {
                capturedData.assign(data, data + dataSize);
                return static_cast<int>(dataSize);
            })
        ));

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    EXPECT_EQ(underTest.setServerResponse(response.data(), size), MP_SUCCESS);
    EXPECT_STREQ(capturedVarName, UEFI_VAR_SERVER_RESPONSE);

    // First 2 bytes: version == MP_BIOS_UEFI_VARIABLE_VERSION_1
    uint16_t writtenVersion;
    memcpy(&writtenVersion, capturedData.data(), sizeof(writtenVersion));
    EXPECT_EQ(writtenVersion, static_cast<uint16_t>(MP_BIOS_UEFI_VARIABLE_VERSION_1));

    // Next 2 bytes: size field == size of the response payload
    uint16_t writtenSize;
    memcpy(&writtenSize, capturedData.data() + 2, sizeof(writtenSize));
    EXPECT_EQ(writtenSize, size);

    // Remaining bytes match the response buffer
    EXPECT_EQ(memcmp(capturedData.data() + 4, response.data(), size), 0);
}

TEST(MPUefiUT_setServerResponse, TwoValidCertsWritesToUefiVar)
{
    uint16_t size = 0;
    const auto response = makeValidResponse(2, 16, &size);

    const int expectedWriteSize = 4 + size;

    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, expectedWriteSize, true))
        .Times(1)
        .WillOnce(::testing::Return(expectedWriteSize));

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    EXPECT_EQ(underTest.setServerResponse(response.data(), size), MP_SUCCESS);
}

// ── writeUEFIVar failure ─────────────────────────────────────────────────────

TEST(MPUefiUT_setServerResponse, WriteUefiVarFailureReturnsUefiInternalError)
{
    uint16_t size = 0;
    const auto response = makeValidResponse(1, 0, &size);

    auto *uefiMock = test::getUefiMock();
    EXPECT_CALL(*uefiMock, writeUEFIVar(::testing::_, ::testing::_, ::testing::_, ::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(0)); // wrong byte count → failure

    std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
    MPUefi underTest(std::move(mock));

    EXPECT_EQ(underTest.setServerResponse(response.data(), size), MP_UEFI_INTERNAL_ERROR);
}
