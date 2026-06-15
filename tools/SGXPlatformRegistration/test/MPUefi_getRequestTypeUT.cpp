/*
 * Copyright (C) 2025 Intel Corporation. All rights reserved.
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

#include <ostream>

#include <MPUefi.h>
#include <UefiVar.h>

#include "TestUtils.hpp"

namespace {

ACTION_P(SaveArg0Value, p)
{
  *p = arg0;
}

} // namespace

struct ReqTypeTestInput_PMV1
{
  const char *description {nullptr};

  SgxUefiVar uefiVar;
  size_t varDataSize;

  MpRequestType expectedRetRequestType;
  MpResult expectedResult;
};

struct ReqTypeTestInput_PMV2
{
  const char *description {nullptr};

  S3mUefiVar uefiVar;
  size_t varDataSize;

  MpRequestType expectedRetRequestType;
  MpResult expectedResult;
};

inline std::ostream& operator<<(std::ostream &oss, const ReqTypeTestInput_PMV1 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

inline std::ostream& operator<<(std::ostream &oss, const ReqTypeTestInput_PMV2 &in)
{
  if(in.description)
    return oss << in.description;

  return oss;
}

class MPUefiUT_getRequestTypePMV1 : public::testing::TestWithParam<ReqTypeTestInput_PMV1>
{};

class MPUefiUT_getRequestTypePMV2 : public::testing::TestWithParam<ReqTypeTestInput_PMV2>
{};

TEST(MPUefiUT_getRquestType , mpReqNoneOnNullptr)
{
  // GIVEN
  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock();
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::Return(nullptr)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  MpRequestType retRequestType;
  const auto actualResult = underTest.getRequestType(retRequestType);

  // THEN
  EXPECT_EQ(actualResult, MpResult::MP_SUCCESS);
  EXPECT_EQ(retRequestType, MpRequestType::MP_REQ_NONE);
  EXPECT_STREQ(actualArg0, UEFI_VAR_SERVER_REQUEST);
}

TEST_P(MPUefiUT_getRequestTypePMV1, nonNullptrResult)
{
  // GIVEN
  const auto input{ GetParam() };
  auto uefiVar = test::createVariable<SgxUefiVar>();
  memcpy(uefiVar.var, &input.uefiVar, sizeof(SgxUefiVar));

  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock(LogLevel::MP_REG_LOG_LEVEL_NONE);
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::SetArgReferee<1>(input.varDataSize),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  MpRequestType retRequestType = MpRequestType::MP_REQ_NONE;
  const auto actualResult = underTest.getRequestType(retRequestType);
  
  // THEN
  EXPECT_EQ(actualResult, input.expectedResult);
  EXPECT_EQ(retRequestType, input.expectedRetRequestType);
  EXPECT_STREQ(actualArg0, UEFI_VAR_SERVER_REQUEST);
}

TEST_P(MPUefiUT_getRequestTypePMV2, nonNullptrResult)
{
  // GIVEN
  const auto input{ GetParam() };
  auto uefiVar = test::createVariable<S3mUefiVar>();
  memcpy(uefiVar.var, &input.uefiVar, sizeof(S3mUefiVar));

  const char *actualArg0 = nullptr;

  auto *uefiMock = test::getUefiMock(LogLevel::MP_REG_LOG_LEVEL_NONE);
  EXPECT_CALL(*uefiMock, readUEFIVar(::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
          SaveArg0Value(&actualArg0),
          ::testing::SetArgReferee<1>(input.varDataSize),
          ::testing::Return(uefiVar.mem)
    ));

  std::unique_ptr<IUefi> mock{reinterpret_cast<IUefi*>(uefiMock)};
  MPUefi underTest(std::move(mock));

  // WHEN
  MpRequestType retRequestType = MpRequestType::MP_REQ_NONE;
  const auto actualResult = underTest.getRequestType(retRequestType);

  // THEN
  EXPECT_EQ(actualResult, input.expectedResult);
  EXPECT_EQ(retRequestType, input.expectedRetRequestType);
  EXPECT_STREQ(actualArg0, UEFI_VAR_SERVER_REQUEST);
}

#ifdef _WIN32
// old 1.8.0 version
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_CASE_P
#else
#define GTEST_TEST_CASE_P INSTANTIATE_TEST_SUITE_P
#endif

GTEST_TEST_CASE_P(
  MPUefi,
  MPUefiUT_getRequestTypePMV1,
  ::testing::Values(

    ReqTypeTestInput_PMV1{
      "varDataSize too small to parse header fields",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          sizeof(StructureHeader),
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      3, // less than sizeof(UefiVersion) + sizeof(S3mUefiSize) == 6
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_1",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_REGISTRATION,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_1 varSize too small for GUID",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size < GUID_SIZE
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_2",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_REGISTRATION,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_2 varSize too small for GUID",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          5, //size < GUID_SIZE
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_1 success",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_REGISTRATION,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_2 success",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_REGISTRATION,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_1 returned size mismatch",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size) - 1,
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest MP_BIOS_UEFI_VARIABLE_VERSION_2 returned size mismatch",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "PlatformManifest unsuported UEFI Variable version",
      test::withManifest(
        SgxUefiVar{
          100,
          5, //size
          StructureHeader{}
        },
        PlatformManifest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_1 success",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_ADD_PACKAGE,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_1 varSize too small for GUID",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size < GUID_SIZE
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_2 success",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          sizeof(StructureHeader), //size
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      sizeof(StructureHeader) + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_ADD_PACKAGE,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_2 varSize too small for GUID",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          5, //size < GUID_SIZE
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_1 returned size mismatch",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "AddRequest MP_BIOS_UEFI_VARIABLE_VERSION_2 returned size mismatch",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          5, //size
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      4 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "AddRequest unsuported UEFI Variable version",
      test::withManifest(
        SgxUefiVar{
          100,
          5, //size
          StructureHeader{}
        },
        AddRequest_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "Incorrect GUID MP_BIOS_UEFI_VARIABLE_VERSION_1",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_1,
          5, //size
          StructureHeader{}
        },
        PlatformInfo_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV1{
      "Incorrect GUID MP_BIOS_UEFI_VARIABLE_VERSION_2",
      test::withManifest(
        SgxUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_2,
          5, //size
          StructureHeader{}
        },
        PlatformInfo_GUID
      ),
      5 + sizeof(SgxUefiVar::version) + sizeof(SgxUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    }

  )
);

GTEST_TEST_CASE_P(
  MPUefi,
  MPUefiUT_getRequestTypePMV2,
  ::testing::Values(

    ReqTypeTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 unexpected GUID",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3,
          sizeof(TlvHeader), //size
          TlvHeader{}
        },
        PlatformInfo_GUID
      ),
      sizeof(TlvHeader) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 incorrect sizes",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3,
          sizeof(TlvHeader), //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(TlvHeader) - 1 + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    },

    ReqTypeTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 success with PlatformManifes_GUID",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3,
          sizeof(TlvHeader), //size
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      sizeof(TlvHeader) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpRequestType::MP_REQ_REGISTRATION,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 success with AddRequest_GUID",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3,
          sizeof(TlvHeader), //size
          TlvHeader{}
        },
        AddRequest_GUID
      ),
      sizeof(TlvHeader) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpRequestType::MP_REQ_ADD_PACKAGE,
      MpResult::MP_SUCCESS
    },

    ReqTypeTestInput_PMV2{
      "MP_BIOS_UEFI_VARIABLE_VERSION_3 varSize too small for GUID",
      test::withManifest(
        S3mUefiVar{
          MP_BIOS_UEFI_VARIABLE_VERSION_3,
          GUID_SIZE - 1, //size < GUID_SIZE
          TlvHeader{}
        },
        PlatformManifest_GUID
      ),
      (GUID_SIZE - 1) + sizeof(S3mUefiVar::version) + sizeof(S3mUefiVar::size),
      MpRequestType::MP_REQ_NONE,
      MpResult::MP_UEFI_INTERNAL_ERROR
    }

  )
);
