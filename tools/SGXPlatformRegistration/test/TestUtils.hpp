/*
 * Copyright(c) 2011-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEST_UTILS_HPP_
#define TEST_UTILS_HPP_

#include <UefiVar.h>
#include "mocks/IUefiMock.hpp"

namespace test {

template<typename T>
struct Variable
{
  uint8_t *mem {nullptr};
  T *var {nullptr};

  T* operator->() { return var; }
};

template<typename T, typename ...Args>
inline Variable<T> createVariable(Args&& ...args)
{
  // TODO: not entirely correctly aligned for T, as there will be
  // external delete call on that (inside MPUefi.cpp for example)
  // still we have UB here - problem for later

  static constexpr size_t SIZE = sizeof(T) + sizeof(std::max_align_t);
  uint8_t *mem = new uint8_t[SIZE];
  memset(mem, 0x00, SIZE);

  auto *var = ::new(mem) T(std::forward<Args>(args)...);

  return Variable<T>{static_cast<uint8_t*>(mem), var};
}

template<typename T>
[[nodiscard]] inline auto createVarGuard(Variable<T> var)
{
  struct Defer
  {
    Variable<T> var;
    ~Defer()
    {
      delete[] var.mem;
    }
  };

  return Defer{var};
}

inline test::IUefiMock *getUefiMock(LogLevel logLevel = LogLevel::MP_REG_LOG_LEVEL_NONE)
{
  test::IUefiMock *uefiMock = new test::IUefiMock;

  EXPECT_CALL(*uefiMock, getLogLevel())
    .Times(::testing::Exactly(1))
    .WillRepeatedly(::testing::Return(logLevel));

  return uefiMock;
}

inline SgxUefiVar withManifest(SgxUefiVar var, const uint8_t *manifestGuid, size_t guidSize = GUID_SIZE)
{
  if(manifestGuid)
    memcpy(var.header.guid, manifestGuid, guidSize);

  return var;
}

inline S3mUefiVar withManifest(S3mUefiVar var, const uint8_t *manifestGuid, size_t guidSize = GUID_SIZE)
{
  if(manifestGuid)
    memcpy(var.header.guid, manifestGuid, guidSize);

  return var;
}

} // namespace

#endif // TEST_UTILS_HPP_
