/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <climits>
#include <cstring>
#include <cassert>
#include <memory>
#include <string.h>
#include <type_traits>
#ifdef _WIN32
#include "WinUefi.h"
#include <regex>
#else
#include "FSUefi.h"
#include <regex.h>
#endif
#include "MPUefi.h"
#include "UefiVar.h"
#include "uefi_logger.h"

#define REGISTRATION_COMPLETE_BIT_MASK 0x0001
#define PACKAGE_INFO_COMPLETE_BIT_MASK 0x0002

#define URL_REGEX "(http://www.|https://www.|http://|https://)?[a-z0-9]+([-.][a-z0-9]+)*.[a-z]{2,5}(:[0-9]{1,5})?(/.*)?"

// defines for values verification
#define MP_VERIFY_UEFI_STRUCT_READ              1
#define MP_VERIFY_UEFI_VERSION_READ             1

namespace {

  using UefiVersion = decltype(std::declval<SgxUefiVar>().version);
  using UefiSize = decltype(std::declval<SgxUefiVar>().size);
  using S3mUefiVersion = decltype(std::declval<S3mUefiVar>().version);
  using S3mUefiSize = decltype(std::declval<S3mUefiVar>().size);

  struct RequestInfo
  {
    UefiVersion version;
    S3mUefiSize uefiVarSize;
    size_t requiredSize, headerOffset;
  };

  // TODO: This should probably go to common and get its own tests
  template
  <
    typename T,
    typename std::enable_if<std::is_integral<T>::value, int>::type = 0
  >
  T parseBytesLE(const uint8_t *raw, size_t offset = 0)
  {
    assert(raw != nullptr && "Requires raw pointer to be non nullptr");

    static_assert(CHAR_BIT == 8, "Requires 8 bit byte");

    constexpr size_t SIZE = sizeof(T);

    T ret{0};
    for(size_t i = offset, pos = SIZE - 1; i < offset + SIZE; ++i, --pos)
    {
      const size_t op = (SIZE - 1 - pos) * 8;
      ret |= static_cast<T>(raw[i]) << op;
    }

    return ret;
  }

  RequestInfo getRequestInfo(const uint8_t *request)
  {
    static_assert(sizeof(UefiVersion) == sizeof(S3mUefiVersion), "Version variables sizes needs to equal");
    static_assert(sizeof(S3mUefiSize) >= sizeof(UefiSize), "S3mSize needs to able to hold legacy size");

    const UefiVersion version = parseBytesLE<UefiVersion>(request);
    if(version == MP_BIOS_UEFI_VARIABLE_VERSION_3)
    {
      // PLATFORM_MANIFEST_V2
      const S3mUefiSize varSize = parseBytesLE<S3mUefiSize>(request, sizeof(UefiVersion));
      const size_t required = sizeof(UefiVersion) + sizeof(S3mUefiSize) + varSize;
      S3mUefiVar var{};
      return {
        version,
        varSize,
        required,
        size_t(std::addressof(var.header)) - size_t(std::addressof(var))
      };
    }

    // PLATFORM_MANIFEST V1
    const UefiSize varSize = parseBytesLE<UefiSize>(request, sizeof(UefiVersion));
    const size_t required = sizeof(UefiVersion) + sizeof(UefiSize) + varSize;
    SgxUefiVar var{};
    return {
      version,
      static_cast<S3mUefiSize>(varSize),
      required,
      size_t(std::addressof(var.header)) - size_t(std::addressof(var))
    };
  };

} // namespace

std::unique_ptr<IUefi> initUefi(std::string path, LogLevel logLevel)
{
#ifdef _WIN32
    return std::make_unique<WinUefi>(logLevel);
#else
    if(path.empty())
      return std::make_unique<FSUefi>(EFIVARS_FILE_SYSTEM, logLevel);

   return std::make_unique<FSUefi>(std::move(path), logLevel);
#endif
}

MPUefi::MPUefi(std::unique_ptr<IUefi> uefi)
  : m_uefi{std::move(uefi)}, m_logLevel{m_uefi->getLogLevel()}
{
}

MpResult MPUefi::getRequestType(MpRequestType& type)
{
  /*
   * We need to check GUID in uefi variable.
   * We expect either PlatformManifest_GUID or AddRequest_GUID.
   *
   * GUID is first entry in header field, which itself is a third field in
   * UEFI structure.
   *
   * First entry is version, which is uint16_t and second field is size,
   * which is either uint16_t or uint32_t depending on platform manifest version.
   *
   * So first, we check uint16_t version, and then move data pointer by appropriate value
   * depending on manifest version.
   *
   */

  size_t varDataSize = 0;
  std::unique_ptr<uint8_t[]> requestUefi{ m_uefi->readUEFIVar(UEFI_VAR_SERVER_REQUEST, varDataSize) };
  if (!requestUefi)
  {
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: SgxRegistrationServerRequest UEFI variable was not found.\n");

    type = MP_REQ_NONE;
    return MP_SUCCESS;
  }

  const auto [version, uefiVarSize, requiredSize, headerOffset] = getRequestInfo(requestUefi.get());

#ifdef MP_VERIFY_UEFI_VERSION_READ
  // structure version check
  if (!(version == MP_BIOS_UEFI_VARIABLE_VERSION_1
        || version == MP_BIOS_UEFI_VARIABLE_VERSION_2
        || version == MP_BIOS_UEFI_VARIABLE_VERSION_3))
  {
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: version check failed. version: %d\n", version);
    return MP_UEFI_INTERNAL_ERROR;
  }
#endif


#ifdef MP_VERIFY_UEFI_STRUCT_READ
  if (varDataSize != requiredSize)
  {
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: SgxRegistrationServerRequest UEFI size is invalid.\n");
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: actual size: %zu, expected size: %zu\n", varDataSize, requiredSize);

    return MP_UEFI_INTERNAL_ERROR;
  }
#endif
  const uint8_t *guidPtr = requestUefi.get() + headerOffset;

  // TODO:
  // Do we need additional checks here?
  // For MP_BIOS_UEFI_VARIABLE_VERSION_1 there can be only manifest
  // For MP_BIOS_UEFI_VARIABLE_VERSION_2 there can be manifest or add package
  // For MP_BIOS_UEFI_VARIABLE_VERSION_3 there can be manifest V2

  // set request type
  if (0 == memcmp(guidPtr, PlatformManifest_GUID, GUID_SIZE))
  {
    type = MP_REQ_REGISTRATION;
  }
  else if (0 == memcmp(guidPtr, AddRequest_GUID, GUID_SIZE))
  {
    type = MP_REQ_ADD_PACKAGE;
  }
  else
  {
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: request GUID doesn't match expected GUID's\n");
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequestType: GUID from SgxRegistrationServerRequest UEFI:\n");
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
        guidPtr[0], guidPtr[1], guidPtr[2], guidPtr[3], guidPtr[4], guidPtr[5],
        guidPtr[6], guidPtr[7], guidPtr[8], guidPtr[9], guidPtr[10], guidPtr[11],
        guidPtr[12], guidPtr[13], guidPtr[14], guidPtr[15]);

    return MP_UEFI_INTERNAL_ERROR;
  }

  return MP_SUCCESS;
}

MpResult MPUefi::getRequest(uint8_t *request, uint32_t &requestSize)
{
  /*
   *
   * 1. Read Version which is uint16_t at the begining.
   * 2. If Version == 1 or 2 then it's MANIFEST V1. If not goto 3.
   *  2a. Next Size is uint16_t on next bytes
   *  2b. Ensure Size is not bigger than passed request size in argument
   *  2c. Return Size count bytes to request pointer
   * 3. If UEFI variable werson == 3 then it's MANIFEST V2
   *  3a. Next Size is uint32_t on next bytes
   *  3b. Ensure Size is not bigger than passed request size in argument
   *  3c. Return Size count bytes to request pointer
   *
   */

  size_t varDataSize{0};
  std::unique_ptr<uint8_t[]> requestUefi{ m_uefi->readUEFIVar(UEFI_VAR_SERVER_REQUEST, varDataSize) };
  if(!requestUefi)
    return MP_NO_PENDING_DATA;

  const auto [version, uefiVarSize, requiredSize, headerOffset] = getRequestInfo(requestUefi.get());

#ifdef MP_VERIFY_UEFI_VERSION_READ
  if(!(version == MP_BIOS_UEFI_VARIABLE_VERSION_1
    || version == MP_BIOS_UEFI_VARIABLE_VERSION_2
    || version == MP_BIOS_UEFI_VARIABLE_VERSION_3))
  {
    uefi_log_message(
        MP_REG_LOG_LEVEL_ERROR,
        "getRequest: version check failed, UEFI version: %d, expected UEFI version: %d or %d or %d\n",
        version, MP_BIOS_UEFI_VARIABLE_VERSION_1,
        MP_BIOS_UEFI_VARIABLE_VERSION_2, MP_BIOS_UEFI_VARIABLE_VERSION_3);

    return MP_INVALID_PARAMETER;
  }
#endif

#ifdef MP_VERIFY_UEFI_STRUCT_READ
  if(varDataSize != requiredSize)
  {
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequest: SgxRegistrationServerRequest UEFI size is invalid.\n");
    uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequest: actual size: %zu, expected size: %zu\n", varDataSize, requiredSize);

    return MP_UEFI_INTERNAL_ERROR;
  }
#endif

  if(request)
  {
    if(requestSize < uefiVarSize)
    {
      uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequest: Request buffer too small for pending request, given size: %d, actual size: %d.\n", requestSize, uefiVarSize);
      return MP_USER_INSUFFICIENT_MEM;
    }

    requestSize = uefiVarSize;
    std::memcpy(request, requestUefi.get() + headerOffset, uefiVarSize);
  }

  return MP_SUCCESS;
}

MpResult MPUefi::setServerResponse(const uint8_t *response, const uint16_t &size) {
    MpResult res = MP_SUCCESS;

    // FIXME: below is UB in C++ due to strict aliasing rule
    // buffer should be define with alignas(SgxUefiVar)
    // then responseUefi should be placement new with such buffer
    // OR
    // we parse bytes into structure like we do in getRequest or getRequestType
    alignas(alignof(SgxUefiVar)) uint8_t responseBuff[MAX_RESPONSE_SIZE + sizeof(SgxUefiVar) - sizeof(StructureHeader)];
    SgxUefiVar *responseUefi = reinterpret_cast<SgxUefiVar*>(responseBuff);

    do {
        if (NULL == response || 0 == size) {
            res = MP_INVALID_PARAMETER;
            break;
        }
        // zero response uefi structure
        memset(responseUefi, 0, sizeof(SgxUefiVar));

        responseUefi->version = MP_BIOS_UEFI_VARIABLE_VERSION_1;
        responseUefi->size = size;

        // copy certs to uefi structure
        memcpy(&(responseUefi->header), response, size);

#if MP_VERIFY_INTERNAL_DATA_STRUCT_WRITE == 1
        // verify PlatformMembershipCertificate response size
        if (0 != size % sizeof(PlatformMembershipCertificate)) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: response size check failed. response should contain PlatformMembershipCertificates, reponse size: %d, PlatformMembershipCertificate size: %d\n", size, sizeof(PlatformMembershipCertificate));
            res = MP_INVALID_PARAMETER;
            break;
        }

        // verify platform membership structure
        for (size_t i = 0; i < size / sizeof(PlatformMembershipCertificate); i++) {
            const PlatformMembershipCertificate *certs = (const PlatformMembershipCertificate *)response;
            // structure version check
            if (MP_STRUCTURE_VERSION != certs[i].header.version) {
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: version check failed on cert %d, version number: %d\n", i, certs[i].header.version);
                res = MP_INVALID_PARAMETER;
                break;
            }

            if ((0 != memcmp(certs[i].header.guid, PlatformMemberShip_GUID, GUID_SIZE)) ||
                (certs[i].header.size != (sizeof(certs[i]) - sizeof(certs[i].header)))) {

                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: PlatformMemberShip structure is invalid.\n");
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: i: %d, certs[i].header.size: %d, sizeof(certs[i]): %d, sizeof(certs[i].header): %d\n",
                    i, certs[i].header.size, sizeof(certs[i]), sizeof(certs[i].header));

                const uint8_t* actual = certs[i].header.guid;
                const uint8_t* expected = PlatformMemberShip_GUID;
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: actual PlatformMemberShip_GUID:\n");
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                    actual[0], actual[1], actual[2], actual[3], actual[4], actual[5],
                    actual[6], actual[7], actual[8], actual[9], actual[10], actual[11],
                    actual[12], actual[13], actual[14], actual[15]);
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: expected PlatformMemberShip_GUID:\n");
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                    expected[0], expected[1], expected[2], expected[3], expected[4], expected[5],
                    expected[6], expected[7], expected[8], expected[9], expected[10], expected[11],
                    expected[12], expected[13], expected[14], expected[15]);

                res = MP_INVALID_PARAMETER;
                break;
            }
        }
#endif
        // write certs to uefi: for the UEFI variable, it has one 4 bytes header: 2 bytes for version, 2 bytes for size
        int numOfBytes = m_uefi->writeUEFIVar(UEFI_VAR_SERVER_RESPONSE, (const uint8_t*)(responseUefi), responseUefi->size + 4, true);
        if (numOfBytes != responseUefi->size + 4) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setServerResponse: failed to write uefi variable.\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
    } while (0);

    return res;
}

MpResult MPUefi::getKeyBlobs(uint8_t *blobs, uint16_t &blobsSize) {
    MpResult res = MP_SUCCESS;
    size_t varDataSize = 0;
    SgxUefiVar *packageInfoUefi = NULL;

    do {
        packageInfoUefi = (SgxUefiVar*)m_uefi->readUEFIVar(UEFI_VAR_PACKAGE_INFO, varDataSize);
        if (packageInfoUefi == 0) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getKeyBlobs: SgxRegistrationPackageInfo UEFI variable was not found. error: %d\n", errno);
            res = MP_NO_PENDING_DATA;
            break;
        }

#ifdef MP_VERIFY_UEFI_VERSION_READ
        // structure version check
        if (MP_BIOS_UEFI_VARIABLE_VERSION_1 != packageInfoUefi->version) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getKeyBlobs: version check failed, UEFI version: %d, expected UEFI version: %d.\n", packageInfoUefi->version, MP_BIOS_UEFI_VARIABLE_VERSION_1);
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif

#ifdef MP_VERIFY_UEFI_STRUCT_READ
        // uefi structure size check
        if (varDataSize != sizeof(packageInfoUefi->version) + sizeof(packageInfoUefi->size) + packageInfoUefi->size) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getKeyBlobs: SgxRegistrationPackageInfo UEFI size is invalid.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getKeyBlobs: actual size: %zu, expected size: %zu\n", varDataSize,
                sizeof(packageInfoUefi->version) + sizeof(packageInfoUefi->size) + packageInfoUefi->size);
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif

        if (blobs) {
            if (blobsSize < packageInfoUefi->size) {
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRequest: Request buffer too small for pending request, given size: %d, actual size: %d.\n",
                    blobsSize, packageInfoUefi->size);
                res = MP_USER_INSUFFICIENT_MEM;
            }
            else {
                memcpy(blobs, &(packageInfoUefi->header), packageInfoUefi->size);
            }
        }
        blobsSize = packageInfoUefi->size;
    } while (0);


    if (packageInfoUefi) {
        delete[](uint8_t*)packageInfoUefi;
    }
    return res;
}

MpResult MPUefi::getRegistrationStatus(MpRegistrationStatus& status) {
    MpResult res = MP_SUCCESS;
    size_t varDataSize = 0;
    RegistrationStatusUEFI *statusUefi = 0;

    do {
        statusUefi = (RegistrationStatusUEFI*)m_uefi->readUEFIVar(UEFI_VAR_STATUS, varDataSize);
        if (statusUefi == 0 || varDataSize != sizeof(RegistrationStatusUEFI)) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationStatus: SgxRegistrationStatus UEFI variable was not found or size not as expected.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationStatus: SgxRegistrationStatus acutal size: %zu, expected size: %zu\n", varDataSize, sizeof(RegistrationStatusUEFI));
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }

#ifdef  MP_VERIFY_UEFI_VERSION_READ
        // structure version check
        if (statusUefi->version != MP_BIOS_UEFI_VARIABLE_VERSION_1) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationStatus: version check failed.\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif

#ifdef MP_VERIFY_UEFI_STRUCT_READ
        // uefi structure size check
        if (statusUefi->size != sizeof(statusUefi->status) + sizeof(statusUefi->errorCode)) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationStatus: SgxRegistrationStatus structure size not as expected.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationStatus: statusUefi->size: %d, sizeof(statusUefi->status): %zu, sizeof(statusUefi->errorCode): %zu\n",
                statusUefi->size, sizeof(statusUefi->status), sizeof(statusUefi->errorCode));
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif
        memset(&status, 0, sizeof(status));

        if (statusUefi->status & REGISTRATION_COMPLETE_BIT_MASK) {
            status.registrationStatus = MP_TASK_COMPLETED;
        }
        if (statusUefi->status & PACKAGE_INFO_COMPLETE_BIT_MASK) {
            status.packageInfoStatus = MP_TASK_COMPLETED;
        }
        status.errorCode = (RegistrationErrorCode)statusUefi->errorCode;
    } while (0);

    if (statusUefi) {
        delete[](uint8_t*)statusUefi;
    }

    return res;
}

MpResult MPUefi::setRegistrationStatus(const MpRegistrationStatus& status) {
    MpResult res = MP_SUCCESS;
    RegistrationStatusUEFI statusUefi;

    // zero all response uefi structure
    memset(&(statusUefi), 0, sizeof(statusUefi));

    do {
        statusUefi.version = MP_BIOS_UEFI_VARIABLE_VERSION_1;
        statusUefi.size = (uint16_t)(sizeof(statusUefi.status) + sizeof(statusUefi.errorCode));

        if (status.registrationStatus == MP_TASK_COMPLETED) {
            statusUefi.status |= REGISTRATION_COMPLETE_BIT_MASK;
        }
        if (status.packageInfoStatus == MP_TASK_COMPLETED) {
            statusUefi.status |= PACKAGE_INFO_COMPLETE_BIT_MASK;
        }
        uefi_log_message(MP_REG_LOG_LEVEL_INFO, "setRegistrationStatus: status.status = 0x%02x, statusUefi.status = 0x%02x.\n", status.status, statusUefi.status);

        statusUefi.errorCode = status.errorCode;

        // write registration status to uefi
        int numOfBytes = m_uefi->writeUEFIVar(UEFI_VAR_STATUS, (const uint8_t*)(&statusUefi), sizeof(statusUefi), false);
        if (numOfBytes != sizeof(statusUefi)) {
            if(numOfBytes == -1) {
                uefi_log_message(MP_REG_LOG_LEVEL_INFO, "Warning: fail to write regsitration status uefi variable, maybe it is in read-only mode.\n");
                res = MP_INSUFFICIENT_PRIVILEGES;
                break;
            }
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationStatus: failed to write uefi variable.\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
    } while (0);

    return res;
}

MpResult MPUefi::getRegistrationServerInfo(uint16_t &flags, std::string &serverAddress, uint8_t *serverId, uint16_t &serverIdSize) {
    MpResult res = MP_SUCCESS;
    size_t varDataSize = 0;
    uint16_t requiredSize = 0;
    ConfigurationUEFI *configurationUefi = 0;

    do {
        configurationUefi = (ConfigurationUEFI *)m_uefi->readUEFIVar(UEFI_VAR_CONFIGURATION, varDataSize);
        if (configurationUefi == 0) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: SgxRegistrationConfiguration UEFI variable was not found.\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }

#ifdef  MP_VERIFY_UEFI_VERSION_READ
        // structure version check
        if (configurationUefi->version != MP_BIOS_UEFI_VARIABLE_VERSION_1) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: version check failed.\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif


#ifdef MP_VERIFY_UEFI_STRUCT_READ
        if (varDataSize != configurationUefi->size + sizeof(configurationUefi->version) + sizeof(configurationUefi->size)) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: RegistrationServerInfo UEFI size is invalid.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: actual size: %zu, expected size: %zu\n", varDataSize,
                configurationUefi->size + sizeof(configurationUefi->version) + sizeof(configurationUefi->size));
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif
        // we assume that REGISTRATION_SERVER_INFO is part of the UEFI defenition so we need to verify it always
        if (MP_STRUCTURE_VERSION != configurationUefi->headerInfo.version) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: version check failed ServerInfo, version number: %d\n", configurationUefi->headerInfo.version);
            res = MP_INVALID_PARAMETER;
            break;
        }

        // copy flags and server address
        flags = configurationUefi->flags;
        serverAddress = std::string((const char*)configurationUefi->url, (size_t)configurationUefi->urlSize);

        requiredSize = (uint16_t)(configurationUefi->headerId.size + (uint16_t)sizeof(configurationUefi->headerId));
        if (serverId) {
            if (serverIdSize < requiredSize) {
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "getRegistrationServerInfo: Request buffer too small for pending request, given size: %d, actual size: %d.\n",
                    serverIdSize, requiredSize);
                res = MP_USER_INSUFFICIENT_MEM;
            }
            else {
                memcpy(serverId, &(configurationUefi->headerId), requiredSize);
            }
        }
        serverIdSize = requiredSize;
    } while (0);

    if (configurationUefi) {
        delete[](uint8_t*)configurationUefi;
    }

    return res;
}

MpResult MPUefi::setRegistrationServerInfo(const uint16_t &flags, const std::string &serverAddress, const uint8_t *serverId, const uint16_t &serverIdSize) {
    MpResult res = MP_SUCCESS;
    int ret = 0;
    uint8_t *buff = NULL;
    ConfigurationUEFI *configurationUefi = NULL;
#ifndef _WIN32
    regex_t regex;
#else
    std::cmatch match;
    std::regex regex(URL_REGEX);
    std::regex_constants::match_flag_type flag =
        std::regex_constants::match_default;
#endif
#if MP_VERIFY_INTERNAL_DATA_STRUCT_WRITE == 1
    RegistrationServerID *registrationServerID;
#endif

    do {
        if (NULL == serverId || 0 == serverIdSize) {
            res = MP_INVALID_PARAMETER;
            break;
        }

        if (MAX_URL_SIZE < serverAddress.length()) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: URL length is too long. \n");
            res = MP_INVALID_PARAMETER;
            break;
        }

#ifndef _WIN32
        /* create regular expression */
        ret = regcomp(&regex, URL_REGEX, REG_EXTENDED);
        if (ret) {
            res = MP_UNEXPECTED_ERROR;
            break;
        }

        /* use regular expression */
        ret = regexec(&regex, serverAddress.c_str(), 0, NULL, 0);
        if (ret) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "Server info contains invalid URL: %s\n", serverAddress.c_str());
            res = MP_INVALID_PARAMETER;
            regfree(&regex);
            break;
        }

        /* free compiled regular expression */
        regfree(&regex);
#else
        /* use regular expression */
        if (!regex_match(serverAddress, regex, flag)) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "Server info contains invalid URL: %s\n", serverAddress.c_str());
            res = MP_INVALID_PARAMETER;
            break;
        }
#endif

        // Allocate buff
        try {
            buff = new uint8_t[sizeof(ConfigurationUEFI) + serverIdSize - sizeof(configurationUefi->headerId)];
        }
        catch (std::bad_alloc&) {
            res = MP_MEM_ERROR;
            break;
        }

        configurationUefi = reinterpret_cast<ConfigurationUEFI*>(buff);

        // zero all response uefi structure
        memset(configurationUefi, 0, sizeof(ConfigurationUEFI) + serverIdSize - sizeof(configurationUefi->headerId));

        configurationUefi->version = MP_BIOS_UEFI_VARIABLE_VERSION_1;
        configurationUefi->size = (uint16_t)(sizeof(configurationUefi->flags) + sizeof(configurationUefi->headerInfo) +
            +sizeof(configurationUefi->urlSize) + sizeof(configurationUefi->url) + serverIdSize);
        configurationUefi->flags = flags;
        memcpy(&(configurationUefi->headerInfo.guid), RegistrationServerInfo_GUID, GUID_SIZE);
        configurationUefi->headerInfo.version = MP_STRUCTURE_VERSION;
        configurationUefi->headerInfo.size = (uint16_t)((uint16_t)sizeof(configurationUefi->urlSize) +
            (uint16_t)sizeof(configurationUefi->url) + serverIdSize);
        configurationUefi->urlSize = (uint16_t)serverAddress.length();
        memcpy(&(configurationUefi->url), serverAddress.c_str(), configurationUefi->urlSize);

        // copy server ID to uefi structure
        memcpy(&(configurationUefi->headerId), serverId, serverIdSize);

#if MP_VERIFY_INTERNAL_DATA_STRUCT_WRITE == 1
        registrationServerID = (RegistrationServerID*)&configurationUefi->headerId;
        // structure version check
        if (configurationUefi->headerInfo.version != MP_STRUCTURE_VERSION) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: version check failed\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }

        // verify registration server info structure
        if ((configurationUefi->headerInfo.size != (sizeof(RegistrationServerInfo) - sizeof(configurationUefi->headerInfo))) ||
            (0 != memcmp(configurationUefi->headerInfo.guid, RegistrationServerInfo_GUID, GUID_SIZE))) {

            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: registration server info structure is invalid.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: configurationUefi->headerInfo.size: %d, \
                expected size: %d\n", configurationUefi->headerInfo.size, sizeof(RegistrationServerInfo) - sizeof(configurationUefi->headerInfo));

            const uint8_t* actual = configurationUefi->headerInfo.guid;
            const uint8_t* expected = RegistrationServerInfo_GUID;
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "actual RegistrationServerInfo_GUID:\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                actual[0], actual[1], actual[2], actual[3], actual[4], actual[5],
                actual[6], actual[7], actual[8], actual[9], actual[10], actual[11],
                actual[12], actual[13], actual[14], actual[15]);
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "expect RegistrationServerInfo_GUID:\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                expected[0], expected[1], expected[2], expected[3], expected[4], expected[5],
                expected[6], expected[7], expected[8], expected[9], expected[10], expected[11],
                expected[12], expected[13], expected[14], expected[15]);

            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
 
        // structure version check
        if (registrationServerID->header.version != MP_STRUCTURE_VERSION) {
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: registrationServerID version check failed\n");
            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }

        if ((registrationServerID->header.size != (sizeof(*registrationServerID) - sizeof(registrationServerID->header))) ||
            (0 != memcmp(registrationServerID->header.guid, RegistrationServerID_GUID, GUID_SIZE))) {

            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: registration server ID structure is invalid.\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: registrationServerID->header.size: %d, sizeof(registrationServerID->): %d, sizeof(registrationServerID->header): %d\n",
                registrationServerID->header.size, sizeof(*registrationServerID), sizeof(registrationServerID->header));

            const uint8_t* actual = registrationServerID->header.guid;
            const uint8_t* expected = RegistrationServerID_GUID;
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "actual RegistrationServerID_GUID:\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                actual[0], actual[1], actual[2], actual[3], actual[4], actual[5],
                actual[6], actual[7], actual[8], actual[9], actual[10], actual[11],
                actual[12], actual[13], actual[14], actual[15]);
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "expect RegistrationServerID_GUID:\n");
            uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
                expected[0], expected[1], expected[2], expected[3], expected[4], expected[5],
                expected[6], expected[7], expected[8], expected[9], expected[10], expected[11],
                expected[12], expected[13], expected[14], expected[15]);

            res = MP_UEFI_INTERNAL_ERROR;
            break;
        }
#endif

        // write registration configuration to uefi
        int numOfBytes = m_uefi->writeUEFIVar(UEFI_VAR_CONFIGURATION, (const uint8_t*)configurationUefi, sizeof(ConfigurationUEFI) + serverIdSize - 
            sizeof(configurationUefi->headerId), false);
        if (numOfBytes != (int)(sizeof(ConfigurationUEFI) + serverIdSize - sizeof(configurationUefi->headerId))) {
            if(numOfBytes == -1) {
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: Can't write Registration Configuration UEFI variable, please check whether the SGX has been disabled.\n");
                res = MP_INSUFFICIENT_PRIVILEGES;
            } 
            else {
                uefi_log_message(MP_REG_LOG_LEVEL_ERROR, "setRegistrationServerInfo: failed to write uefi variable.\n");
                res = MP_UNEXPECTED_ERROR;
            }	    
            break;
        }
    } while (0);

    if (buff) {
        delete[] buff;
    }

    return res;
}
