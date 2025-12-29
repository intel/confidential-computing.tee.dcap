/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __UEFI_NETWORK_LOGGER_H
#define __UEFI_NETWORK_LOGGER_H
#include "logger.h"

extern "C" void uefi_log_message_aux(LogLevel glog_level, LogLevel level, const char *format, ...);

#define uefi_log_message(level, format, ...) uefi_log_message_aux(m_logLevel, level, format, ## __VA_ARGS__)

#ifndef _WIN32
extern "C" void  __attribute__((weak)) log_message_aux(LogLevel level, const char *format, va_list argptr);
#else
extern "C" void default_uefi_log_message(LogLevel glog_level, LogLevel level, const char *format, ...);
#pragma comment(linker, "/alternatename:uefi_log_message_aux=default_uefi_log_message")
#endif

#endif // #ifndef __UEFI_NETWORK_LOGGER_H

