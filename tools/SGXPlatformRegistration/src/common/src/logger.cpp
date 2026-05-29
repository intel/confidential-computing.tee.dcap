/*
 * Copyright(c) 2011-2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * File: comomon.cpp
 *  
 * Description: Shared utility functions for logging data.
 */
#include <stdio.h>
#include <stdarg.h>
#include <ctime>
#include <string>
using namespace std;

#include "logger.h"
#ifndef _WIN32
#include "dcap_safe_file_ops.h"
#endif

LogLevel glog_level = MP_REG_LOG_LEVEL_INFO;

#ifndef _WIN32

extern "C" void log_message_aux(
    LogLevel level,
	const char *format,
	va_list argptr)
{
	FILE *f = dcap_safe_fopen(LOG_FILE, "a");
	if (f == NULL)
	{
		printf("Could not open log file. \n");
		return;
	}
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buffer, 80, "[%d-%m-%Y %I:%M:%S] ", timeinfo);
	string str(buffer);
	fprintf(f, "%s", str.c_str());

    switch (level) {
		case MP_REG_LOG_LEVEL_ERROR:
			fprintf(f, "%s", "ERROR: ");
			break;
		case MP_REG_LOG_LEVEL_WARN:
			fprintf(f, "%s", "WARN: ");
			break;
		case MP_REG_LOG_LEVEL_INFO:
			fprintf(f, "%s", "INFO: ");
			break;
        case MP_REG_LOG_LEVEL_DEBUG:
			fprintf(f, "%s", "DEBUG: ");
			break;
        default:
            break;
    }

	vfprintf(f, format, argptr);
	fclose(f);
}

extern "C" void log_message(LogLevel level, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	log_message_aux(level, format, ap);
	va_end(ap);
}

#else

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "messages.h"

#define SVCNAME				TEXT("IntelMPAService")
#define TIME_BUFFER_SIZE	80
#define MESSAGE_BUFFER_SIZE 512
#define LOG_FILE_NAME		"mpa.log"

#ifndef TEST_MODE
void SvcReportEvent(LogLevel level, char* buffer)
{
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
    WORD eventType = 0;

	hEventSource = RegisterEventSource(NULL, SVCNAME);

	if (NULL != hEventSource)
	{
		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = buffer;
        
        switch (level) {
            case MP_REG_LOG_LEVEL_ERROR:
                eventType = EVENTLOG_ERROR_TYPE;
                break;
			case MP_REG_LOG_LEVEL_WARN:
				eventType = EVENTLOG_WARNING_TYPE;
				break;
            case MP_REG_LOG_LEVEL_INFO:
            case MP_REG_LOG_LEVEL_DEBUG:
				eventType =  EVENTLOG_INFORMATION_TYPE;
				break;
            default:
                break;
        }

		if (level != MP_REG_LOG_LEVEL_NONE)
		{
			ReportEvent(hEventSource,  // event log handle
				eventType, // event type
				0,					 // event category
				SVC_INFO,		     // event identifier
				NULL,                // no security identifier
				2,                   // size of lpszStrings array
				0,                   // no binary data
				lpszStrings,         // array of strings
				NULL);               // no binary data
		}

		DeregisterEventSource(hEventSource);
	}
}

#else
static void writeToStdout(LogLevel level, const char* buffer)
{
    switch (level) {
        case MP_REG_LOG_LEVEL_ERROR:
            printf("%s", "ERROR: ");
            break;
        case MP_REG_LOG_LEVEL_WARN:
            printf("%s", "WARN: ");
            break;
        case MP_REG_LOG_LEVEL_INFO:
            printf("%s", "INFO: ");
            break;
	    case MP_REG_LOG_LEVEL_DEBUG:
			printf("%s", "DEBUG: ");
			break;
        default:
            break;
    }

    printf("%s", buffer);
}
#endif

static void common_log_message(LogLevel level, const char *format, va_list ap)
{
	char buffer[MESSAGE_BUFFER_SIZE] = {};
	vsnprintf(buffer, MESSAGE_BUFFER_SIZE, format, ap);

#ifdef TEST_MODE
    writeToStdout(level, buffer);
#else
	SvcReportEvent(level, buffer);
#endif
}

#define CALL_COMMON_LOG {\
	va_list ap;\
    if (glog_level < level) return; \
	va_start(ap, format);\
	common_log_message(level, format, ap);\
	va_end(ap);}


extern "C" void agent_log_message(LogLevel level, const char *format, ...) CALL_COMMON_LOG
extern "C" void management_log_message(LogLevel level, const char *format, ...) CALL_COMMON_LOG
//Dlls
extern "C" void network_log_message_aux(LogLevel glog_level, LogLevel level, const char *format, ...) CALL_COMMON_LOG
extern "C" void uefi_log_message_aux(LogLevel glog_level, LogLevel level, const char *format, ...) CALL_COMMON_LOG

#endif
