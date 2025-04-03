#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

BUILDENV_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include $(BUILDENV_DIR)/version.mk

# If the value of _FORTIFY_SOURCE is greater than 2, use the value, else use 2.
FORTIFY_SOURCE_VAL:= $(lastword $(sort $(word 2,$(subst =, ,$(filter -D_FORTIFY_SOURCE=%,$(CFLAGS)))) 2))

CP    := cp -f
LN    := ln -sf
MKDIR := mkdir -p
STRIP := strip
OBJCOPY := objcopy
NIPX := .nipx
NIPD := .nipd
NIPRODT := .niprod

######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

ifndef SERVTD_ATTEST
    ifneq ($(origin SGX_SDK),file)
        include $(SGX_SDK)/buildenv.mk
    else
        ifneq ($(SDK_NOT_REQUIRED), 1)
            $(info You may need to set environment variables if the SGX SDK is installed.)
            $(info Use a command like 'source /opt/intel/sgxsdk/environment')
        endif
    endif
endif

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_TRUSTED_LIBRARY_PATH)
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

# clean the content of 'INCLUDE' - this variable will be set by vcvars32.bat
# thus it will cause build error when this variable is used by our Makefile,
# when compiling the code under Cygwin tainted by MSVC environment settings.
INCLUDE :=

# this will return the path to the file that included the buildenv.mk file
CUR_DIR := $(realpath $(call parent-dir,$(lastword $(wordlist 2,$(words $(MAKEFILE_LIST)),x $(MAKEFILE_LIST)))))

CET_FLAGS :=
CC_VERSION := $(shell $(CC) -dumpversion)
CC_NO_LESS_THAN_8 := $(shell expr $(CC_VERSION) \>\= "8")
ifeq ($(CC_NO_LESS_THAN_8), 1)
    CET_FLAGS += -fcf-protection
endif

# turn on stack protector for SDK
COMMON_FLAGS += -fstack-protector-strong

ifdef DEBUG
    COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG
    COMMON_FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG -DDEBUG_MODE=1
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL) -UDEBUG -DNDEBUG
endif

ifdef SE_SIM
    COMMON_FLAGS += -DSE_SIM
endif


COMMON_FLAGS += -ffunction-sections -fdata-sections

# turn on compiler warnings as much as possible
COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
		-Waddress -Wsequence-point -Wformat-security \
		-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
		-Wcast-align -Wconversion -Wredundant-decls

# additional warnings flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor

CXXFLAGS += -std=c++14

.DEFAULT_GOAL := all
# this turns off the RCS / SCCS implicit rules of GNU Make
% : RCS/%,v
% : RCS/%
% : %,v
% : s.%
% : SCCS/s.%

# If a rule fails, delete $@.
.DELETE_ON_ERROR:

HOST_FILE_PROGRAM := file

UNAME := $(shell uname -m)
ifneq (,$(findstring 86,$(UNAME)))
    HOST_ARCH := x86
    ifneq (,$(shell $(HOST_FILE_PROGRAM) -L $(SHELL) | grep 'x86[_-]64'))
        HOST_ARCH := x86_64
    endif
else
    $(info Unknown host CPU arhitecture $(UNAME))
    $(error Aborting)
endif

BUILD_DIR := $(ROOT_DIR)/build/linux

ifeq "$(findstring __INTEL_COMPILER, $(shell $(CC) -E -dM -xc /dev/null))" "__INTEL_COMPILER"
  ifeq ($(shell test -f /usr/bin/dpkg; echo $$?), 0)
    ADDED_INC := -I /usr/include/$(shell dpkg-architecture -qDEB_BUILD_MULTIARCH)
  endif
endif

ARCH := $(HOST_ARCH)
ifeq "$(findstring -m32, $(CXXFLAGS))" "-m32"
  ARCH := x86
endif

ifeq ($(ARCH), x86)
COMMON_FLAGS += -DITT_ARCH_IA32
else
COMMON_FLAGS += -DITT_ARCH_IA64
endif

ifneq ($(MITIGATION-CVE-2020-0551), LOAD)
    ifneq ($(MITIGATION-CVE-2020-0551), CF)
        COMMON_FLAGS += $(CET_FLAGS)
    endif
endif

ifdef SERVTD_ATTEST
COMMON_FLAGS += -DSERVTD_ATTEST
endif

CFLAGS   += $(COMMON_FLAGS)
CXXFLAGS += $(COMMON_FLAGS)

# Enable the security flags
COMMON_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack

# Enable build static library
GEN_STATIC ?= 0

# Compiler and linker options for an Enclave
#
# We are using '--export-dynamic' so that `g_global_data_sim' etc.
# will be exported to dynamic symbol table.
#
# When `pie' is enabled, the linker (both BFD and Gold) under Ubuntu 14.04
# will hide all symbols from dynamic symbol table even if they are marked
# as `global' in the LD version script.
ENCLAVE_CFLAGS   = -ffreestanding -nostdinc -fvisibility=hidden -fpie -fno-strict-overflow -fno-delete-null-pointer-checks $(MITIGATION_CFLAGS)
ENCLAVE_CXXFLAGS = $(ENCLAVE_CFLAGS) -nostdinc++
ENCLAVE_LDFLAGS  = $(COMMON_LDFLAGS) -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                   -Wl,--defsym,__ImageBase=0

SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH := $(ROOT_DIR)/../../..
SERVTD_ATTEST_STD_INC_PATH := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/common/inc
SERVTD_ATTEST_STD_LIB_PATH := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/build/linux
SERVTD_ATTEST_CFLAGS := $(CFLAGS) -ffreestanding -nostdinc -fPIC -fvisibility=hidden -DSERVTD_ATTEST
SERVTD_ATTEST_CXXFLAGS := $(SERVTD_ATTEST_CFLAGS) -nostdinc++
SERVTD_ATTEST_LDFLAGS := -nostdlib -nodefaultlibs -nostartfiles  \
                        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,--gc-sections -g
SERVTD_ATTEST_BUILD_DIR := $(BUILD_DIR)/servtd_attest
