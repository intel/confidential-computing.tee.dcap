#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

BUILDENV_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include $(BUILDENV_DIR)/version.mk

JOBS_FLAG = $(findstring -j,$(MAKEFLAGS))
NUM_JOBS = $(patsubst -j%,%,$(filter -j%,$(MAKEFLAGS)))
MAKE_PARALLEL_JOBS = $(strip $(if $(JOBS_FLAG),$(if $(NUM_JOBS),-j$(NUM_JOBS),-j)))

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

# Compiler detection
check_compiler = $(shell $(1) -dM -E - < /dev/null 2>/dev/null | grep -q $(2) && echo 1 || echo 0)

IS_CLANG := $(call check_compiler,$(CC),__clang__)
ifeq ($(IS_CLANG), 1)
    IS_GCC := 0
else
    IS_GCC := $(call check_compiler,$(CC),__GNUC__)
endif

ifneq ($(IS_CLANG), 1)
    ifneq ($(IS_GCC), 1)
        $(error No GCC or Clang compiler found)
    endif
endif

ifeq ($(IS_CLANG), 1)
    # For Clang: parse --version
    CC_VERSION_FULL := $(shell $(CC) --version | head -n1)
    CC_VERSION := $(shell echo "$(CC_VERSION_FULL)" | sed -n 's/.*clang version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
else
    # For GCC: -dumpversion
    CC_VERSION := $(shell $(CC) -dumpversion)
endif

CC_VERSION_MAJOR := $(shell echo $(CC_VERSION) | cut -f1 -d.)
CC_VERSION_MINOR := $(shell echo $(CC_VERSION) | cut -f2 -d.)
CC_NO_LESS_THAN_7 := $(shell [ $(CC_VERSION_MAJOR) -ge 7 ] && echo 1 || echo 0)
CC_NO_LESS_THAN_8 := $(shell [ $(CC_VERSION_MAJOR) -ge 8 ] && echo 1 || echo 0)
CC_NO_LESS_THAN_9 := $(shell [ $(CC_VERSION_MAJOR) -ge 9 ] && echo 1 || echo 0)
CC_NO_LESS_THAN_11 := $(shell [ $(CC_VERSION_MAJOR) -ge 11 ] && echo 1 || echo 0)
CC_NO_LESS_THAN_12 := $(shell [ $(CC_VERSION_MAJOR) -ge 12 ] && echo 1 || echo 0)
CC_LESS_THAN_15 := $(shell [ $(CC_VERSION_MAJOR) -lt 15 ] && echo 1 || echo 0)


ifeq ($(IS_GCC)$(CC_NO_LESS_THAN_12), 11)
    FORTIFY_SOURCE_VAL:= 3
else ifeq ($(IS_CLANG)$(CC_NO_LESS_THAN_9), 11)
    FORTIFY_SOURCE_VAL:= 3
else
    FORTIFY_SOURCE_VAL:= 2
endif


ifdef DEBUG
    COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG
    COMMON_FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG -DDEBUG_MODE=1
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL) -UDEBUG -DNDEBUG
endif

ifdef SE_SIM
    COMMON_FLAGS += -DSE_SIM
endif


ifeq ($(IS_GCC)$(CC_NO_LESS_THAN_8), 11)
    CET_FLAGS += -fcf-protection
else ifeq ($(IS_CLANG)$(CC_NO_LESS_THAN_7), 11)
    CET_FLAGS += -fcf-protection
endif

ifeq ($(IS_GCC)$(CC_NO_LESS_THAN_8), 11)
    COMMON_FLAGS += -fstack-clash-protection
else ifeq ($(IS_CLANG)$(CC_NO_LESS_THAN_11), 11)
    COMMON_FLAGS += -fstack-clash-protection
endif


COMMON_FLAGS += -ffunction-sections -fdata-sections -fstack-protector-strong -D_GLIBCXX_ASSERTIONS

# turn on compiler warnings as much as possible
COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
		-Waddress -Wsequence-point -Wformat-security \
		-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
		-Wcast-align -Wconversion -Wredundant-decls -Wimplicit-fallthrough

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

#
# --- ServTD Attestation: SDK source resolution ---
#
# SERVTD_ATTEST_SGX_REPO_ROOT_PATH points at the SGX repo root. This DCAP repo is
# normally nested there at <SGX_repo>/external/dcap_source, hence ../../.. .
# Historically the SGX SDK lived inside that repo as a plain sdk/ directory; it is
# now a git submodule, so it may be absent until initialized.
#
# SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH is the resolved SGX SDK source tree we build
# against. It defaults to <SGX_repo>/sdk but can be overridden to point at a
# standalone SDK checkout (in which case SERVTD_ATTEST_SGX_REPO_ROOT_PATH is unused).
SERVTD_ATTEST_SGX_REPO_ROOT_PATH ?= $(ROOT_DIR)/../../..
SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH ?= $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH)/sdk

# Layout heuristics (return the path on match, empty otherwise). They probe at
# DIFFERENT depths on purpose:
#  - servtd_is_sdk asks "is this a *usable* SDK source tree?", so it probes deep
#    into content that only exists once the tree is populated.
#  - servtd_is_sgx_repo asks "is this the SGX super-repo container?", so it probes
#    shallow: the bare presence of the sdk/ and psw/ entries.
servtd_is_sdk = $(if $(and $(wildcard $(1)/common/inc),$(wildcard $(1)/sdk/tlibcxx)),$(1))
servtd_is_sgx_repo = $(if $(and $(wildcard $(1)/sdk),$(wildcard $(1)/psw)),$(1))

# servtd_sdk_missing_objs asks a third question -- not "is this an SDK tree?" but "was it built with the *servtd_attest* flavor?" -- returning the loose-object dirs the link re-archives that are still absent from build/linux (empty => ready); a plain 'make sdk' archives then deletes these, so their presence uniquely marks a 'make servtd_attest' build.
servtd_sdk_objdirs := .tlibthread .tsafecrt .tsetjmp .tmm_rsrv .tlibcxx .cpprt
servtd_sdk_missing_objs = $(strip $(foreach d,$(servtd_sdk_objdirs),$(if $(wildcard $(1)/build/linux/$(d)/*.o),,$(d))))

# Resolve and validate the SDK source location.
ifdef SERVTD_ATTEST
ifeq ($(filter clean,$(MAKECMDGOALS)),)

# 1) If the configured SDK path already looks like a real SDK, use it as-is.
ifeq ($(call servtd_is_sdk,$(abspath $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH))),)

    # 2) Otherwise the SGX repo root must at least look like a real SGX repo.
    ifeq ($(call servtd_is_sgx_repo,$(abspath $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH))),)
        $(error servtd_attest: SGX SDK source not found at $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH) (=$(abspath $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH))). To build in SERVTD_ATTEST mode, ensure this (DCAP) repo is nested within the SGX repo at <SGX_repo>/external/dcap_source and that the SGX SDK sources are available at <SGX_repo>/sdk (submodule initialized), or set SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH=<SGX_SDK_source_path>)

    # 3) The SGX repo's sdk/ submodule, if initialized, is the SDK we want.
    else ifneq ($(call servtd_is_sdk,$(abspath $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH)/sdk)),)
        override SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH := $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH)/sdk

    # 4) SGX repo is present but its SDK submodule has not been initialized yet.
    else
        $(error servtd_attest: SGX SDK submodule not initialized at $(abspath $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH)/sdk). Please run 'make servtd_attest_preparation' in $(abspath $(SERVTD_ATTEST_SGX_REPO_ROOT_PATH)) to fetch the SGX SDK submodule, or set SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH=<SGX_SDK_source_path> if using detached SDK source.)
    endif

endif

# 5) SDK source resolved but not built with the servtd_attest flavor (its loose objects are missing; a plain 'make sdk' is not enough) -- fail early, not later as 'ar: .../.tlibthread/*.o: No such file' / 'cannot find -lsgx_tstdc'.
SERVTD_ATTEST_MISSING_OBJS := $(call servtd_sdk_missing_objs,$(abspath $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)))
ifneq ($(SERVTD_ATTEST_MISSING_OBJS),)
    $(error servtd_attest: SGX SDK at $(abspath $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)) is not built for servtd_attest (missing object directories $(SERVTD_ATTEST_MISSING_OBJS) under build/linux). Please run 'make servtd_attest' in that SDK tree first.)
endif

endif
endif
# Now resolve to absolute for all downstream use
override SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH := $(abspath $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH))
SERVTD_ATTEST_STD_INC_PATH := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/common/inc
SERVTD_ATTEST_STD_LIB_PATH := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/build/linux
SERVTD_ATTEST_LIBCXX_INC_PATH := $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/sdk/tlibcxx/include
SERVTD_ATTEST_CFLAGS := $(CFLAGS) -ffreestanding -nostdinc -fPIC -fvisibility=hidden -DSERVTD_ATTEST
SERVTD_ATTEST_CXXFLAGS := $(filter-out -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants,$(SERVTD_ATTEST_CFLAGS)) -nostdinc++
SERVTD_ATTEST_LDFLAGS := -nostdlib -nodefaultlibs -nostartfiles  \
                        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,--gc-sections -g
SERVTD_ATTEST_BUILD_DIR := $(BUILD_DIR)/servtd_attest
