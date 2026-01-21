#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


ENV := $(strip $(wildcard $(TOP_DIR)/buildenv.mk))

ifeq ($(ENV),)
    $(error "Can't find $(TOP_DIR)/buildenv.mk")
endif

include $(TOP_DIR)/buildenv.mk

WORK_DIR := $(shell pwd)

EXTERNAL_LIB_NO_CRYPTO = -lsgx_tstdc

URTSLIB := -lsgx_urts
TRTSLIB := -lsgx_trts
EXTERNAL_LIB_NO_CRYPTO += -lsgx_tservice

EXTERNAL_LIB   = $(EXTERNAL_LIB_NO_CRYPTO) -lsgx_tcrypto

CXXFLAGS  += $(ENCLAVE_CXXFLAGS) -Werror
CFLAGS    += $(ENCLAVE_CFLAGS) -Werror

LDTFLAGS  = -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive $(TRTSLIB) -Wl,--no-whole-archive \
            -Wl,--start-group $(EXTERNAL_LIB) -Wl,--end-group -Wl,--build-id            \
            -Wl,--version-script=$(WORK_DIR)/enclave.lds $(ENCLAVE_LDFLAGS)

LDTFLAGS_NO_CRYPTO = -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive $(TRTSLIB) -Wl,--no-whole-archive \
            -Wl,--start-group $(EXTERNAL_LIB_NO_CRYPTO) -Wl,--end-group                    \
            -Wl,--version-script=$(WORK_DIR)/enclave.lds $(ENCLAVE_LDFLAGS)

LDTFLAGS += -Wl,-Map=out.map -Wl,--undefined=version -Wl,--gc-sections
LDTFLAGS_NO_CRYPTO += -Wl,-Map=out.map -Wl,--undefined=version -Wl,--gc-sections


vpath %.cpp $(COMMON_DIR)/src:$(LINUX_PSW_DIR)/../ae/dep/common

.PHONY : version

version.o: $(TOP_DIR)/../ae/dep/common/version.cpp
	$(CXX) $(CXXFLAGS) -fno-exceptions -fno-rtti $(INCLUDE) $(DEFINES) -c $(TOP_DIR)/../ae/dep/common/version.cpp -o $@
