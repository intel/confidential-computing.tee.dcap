#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

CUR_MKFILE:= $(lastword $(MAKEFILE_LIST))
TOPDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

include $(TOPDIR)/QuoteGeneration/version.mk

ifeq ($(BUILD_SAMPLECODE), 1)
# Avoid parallel build for SGXPlatformRegistration to avoid build conflicts when ThirdParty target (from other Makefile(s))
.NOTPARALLEL: SGXPlatformRegistration PckClientTool SampleCode
.PHONY: all clean rebuild QuoteGeneration QuoteVerification PCKCertSelection PCKRetrievalTool SGXPlatformRegistration PckClientTool WinPle WinPleIntel SampleCode PoeTools
all: QuoteGeneration QuoteVerification PCKCertSelection PCKRetrievalTool SGXPlatformRegistration PckClientTool WinPle WinPleIntel ThirdParty SampleCode PoeTools
else
# Avoid parallel build for SGXPlatformRegistration to avoid build conflicts when ThirdParty target (from other Makefile(s))
.NOTPARALLEL: SGXPlatformRegistration PckClientTool
.PHONY: all clean rebuild QuoteGeneration QuoteVerification PCKCertSelection PCKRetrievalTool SGXPlatformRegistration PckClientTool WinPle WinPleIntel PoeTools
all: QuoteGeneration QuoteVerification PCKCertSelection PCKRetrievalTool SGXPlatformRegistration PckClientTool WinPle WinPleIntel ThirdParty PoeTools
endif

ThirdParty:
	+$(MAKE) -C external

QuoteGeneration: QuoteVerification
	+$(MAKE) -C QuoteGeneration

QuoteVerification:
	+$(MAKE) -C QuoteVerification

PCKCertSelection:
	+$(MAKE) -C tools/PCKCertSelection

PCKRetrievalTool: QuoteGeneration
	+$(MAKE) -C tools/PCKRetrievalTool

SGXPlatformRegistration: ThirdParty
	+$(MAKE) -C tools/SGXPlatformRegistration

PckClientTool:
	+$(MAKE) -C tools/PcsClientTool

PoeTools:
	+$(MAKE) -C tools/PoeTools POE_VERSION=$(DCAP_VER)

.PHONY: PoeTools_deb PoeTools_rpm
PoeTools_deb:
	+$(MAKE) -C tools/PoeTools deb POE_VERSION=$(DCAP_VER)

PoeTools_rpm:
	+$(MAKE) -C tools/PoeTools rpm POE_VERSION=$(DCAP_VER)

WinPle:
	+$(MAKE) -C driver/win/PLE

WinPleIntel:
	+$(MAKE) -C driver/win/PLE INTEL_SIGNED=1

SampleCode: QuoteGeneration
	export DCAP_LINUX_BUILD_DIR=$(TOPDIR)/QuoteGeneration/build/linux/ && $(MAKE) -C SampleCode/QuoteGenerationSample/
	export DCAP_LINUX_BUILD_DIR=$(TOPDIR)/QuoteGeneration/build/linux/ && $(MAKE) -C SampleCode/QuoteVerificationSample/

clean:
	+$(MAKE) -C external clean
	+$(MAKE) -C QuoteGeneration clean
	+$(MAKE) -C QuoteVerification clean
	+$(MAKE) -C tools/PCKCertSelection clean
	+$(MAKE) -C tools/PCKRetrievalTool clean
	+$(MAKE) -C tools/SGXPlatformRegistration clean
	+$(MAKE) -C tools/PcsClientTool clean
	+$(MAKE) -C tools/PoeTools clean
	+$(MAKE) -C driver/win/PLE clean
	+$(MAKE) -C driver/win/PLE INTEL_SIGNED=1 clean

rebuild:
	+$(MAKE) -f $(CUR_MKFILE) clean
	+$(MAKE) -f $(CUR_MKFILE) all

test:
	+$(MAKE) -C tools/PcsClientTool test
