#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

# If the value of _FORTIFY_SOURCE is greater than 2, use the value, else use 2.
FORTIFY_SOURCE_VAL:= $(lastword $(sort $(word 2,$(subst =, ,$(filter -D_FORTIFY_SOURCE=%,$(CFLAGS)))) 2))

ifeq ($(shell getconf LONG_BIT), 32)
        SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
        SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
        SGX_COMMON_CFLAGS := -m32
        SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
        SGX_COMMON_CFLAGS := -m64
        SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

# turn on stack protector for SDK
COMMON_FLAGS += -fstack-protector-strong

ifdef DEBUG
    COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL) -UDEBUG -DNDEBUG
endif


CET_FLAGS :=
CC_VERSION := $(shell $(CC) -dumpversion)
CC_NO_LESS_THAN_8 := $(shell expr $(CC_VERSION) \>\= "8")
ifeq ($(CC_NO_LESS_THAN_8), 1)
    CET_FLAGS += -fcf-protection
endif
COMMON_FLAGS += $(CET_FLAGS)

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

CXXFLAGS += -std=c++17



######## App Settings ########

App_Cpp_Files := $(wildcard App/linux/*.cpp App/*.cpp)
App_Include_Paths := -I$(SGX_SDK)/include -I ./App/inc
App_Include_Paths += -I ../../QuoteGeneration/common/inc/internal 
App_Include_Paths += -I ../../QuoteGeneration/ae/inc/internal -I ../SGXPlatformRegistration/include

App_C_Flags := $(COMMON_FLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack
App_Link_Flags +=  -lcurl -ldl -lpthread
ifeq ($(STANDALONE), 1)
	App_Link_Flags += '-Wl,-rpath,$$ORIGIN'
endif


App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := PCKIDRetrievalTool



.PHONY: all 

all: $(App_Name) 



######## App Objects ########

App/pce_u.c: 
	cd App && $(SGX_EDGER8R) --untrusted ../../../QuoteGeneration/ae/pce/pce.edl 
	@echo "GEN  =>  $@"

App/id_enclave_u.c: 
	cd App && $(SGX_EDGER8R) --untrusted ../../../QuoteGeneration/quote_wrapper/quote//id_enclave/id_enclave.edl
	echo "GEN  =>  $@"

App/id_enclave_u.o: App/id_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/pce_u.o: App/pce_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	echo "CXX  <=  $<"

$(App_Name): App/id_enclave_u.o App/pce_u.o $(App_Cpp_Objects)
	$(CXX) $^ $(App_Link_Flags) -o $@
	echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f $(App_Name)  $(App_Cpp_Objects) App/id_enclave_u.* App/pce_u.*
