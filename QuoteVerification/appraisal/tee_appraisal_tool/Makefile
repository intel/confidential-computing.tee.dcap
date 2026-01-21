#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

DCAP_TOPDIR = ../../..
include $(DCAP_TOPDIR)/QuoteGeneration/buildenv.mk

PREBUILD_OPENSSL_PATH := $(DCAP_TOPDIR)/prebuilt/openssl
FLAGS := -fpie -g -I./ \
		-I$(SGX_SDK)/include \
		-I$(DCAP_TOPDIR)/external/jwt-cpp/include \
		-I../../QVL/Src/ThirdParty/rapidjson/include \
		-I$(DCAP_TOPDIR)/QuoteGeneration/common/inc/internal/ \
		-I$(DCAP_TOPDIR)/QuoteGeneration/common/inc/internal/linux/ \
		-I$(PREBUILD_OPENSSL_PATH)/inc \
		-I../common

ifdef DEBUG
FLAGS +=  -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG
else
FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_ERROR
endif

CFLAGS += $(FLAGS)
CXXFLAGS += $(FLAGS)
Cpp_Files := $(wildcard *.cpp)
Cpp_Common_Obj_Files := file_util.o format_util.o
C_Obj_Files := se_trace.o

Obj_Files := $(Cpp_Files:.cpp=.o) $(C_Obj_Files) $(Cpp_Common_Obj_Files)
LDFLAGS += $(COMMON_LDFLAGS) -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 -pie -lcrypto -lpthread -ldl


TARGET_NAME := tee_appraisal_tool

.PHONY: all clean rebuild gen_key

all: $(TARGET_NAME) | $(BUILD_DIR)
	$(CP) $^ $|

$(BUILD_DIR):
	@$(MKDIR) $@

$(TARGET_NAME): $(Obj_Files)
	$(CXX) $(CXXFLAGS) -o $@ $(Obj_Files) $(LDFLAGS)

$(C_Obj_Files): %.o:$(DCAP_TOPDIR)/QuoteGeneration/common/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(Cpp_Common_Obj_Files): %.o:../common/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

gen_key:
	@openssl ecparam -name secp384r1 -genkey -noout -out ec_private.pem
	@echo "The private key file named ec_private.pem is generated successfully for test purposes."


clean:
	$(RM)  $(TARGET_NAME) *.o $(BUILD_DIR)/$(TARGET_NAME)

rebuild:
	$(MAKE) clean
	$(MAKE) all
