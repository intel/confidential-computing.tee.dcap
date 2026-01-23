#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../../buildenv.mk

INSTALL_PATH 		?= /usr/lib/x86_64-linux-gnu
QVE_SRC_PATH		:= ../../../ae/QvE
DCAP_QPL_DIR := $(DCAP_QG_DIR)/qpl

QVL_LIB_INC		+= -I$(PREBUILD_OPENSSL_PATH)/inc -I$(QVE_SRC_PATH)/Include
QVL_PARSER_INC  += -I$(PREBUILD_OPENSSL_PATH)/inc
QVL_VERIFY_INC	:= -I$(QVE_SRC_PATH)/Include \
                   -I../inc \
                   -I$(DCAP_QG_DIR)/quote_wrapper/common/inc \
                   -I$(SGX_SDK)/include \
                   -I$(DCAP_QG_DIR)/common/inc/internal \
                   -I$(DCAP_QG_DIR)/common/inc/internal/linux \
                   -I$(DCAP_QG_DIR)/pce_wrapper/inc \
                   -I$(PREBUILD_OPENSSL_PATH)/inc \
                   $(QVL_LIB_INC) \
                   -I$(DCAP_QPL_DIR)/inc \
                   -I$(DCAP_QV_DIR)/appraisal/common \
                   -I$(DCAP_QV_DIR)/appraisal/qal

QPL_BASE64_CPP_DEP	:= $(DCAP_QPL_DIR)/sgx_base64.d

SGX_COMMON_CFLAGS	+= $(CFLAGS) -g -fPIC -Wno-attributes -USGX_TRUSTED
SGX_COMMON_CXXFLAGS	+= $(CXXFLAGS) -g -fPIC -USGX_TRUSTED

ifeq ($(CC_NO_LESS_THAN_8), 1)
    SGX_COMMON_CFLAGS += -fcf-protection=none
    SGX_COMMON_CXXFLAGS += -fcf-protection=none
endif

QVL_LIB_OBJS := $(QVL_LIB_FILES:.cpp=_untrusted.o)
QVL_PARSER_OBJS := $(QVL_PARSER_FILES:.cpp=_untrusted.o)

QVL_LIB := sgx_dcap_qvl_parser
QVL_PARSER := sgx_dcap_qvl_attestation
QVL_LIB_NAME := lib$(QVL_LIB).a
QVL_PARSER_NAME := lib$(QVL_PARSER).a

LDUFLAGS	:= -pthread -ldl -L. -l$(QVL_LIB) -l$(QVL_PARSER) $(COMMON_LDFLAGS) -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 -lcrypto
LDUFLAGS	+= -Wl,--version-script=sgx_dcap_quoteverify.lds -Wl,--gc-sections

QVL_VERIFY_CPP_SRCS := $(wildcard ../*.cpp) $(wildcard *.cpp)
QVL_VERIFY_C_SRCS := $(COMMON_DIR)/src/se_trace.c $(COMMON_DIR)/src/se_thread.c
QVL_VERIFY_C_SRCS += qve_u.c

QVL_VERIFY_CPP_OBJS := $(QVL_VERIFY_CPP_SRCS:.cpp=.o)
QVL_VERIFY_CPP_OBJS_STATIC := $(QVL_VERIFY_CPP_SRCS:.cpp=_s.o)
QVL_VERIFY_C_OBJS := $(QVL_VERIFY_C_SRCS:.c=.o)
QVL_LIB_COMMON_OBJS := sgx_base64.o ec_key.o

QVE_CPP_SRC ?= $(QVE_SRC_PATH)/qve/qve.cpp
QVE_CPP_OBJ ?= $(QVE_SRC_PATH)/qve/untrusted_qve.o
QVE_LOGIC_CPP_SRC ?= $(QVE_SRC_PATH)/qve/qve_logic.cpp
QVE_LOGIC_CPP_OBJ ?= $(QVE_SRC_PATH)/qve/untrusted_qve_logic.o

QVL_VERIFY_LIB_NAME := libsgx_dcap_quoteverify
QVL_VERIFY_LIB_NAME_Dynamic := $(QVL_VERIFY_LIB_NAME).so
QVL_VERIFY_LIB_NAME_Dynamic_Full := $(QVL_VERIFY_LIB_NAME_Dynamic).$(SGX_VER)
QVL_VERIFY_LIB_NAME_Dynamic_Major := $(QVL_VERIFY_LIB_NAME_Dynamic).$(SGX_MAJOR_VER)
QVL_VERIFY_LIB_NAME_Static := $(QVL_VERIFY_LIB_NAME).a

QAL_APPRAISAL_DIR := $(DCAP_QV_DIR)/appraisal/qal
QAL_APPRAISAL_CPP_SRCS :=$(wildcard $(QAL_APPRAISAL_DIR)/*.cpp)
QAL_CPP_OBJS := $(QAL_APPRAISAL_CPP_SRCS:.cpp=.o) $(QAL_APPRAISAL_DIR)/file_util.o $(QAL_APPRAISAL_DIR)/format_util.o
QAL_C_OBJS := $(QAL_APPRAISAL_DIR)/qae_u.o
QAL_OBJS := $(sort $(QAL_CPP_OBJS) $(QAL_C_OBJS))
QAL_Static_Lib_Name := libdcap_qal.a
WARM_Lib_Path := $(DCAP_EXTERNAL_DIR)/wasm-micro-runtime/product-mini/platforms/linux/build/
LDUFLAGS += -L$(WARM_Lib_Path) -lvmlib
ifeq ($(DEBUG), 1)
	SGX_COMMON_CFLAGS += -fsanitize=undefined
	SGX_COMMON_CXXFLAGS += -fsanitize=undefined
	LDUFLAGS += -fsanitize=undefined
endif

.PHONY: all run


all: install_lib

$(BUILD_DIR):
	@$(MKDIR) $@

install_lib: $(QVL_VERIFY_LIB_NAME_Dynamic) | $(BUILD_DIR)
	@$(CP) $(QVL_VERIFY_LIB_NAME_Dynamic) $|/$(QVL_VERIFY_LIB_NAME_Dynamic_Full)
	@$(LN) $(QVL_VERIFY_LIB_NAME_Dynamic_Full) $|/$(QVL_VERIFY_LIB_NAME_Dynamic_Major)
	@$(LN) $(QVL_VERIFY_LIB_NAME_Dynamic_Major) $|/$(QVL_VERIFY_LIB_NAME_Dynamic)
	$(CP) $(PREBUILD_PATH)/opa_bin/policy.wasm $|/tee_appraisal_policy.wasm

ifeq ($(GEN_STATIC),1)
	@$(MAKE) $(QVL_VERIFY_LIB_NAME_Static)
	@$(CP) $(QVL_VERIFY_LIB_NAME_Static) $|
endif


run: all

######## QVL Library Objects ########

qve_u.h: $(QVE_SRC_PATH)/qve/qve.edl $(SGX_EDGER8R)
	@$(SGX_EDGER8R) --untrusted $< $(addprefix --search-path ,$(QVE_SRC_PATH)/qve $(SGX_SDK)/include $(addprefix $(SGXSSL_PACKAGE_PATH)/include/,. $(if $(FIPS),,no)filefunc))
	@echo "GEN  =>  $@"

qve_u.c : qve_u.h

$(QVL_VERIFY_C_OBJS): %.o: %.c qve_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CC  <=  $<"

-include $(QPL_BASE64_CPP_DEP)

sgx_base64.o: $(DCAP_QPL_DIR)/sgx_base64.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

ec_key.o: $(DCAP_QV_DIR)/appraisal/common/ec_key.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_VERIFY_CPP_OBJS): %.o: %.cpp qve_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_VERIFY_CPP_OBJS_STATIC): %_s.o: %.cpp qve_u.h
	@$(CXX) -DGEN_STATIC $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVE_CPP_OBJ): $(QVE_CPP_SRC)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $(QVE_CPP_OBJ)
	@echo "CXX  <=  $<"

$(QVE_LOGIC_CPP_OBJ): $(QVE_LOGIC_CPP_SRC)
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_INC) -c $< -o $(QVE_LOGIC_CPP_OBJ)
	@echo "CXX  <=  $<"

$(QVL_LIB_OBJS): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_PARSER_OBJS): %_untrusted.o: %.cpp
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_PARSER_INC) -c $< -o $@
	@echo "CXX  <=  $<"

$(QVL_LIB_NAME): $(QVL_LIB_OBJS)
	@$(AR) rsD $(QVL_LIB_NAME) $(QVL_LIB_OBJS)

$(QVL_PARSER_NAME): $(QVL_PARSER_OBJS)
	@$(AR) rsD $(QVL_PARSER_NAME) $(QVL_PARSER_OBJS)


$(QVL_VERIFY_LIB_NAME_Dynamic): $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVE_LOGIC_CPP_OBJ) $(QVL_LIB_NAME) $(QVL_PARSER_NAME) $(QVL_LIB_COMMON_OBJS) qal
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVE_LOGIC_CPP_OBJ) $(QAL_OBJS) $(QVL_LIB_COMMON_OBJS) -L$(SGXSSL_PACKAGE_PATH)/lib64 -lsgx_usgxssl -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(LDUFLAGS) -o $@
	@ln -sf $(QVL_VERIFY_LIB_NAME_Dynamic) $(QVL_VERIFY_LIB_NAME_Dynamic).1

$(QVL_VERIFY_LIB_NAME_Static): $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVE_LOGIC_CPP_OBJ) $(QVL_LIB_NAME) $(QVL_PARSER_NAME) $(QVL_LIB_COMMON_OBJS)
	@$(AR) rsD $(QVL_VERIFY_LIB_NAME_Static) $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVE_CPP_OBJ) $(QVE_LOGIC_CPP_OBJ) $(QVL_LIB_COMMON_OBJS)

.PHONY: qal
qal:
	$(MAKE) -C $(QAL_APPRAISAL_DIR) $(QAL_Static_Lib_Name)

force_look:
	true

install: $(QVL_VERIFY_LIB_NAME_Dynamic)
	$(CP) $(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)
	ln -sf $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic).1

uninstall:
	rm -f $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic) $(INSTALL_PATH)/$(QVL_VERIFY_LIB_NAME_Dynamic).1

.PHONY: clean

clean:
	@$(RM) *_u.* $(QVL_VERIFY_CPP_OBJS) $(QVL_VERIFY_CPP_OBJS_STATIC) $(QVL_VERIFY_C_OBJS) $(QVL_VERIFY_LIB_NAME_Dynamic) $(QVL_VERIFY_LIB_NAME_Static)
	@$(RM) $(addprefix $(BUILD_DIR)/,$(QVL_VERIFY_LIB_NAME_Dynamic) $(QVL_VERIFY_LIB_NAME_Dynamic_Full) $(QVL_VERIFY_LIB_NAME_Dynamic_Major) tee_appraisal_policy.wasm)
	@$(RM) $(QVL_LIB_OBJS) $(QVL_PARSER_OBJS) $(QVL_LIB_COMMON_OBJS)
	@$(RM) $(QVL_LIB_NAME) $(QVL_PARSER_NAME)
	@$(RM) *.1
	@$(RM) $(QVE_CPP_OBJ) $(QVE_LOGIC_CPP_OBJ)
	@$(MAKE) -C $(QAL_APPRAISAL_DIR) clean
