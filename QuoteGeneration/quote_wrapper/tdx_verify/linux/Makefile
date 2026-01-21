#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## Basic Settings ########
TOP_DIR  = ../../..
QV_QVE_AE_DIR = $(TOP_DIR)/../ae/QvE
QV_QVE_INC_DIR = $(QV_QVE_AE_DIR)/Include
include $(TOP_DIR)/buildenv.mk

######## Tdx_Verify Settings ########
INCLUDE :=  -I. \
			-I$(SERVTD_ATTEST_STD_INC_PATH) \
			-I$(SERVTD_ATTEST_STD_INC_PATH)/tlibc \
			-I$(TOP_DIR)/quote_wrapper/servtd_attest/inc \
			-I$(TOP_DIR)/quote_wrapper/common/inc \
			-I$(TOP_DIR)/../QuoteVerification/dcap_quoteverify/inc \
			-I$(QV_QVE_INC_DIR)  \
			-I../../qgs_msg_lib/inc \
			-I../../../pce_wrapper/inc

Tdx_Verify_CFLAGS := $(INCLUDE) $(SERVTD_ATTEST_CFLAGS)
Tdx_Verify_CFLAGS += -Werror

Tdx_Verify_C_Files := ../tdx_verify.c $(TOP_DIR)/quote_wrapper/servtd_attest/servtd_utils.c
Tdx_Verify_Objects := $(Tdx_Verify_C_Files:.c=.o)


$(SERVTD_ATTEST_BUILD_DIR):
	@$(MKDIR) $@ 

$(Tdx_Verify_Objects): %.o: %.c
	$(CC) $(Tdx_Verify_CFLAGS) -c $< -o $@

.PHONY: all install_objs

all: install_objs

install_objs: $(Tdx_Verify_Objects) | $(SERVTD_ATTEST_BUILD_DIR)
	$(CP) $^ $(SERVTD_ATTEST_BUILD_DIR)

.PHONY: clean
clean:
	@rm -rf $(Tdx_Verify_Objects)
