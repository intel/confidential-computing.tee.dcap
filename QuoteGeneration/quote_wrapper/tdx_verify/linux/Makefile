#
# Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# ( OF THE POSSIBILITY OF SUCH DAMAGE.
#
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

Tdx_Verify_CFLAGS := $(INCLUDE)	$(SERVTD_ATTEST_CFLAGS)

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
