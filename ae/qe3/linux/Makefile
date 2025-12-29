#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


TOP_DIR := ../../../QuoteGeneration
MITIGATION-CVE-2020-0551 := LOAD
include $(TOP_DIR)/../ae/dep/buildenv.mk

AENAME := qe3
SONAME := $(AENAME).so
SIGNED_QE3_NAME := libsgx_$(AENAME)$(if $(FIPS),-fips).signed.so
QE3_CONFIG_FILE := config$(if $(FIPS),.fips).xml
QE3_KEY_FILE := ../../dep/dcap_ae_test_key.pem

TCRYPTO_LIB_NAME := sgx_tcrypto

INCLUDE := -I$(SGX_SDK)/include                        \
           -I$(SGX_SDK)/include/tlibc                  \
           -I$(SGX_SDK)/include/libcxx                 \
           -I$(COMMON_DIR)/inc/internal                \
           -I$(COMMON_DIR)/inc/internal/linux          \
           -I$(TOP_DIR)/ae/inc/internal                \
           -I$(TOP_DIR)/quote_wrapper/quote/inc                                 \
           -I$(TOP_DIR)/quote_wrapper/common/inc       \
           -I$(TOP_DIR)/pce_wrapper/inc               \
           -I..                                        \
           -I.

EXTERNAL_LIB = $(EXTERNAL_LIB_NO_CRYPTO) -lsgx_tcxx -l$(TCRYPTO_LIB_NAME)

vpath %.cpp .. .
SRC := quoting_enclave_3.cpp

OBJ := $(SRC:.cpp=.o)
OBJS := $(sort $(OBJ) version.o)

.PHONY: all
all: $(SONAME) $(SIGNED_QE3_NAME)

$(SONAME): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) -nostdlib -nodefaultlibs -nostartfiles -Wl,-soname=libsgx_${AENAME}.signed.so.$(call get_major_version,QE3_VERSION) $(LDTFLAGS) -fno-exceptions -fno-rtti
	$(STRIP) --strip-unneeded --remove-section=.comment --remove-section=.note $@

$(SIGNED_QE3_NAME): $(SONAME) $(QE3_CONFIG_FILE) $(QE3_KEY_FILE)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(QE3_KEY_FILE) -enclave $< -out $@ -config $(QE3_CONFIG_FILE)

quoting_enclave_3.o: $(AENAME)_t.c

%.o:%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(DEFINES) -fno-exceptions -c $< -o $@

$(AENAME)_t.c: ../$(AENAME).edl
	@$(SGX_EDGER8R) --trusted $<

.PHONY: clean
clean:
	@$(RM) *.o
	@$(RM) *.so
	@$(RM) *.map
	@$(RM) *_t.*
	@$(RM) *.signed.so

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
