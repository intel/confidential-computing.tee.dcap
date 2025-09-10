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

include ../buildenv.mk


ifeq ($(DEBUG), 1)
        SGXSSL_TLIB = sgx_tsgxssld
        SGXSSL_TCRYPTO = sgx_tsgxssl_cryptod
else
        SGXSSL_TLIB = sgx_tsgxssl
        SGXSSL_TCRYPTO = sgx_tsgxssl_crypto
endif

DCAP_QPL_DIR := $(DCAP_QG_DIR)/qpl
JWT_CPP_DIR := $(DCAP_EXTERNAL_DIR)/jwt-cpp

QVL_LIB_OBJS := $(QVL_LIB_FILES:.cpp=.o)
QVL_PARSER_OBJS := $(QVL_PARSER_FILES:.cpp=.o)
ifndef SERVTD_ATTEST
QVL_LIB_COMMON_OBJS := Enclave/sgx_base64.o Enclave/ec_key.o
endif

######## Enclave Settings ########

ifeq ($(MODE), SIM)
	TRTS_NAME := sgx_trts_sim
	SERVICE_NAME := sgx_tservice_sim
else
ifndef SERVTD_ATTEST
	TRTS_NAME := sgx_trts
	SERVICE_NAME := sgx_tservice
endif
endif
CRYPTO_LIB_NAME := sgx_tcrypto

QVE_FILES := Enclave/qve.cpp
ifdef SERVTD_ATTEST
	QVE_FILES += Enclave/servtd_qve_utils.cpp
	QVE_C_FILES := $(DCAP_QG_DIR)/quote_wrapper/servtd_attest/servtd_utils.c

QVE_OBJS := $(QVE_FILES:.cpp=.o) $(QVE_C_FILES:.c=.o)
else
QVE_OBJS := $(QVE_FILES:.cpp=.o)
endif

ifdef SERVTD_ATTEST
	QVE_NAME := libqve.so
	QVE_STATIC_NAME := libqve.a
else
	QVE_NAME := qve.so
endif
SIGNED_QVE_NAME := libsgx_qve$(if $(FIPS),-fips).signed.so
QVE_CONFIG_FILE := Enclave/linux/config$(if $(FIPS),.fips).xml

QVE_VER:= $(shell awk '$$2 ~ /QVE_VERSION/ { print substr($$3, 2, length($$3) - 2); }' $(DCAP_QG_DIR)/common/inc/internal/se_version.h)


ENCLAVE_INC_PATH := $(COMMON_INCLUDE) -IInclude -IEnclave -I$(DCAP_QG_DIR)/quote_wrapper/common/inc -I$(DCAP_QG_DIR)/pce_wrapper/inc -I$(DCAP_QPL_DIR)/inc -I$(DCAP_QV_DIR)/appraisal/common
ifdef SERVTD_ATTEST
	ENCLAVE_INC_PATH += -I$(DCAP_QV_DIR)/dcap_quoteverify/inc -I$(DCAP_QG_DIR)/quote_wrapper/tdx_verify -I$(DCAP_QG_DIR)/quote_wrapper/servtd_attest/inc -I../../prebuilt/openssl/inc \
			    -I$(DCAP_QG_DIR)/quote_wrapper/servtd_attest/inc
ifeq ($(DEBUG), 1)
	ENCLAVE_CFLAGS += -O0 -ggdb -g
endif
endif

ifdef SERVTD_ATTEST
ENCLAVE_CFLAGS += $(ENCLAVE_INC_PATH) -fPIC -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL)
else
ENCLAVE_CFLAGS += $(ENCLAVE_INC_PATH) -fpie -fpic -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL)
endif
ifneq ($(DEBUG), 1)
    ENCLAVE_CFLAGS += -ffunction-sections -fdata-sections
endif
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	ENCLAVE_CFLAGS += -fstack-protector
else
	ENCLAVE_CFLAGS += -fstack-protector-strong
endif

ENCLAVE_CXXFLAGS += $(ENCLAVE_CFLAGS) -std=c++17 -DSGX_TRUSTED -DSGX_JWT -DPICOJSON_USE_LOCALE=0


ifdef SERVTD_ATTEST
ENCLAVE_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack -shared \
				   -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
				   -L$(SERVTD_ATTEST_STD_LIB_PATH) -L$(SGXSSL_PACKAGE_PATH)/lib64 \
				   -Wl,--whole-archive -l$(SGXSSL_TLIB) -Wl,--no-whole-archive \
				   -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(SGXSSL_TCRYPTO) -l$(CRYPTO_LIB_NAME) -Wl,--end-group \
				   -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,--gc-sections \
				   -Wl,--export-dynamic -Wl,-Map,qve.map \
				   -Wl,--defsym,__ImageBase=0  \
				   -Wl,--build-id		\
				   -Wl,-Bdynamic -L$(SERVTD_ATTEST_BUILD_DIR) -ltdx_verify \
				   -Wl,-L/lib/x86_64-linux-gnu/ -lc \
				   -Wl,--version-script=Enclave/linux/qve_migration.lds
else
ENCLAVE_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack -fPIC \
				   -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
				   -L$(SGX_LIBRARY_PATH) -L$(SGXSSL_PACKAGE_PATH)/lib64 \
				   -Wl,--whole-archive -l$(TRTS_NAME) $(if $(FIPS),-lsgx_ossl_fips) -l$(SGXSSL_TLIB) -Wl,--no-whole-archive \
				   -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -l$(SGXSSL_TCRYPTO) -l$(CRYPTO_LIB_NAME) \
				   -l$(SERVICE_NAME) -Wl,--end-group \
				   -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,--gc-sections \
				   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,-Map,qve.map \
				   -Wl,--defsym,__ImageBase=0  \
				   -Wl,--build-id		\
				   -Wl,--version-script=Enclave/linux/qve.lds
endif


.PHONY: all PREPARE_SGX_SSL prepare

prepare:
ifeq ($(shell grep -c SGX_JWT $(JWT_CPP_DIR)/include/jwt-cpp/jwt.h), 0)
	cd $(JWT_CPP_DIR) && patch -p1 <../0001-Add-a-macro-to-disable-time-support-in-jwt-for-SGX.patch && cd -
endif

ifdef SERVTD_ATTEST
all: $(QVE_NAME) PREPARE_SGX_SSL
else
all: PREPARE_SGX_SSL prepare
	make install_lib
endif

$(BUILD_DIR):
	@$(MKDIR) $@

PREPARE_SGXSSL := ../prepare_sgxssl.sh
SGXSSL_HEADER_CHECK := $(SGXSSL_PACKAGE_PATH)/include/openssl/opensslconf.h
PREPARE_SGX_SSL:
ifdef SERVTD_ATTEST
	@test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a && test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a && test -f $(SGXSSL_HEADER_CHECK) || $(PREPARE_SGXSSL) SERVTD_ATTEST
else
	@test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a && test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a && test -f $(SGXSSL_HEADER_CHECK) || $(PREPARE_SGXSSL) $(if $(FIPS),FIPS)
endif

$(SGXSSL_HEADER_CHECK): PREPARE_SGX_SSL

install_lib: $(SIGNED_QVE_NAME) | $(BUILD_DIR)
	 @$(CP) $(SIGNED_QVE_NAME) $(BUILD_DIR)

######## Enclave Objects ########

ifndef SERVTD_ATTEST
Enclave/sgx_base64.o: $(DCAP_QPL_DIR)/sgx_base64.cpp
	@$(CXX) $(ENCLAVE_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
	@echo "CXX  <=  $<"
Enclave/ec_key.o: $(DCAP_QV_DIR)/appraisal/common/ec_key.cpp
	@$(CXX) $(ENCLAVE_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
	@echo "CXX  <=  $<"
endif

$(QVL_LIB_OBJS): %.o: %.cpp $(SGXSSL_HEADER_CHECK)
ifdef SERVTD_ATTEST
	@$(CXX) -DSERVTD_ATTEST $(ENCLAVE_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
else
	@$(CXX) $(ENCLAVE_CXXFLAGS) $(QVL_LIB_INC) -c $< -o $@
endif
	@echo "CXX  <=  $<"

$(QVL_PARSER_OBJS): %.o: %.cpp $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(ENCLAVE_CXXFLAGS) $(QVL_PARSER_INC) -c $< -o $@
	@echo "CXX  <=  $<"

ifndef SERVTD_ATTEST
Enclave/qve_t.h: Enclave/qve.edl $(SGX_EDGER8R)
	$(SGX_EDGER8R) --trusted $< --trusted-dir $(dir $@) $(addprefix --search-path ,$(SGX_SDK)/include $(addprefix $(SGXSSL_PACKAGE_PATH)/include/,. $(if $(FIPS),,no)filefunc))
	@echo "GEN  =>  $@"

Enclave/qve_t.c: Enclave/qve_t.h

Enclave/qve_t.o: Enclave/qve_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
endif

ifdef SERVTD_ATTEST
Enclave/%.o: Enclave/%.cpp $(SGXSSL_HEADER_CHECK)
else
Enclave/%.o: Enclave/%.cpp Enclave/qve_t.h $(SGXSSL_HEADER_CHECK)
endif
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(ENCLAVE_CXXFLAGS) $(if $(FIPS),-DSGXSSL_FIPS) $(QVL_LIB_INC) -I$(QVL_SRC_PATH) -c $< -o $@
	@echo "CXX  <=  $<"

ifdef SERVTD_ATTEST
$(QVE_C_FILES:.c=.o):$(QVE_C_FILES)
	$(CC) $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) -c $< -o $@
endif

ifdef SERVTD_ATTEST
.PHONY: install_objs
install_objs: $(QVE_OBJS) $(QVL_PARSER_OBJS) $(QVL_LIB_OBJS)
	if [ ! -d "$(SERVTD_ATTEST_BUILD_DIR)" ]; then mkdir -p '$(SERVTD_ATTEST_BUILD_DIRs)';fi
	$(CP) $(QVE_OBJS) $(SERVTD_ATTEST_BUILD_DIR)
	mkdir -p $(SERVTD_ATTEST_BUILD_DIR)/QVL_PARSER $(SERVTD_ATTEST_BUILD_DIR)/QVL_LIB
	$(CP) $(QVL_PARSER_OBJS) $(SERVTD_ATTEST_BUILD_DIR)/QVL_PARSER
	$(CP) $(QVL_LIB_OBJS) $(SERVTD_ATTEST_BUILD_DIR)/QVL_LIB
endif

ifdef SERVTD_ATTEST
$(QVE_NAME): $(QVE_OBJS) $(QVL_PARSER_OBJS) $(QVL_LIB_OBJS)
	if [ ! -d "$(SERVTD_ATTEST_BUILD_DIR)" ]; then mkdir -p '$(SERVTD_ATTEST_BUILD_DIR)';fi
	@$(CXX) $^ -shared -o $(SERVTD_ATTEST_BUILD_DIR)/$@ $(ENCLAVE_LDFLAGS) $(ENCLAVE_CXXFLAGS)
else
$(QVE_NAME): $(QVE_OBJS) Enclave/qve_t.o $(QVL_PARSER_OBJS) $(QVL_LIB_OBJS) $(QVL_LIB_COMMON_OBJS)
	@$(CXX) $^ -o $@ $(ENCLAVE_LDFLAGS) $(ENCLAVE_CXXFLAGS) -Wl,-soname=${SIGNED_QVE_NAME}.$(call get_major_version,QVE_VERSION)
	$(STRIP) --strip-unneeded --remove-section=.comment --remove-section=.note $@
endif
	@echo "LINK =>  $@"

$(SIGNED_QVE_NAME): $(QVE_NAME) $(QVE_CONFIG_FILE)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/qve_test_key.pem -enclave $< -out $@ -config $(QVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

print-% : ; @echo $* = $($*)

.PHONY: clean SGXSSL_clean

clean:
	@echo "Cleaning objects"
	@rm -rf $(QVL_PARSER_OBJS) $(QVL_LIB_OBJS) $(QVL_LIB_COMMON_OBJS)
	@rm -f .config_* $(QVE_NAME) $(SIGNED_QVE_NAME) Enclave/str_to_time.o Enclave/bionic_localtime.o $(QVE_OBJS) Enclave/qve_t.* Enclave/*.d
	@rm -f *.map
	@rm -f $(SERVTD_ATTEST_BUILD_DIR)/$(QVE_NAME)
	@rm -f $(BUILD_DIR)/$(SIGNED_QVE_NAME)

SGXSSL_clean:
	@echo "Cleaning sgxssl"
	@rm -rf ../sgxssl/
