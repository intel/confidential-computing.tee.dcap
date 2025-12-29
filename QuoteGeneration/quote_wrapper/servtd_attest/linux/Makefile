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
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
######## Basic Settings ########
include ../../../../QuoteVerification/buildenv.mk
QG_ATTEST_DIR = $(DCAP_QG_DIR)/quote_wrapper/tdx_attest
QG_VERIFICATION_DIR = $(DCAP_QG_DIR)/quote_wrapper/tdx_verify
QV_QVE_DIR = $(DCAP_QV_DIR)/../ae/QvE
QV_QVE_INC_DIR = $(QV_QVE_DIR)/Include

######## SERVTD_ATTEST Settings ########
ifeq ($(DEBUG), 1)
        SGXSSL_TLIB = sgx_tsgxssld
        SGXSSL_TCRYPTO = sgx_tsgxssl_cryptod
else
        SGXSSL_TLIB = sgx_tsgxssl
        SGXSSL_TCRYPTO = sgx_tsgxssl_crypto
endif

RDRAND_DIR = $(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/external/rdrand
RDRAND_LIB_DIR = $(RDRAND_DIR)/src
RDRAND_MAKEFILE := $(RDRAND_LIB_DIR)/Makefile

Servtd_Attest_Include := -I$(SERVTD_ATTEST_STD_INC_PATH) \
						-I$(SERVTD_ATTEST_STD_INC_PATH)/tlibc \
						-I$(SERVTD_ATTEST_STD_INC_PATH)/../../sdk/tlibcxx/include \
						-I$(SERVTD_ATTEST_STD_INC_PATH)/internal \
						-I$(RDRAND_DIR) \
						-I$(DCAP_QG_DIR)/pce_wrapper/inc \
						-I$(DCAP_QG_DIR)/quote_wrapper/common/inc \
						-I$(QV_QVE_INC_DIR)

CPP_Files := ../servtd_attest_wrapper.cpp $(SERVTD_ATTEST_STD_INC_PATH)/../src/sgx_read_rand.cpp
CPP_Objects := $(CPP_Files:.cpp=.o)

ServTd_Attest_Static_Lib_Name := libservtd_attest.a

.PHONY: all
all: install_lib

install_lib: $(ServTd_Attest_Static_Lib_Name) | $(SERVTD_ATTEST_BUILD_DIR)
	@$(CP) $(ServTd_Attest_Static_Lib_Name) $|

$(SERVTD_ATTEST_BUILD_DIR):
	@$(MKDIR) $@ 

$(CPP_Objects): %.o: %.cpp
	$(CXX) $(Servtd_Attest_Include) $(SERVTD_ATTEST_CXXFLAGS) -fpermissive -c $< -o $@
	@echo "CXX  <=  $<"

submodule:
	$(MAKE) -C $(QG_ATTEST_DIR)/linux -f Makefile.servtd_attest
	$(MAKE) -C $(QG_VERIFICATION_DIR)/linux
	$(MAKE) -C $(QV_QVE_DIR) SERVTD_ATTEST=1 install_objs

$(RDRAND_MAKEFILE):
	@cd $(RDRAND_LIB_DIR) && ./configure CFLAGS=-fPIC && cd -

RDRAND: $(RDRAND_MAKEFILE)
	$(MAKE) -C $(RDRAND_LIB_DIR)

QGS_MSG_LIB:
	$(MAKE) -C ../../qgs_msg_lib/linux

$(ServTd_Attest_Static_Lib_Name): $(CPP_Objects) submodule RDRAND QGS_MSG_LIB
	@$(MKDIR) $(SERVTD_ATTEST_BUILD_DIR)/.libqgs_msg/ $(SERVTD_ATTEST_BUILD_DIR)/.librdrand/ $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl_crypto
	@$(RM) -f $(SERVTD_ATTEST_BUILD_DIR)/.libqgs_msg/* && cd $(SERVTD_ATTEST_BUILD_DIR)/.libqgs_msg && $(AR) x ../../../../quote_wrapper/qgs_msg_lib/linux/libqgs_msg.a && cd -
	@$(RM) -f $(SERVTD_ATTEST_BUILD_DIR)/.librdrand/* && cd $(SERVTD_ATTEST_BUILD_DIR)/.librdrand && $(AR) x ../../../../quote_wrapper/servtd_attest/linux/$(RDRAND_LIB_DIR)/librdrand.a && cd -
	@$(RM) -f $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl/* && cd $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl && $(AR) x ../../../../quote_wrapper/servtd_attest/linux/$(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a && cd -
	@$(RM) -f $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl_crypto/* && cd $(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl_crypto && $(AR) x ../../../../quote_wrapper/servtd_attest/linux/$(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a && cd -

	@$(RM) -f $@
	$(CP) $(SERVTD_ATTEST_STD_LIB_PATH)/libsgx_tstdc.a $@
	$(AR) qD $@ \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.tlibthread/*.o \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.tsafecrt/*.o \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.tsetjmp/*.o \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.tmm_rsrv/*.o \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.tlibcxx/*.o \
	$(SERVTD_ATTEST_STD_LIB_PATH)/.cpprt/*.o \
	$(SERVTD_ATTEST_BUILD_DIR)/.libqgs_msg/*.o \
	$(SERVTD_ATTEST_BUILD_DIR)/.librdrand/*.o \
	$(CPP_Objects) \
	$(SERVTD_ATTEST_BUILD_DIR)/*.o \
	$(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl/*.o \
	$(SERVTD_ATTEST_BUILD_DIR)/.tsgxssl_crypto/*.o \
	$(QVL_LIB_FILES:.cpp=.o) \
	$(QVL_PARSER_FILES:.cpp=.o)


.PHONY: clean
clean:
	$(MAKE) -C $(QG_ATTEST_DIR)/linux -f Makefile.servtd_attest clean
	$(MAKE) -C $(QG_VERIFICATION_DIR)/linux clean
	$(MAKE) -C $(QV_QVE_DIR) SERVTD_ATTEST=1 clean
	if [ -e "$(RDRAND_LIB_DIR)/Makefile" ]; then $(MAKE) -C $(RDRAND_LIB_DIR) clean; fi
	@rm -rf $(CPP_Objects)
	@rm -rf $(ServTd_Attest_Static_Lib_Name)
	@rm -rf $(SERVTD_ATTEST_BUILD_DIR)

# For Test
ServTd_Attest_Lib_Name := libservtd_attest.so

Servtd_Attest_External_Lib := -lqgs_msg -lsgx_tstdc -lsgx_tcxx -lrdrand -l$(SGXSSL_TCRYPTO)

Servtd_Attest_LDFLAGS := $(SERVTD_ATTEST_LDFLAGS) \
	-L$(SERVTD_ATTEST_STD_LIB_PATH) \
	-L$(SERVTD_ATTEST_LINUX_TRUNK_ROOT_PATH)/external/rdrand/lib/linux/x64 \
	-L$(SGXSSL_PACKAGE_PATH)/lib64/ \
	-L../../qgs_msg_lib/linux \
	-L$(RDRAND_LIB_DIR) \
	-Wl,-z,relro,-z,now,-z,noexecstack -fPIC \
	-Wl,--gc-sections \
	-Wl,--no-whole-archive \
	-Wl,--start-group $(Servtd_Attest_External_Lib) -Wl,--end-group \
	-Wl,-Map,servtd_attest.map \
	-Wl,--defsym,__ImageBase=0  \
	-Wl,--build-id		\
	-Wl,--version-script=servtd_attest_wrapper.lds -Wl,-rpath=. \
	-Wl,--whole-archive -l$(SGXSSL_TLIB)

$(ServTd_Attest_Lib_Name): $(CPP_Objects) submodule
	$(CXX) $(CPP_Objects) $(SERVTD_ATTEST_BUILD_DIR)/*.o $(QVL_LIB_FILES:.cpp=.o) $(QVL_PARSER_FILES:.cpp=.o) $(Servtd_Attest_LDFLAGS) -shared -o $@

test_app_static: $(ServTd_Attest_Static_Lib_Name)
	$(CXX) -fpie -pie -I../inc -I../../common/inc -I../../../../../../common/inc -I$(QV_QVE_INC_DIR) ../test_servtd_attest.cpp -L. -Wl,-Bstatic -lservtd_attest -Wl,-Bdynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -g -O0 -ggdb -o $@

test_app: $(ServTd_Attest_Lib_Name)
	$(CXX) -fpie -pie -I../inc -I../../common/inc -I../../../../../../common/inc -I$(QV_QVE_INC_DIR) ../test_servtd_attest.cpp -L. -lservtd_attest -Wl,-rpath=./ -g -O0 -ggdb -fpermissive -o $@

test_clean:
	@rm -rf $(ServTd_Attest_Lib_Name) *.map
	@rm test_app_static test_app
