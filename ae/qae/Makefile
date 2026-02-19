#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


# include QuoteVerification buildenv.mk
include ../../QuoteVerification/buildenv.mk

ifneq ($(SGX_MODE), HW)
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
else
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

ifeq ($(DEBUG), 1)
    SGX_DEBUG = 1
endif
ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -g
else
    SGX_COMMON_FLAGS += -O2
endif


SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

WARM_Top_Path = $(DCAP_EXTERNAL_DIR)/wasm-micro-runtime
WARM_Lib_SGX_Path = $(WARM_Top_Path)/product-mini/platforms/linux-sgx
WARM_Lib_SGX_Build = $(WARM_Lib_SGX_Path)/build
JWT_CPP_Path = $(DCAP_EXTERNAL_DIR)/jwt-cpp
RAPIDJSON_DIR =  $(DCAP_QV_DIR)/QVL/Src/ThirdParty/rapidjson/include
SGXSSL_PACKAGE_PATH := $(DCAP_QV_DIR)/sgxssl/Linux/package
Enclave_Include_Paths := -I./ -I$(WARM_Top_Path)/core/iwasm/include \
                         -I$(WARM_Top_Path)/core/shared/utils \
                         -I$(WARM_Top_Path)/core/shared/platform/linux-sgx \
                         -I$(SGX_SDK)/include \
                         -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/libcxx/ \
                         -I$(JWT_CPP_Path)/include \
                         -I$(SGXSSL_PACKAGE_PATH)/include/ \
                         -I$(RAPIDJSON_DIR)/  \
                         -I$(DCAP_QV_DIR)/dcap_tvl \
                         -I$(DCAP_QV_DIR)/appraisal/qal \
                         -I$(DCAP_QV_DIR)/appraisal/common \
                         -I$(DCAP_QG_DIR)/common/inc/internal

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_Common_Flags := -fstack-protector
else
	Enclave_Common_Flags := -fstack-protector-strong
endif
Enclave_Common_Flags += -ffreestanding -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(Enclave_Include_Paths)
Enclave_Common_Flags += -DPICOJSON_USE_LOCALE=0 -DBUILD_QAE -DSGX_JWT

Enclave_Compile_CFlags := -nostdinc $(SGX_COMMON_CFLAGS) $(Enclave_Common_Flags)
Enclave_Compile_CXXFlags := -nostdinc++ $(Enclave_Common_Flags) $(SGX_COMMON_CXXFLAGS)

Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

ifeq ($(DEBUG), 1)
        SGXSSL_TLIB = sgx_tsgxssld
        SGXSSL_TCRYPTO = sgx_tsgxssl_cryptod
else
        SGXSSL_TLIB = sgx_tsgxssl
        SGXSSL_TCRYPTO = sgx_tsgxssl_crypto
endif

Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L$(SGXSSL_PACKAGE_PATH)/lib64 \
    -Wl,--whole-archive -l$(Trts_Library_Name) -l$(SGXSSL_TLIB) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(SGXSSL_TCRYPTO) -l$(Crypto_Library_Name) -l$(Service_Library_Name) -lsgx_pthread -Wl,--end-group \
    -Wl,--version-script=qae.lds -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

WASM_CONFIG ?= -DCMAKE_BUILD_TYPE=Release
ifeq ($(DEBUG), 1)
    WASM_CONFIG := -DCMAKE_BUILD_TYPE=Debug
endif

Enclave_Cpp_Files := $(wildcard *.cpp)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Gen_Trusted_Source := qae_t.c
Gen_Trusted_Object := qae_t.o

COMMON_Cpp_Objects := ec_key.o format_util.o
OPA_Cpp_Objects := opa_wasm.o opa_helper.o opa_builtins.o qal_json.o qal_auth.o

Enclave_Objects := $(sort $(Gen_Trusted_Object) $(COMMON_Cpp_Objects) $(OPA_Cpp_Objects) $(Enclave_Cpp_Objects))

Enclave_Name := libsgx_qae.so
Signed_Enclave_Name := libsgx_qae.signed.so
Enclave_Config_File := config.xml
Enclave_Test_Key := Enclave_private_test.pem


Enclave_Edl_Search_Path :=  --search-path $(SGX_SDK)/include


.PHONY: all PREPARE_SGX_SSL wasm_sgx_lib prepare

prepare:
ifeq ($(shell grep -c SGX_JWT $(JWT_CPP_Path)/include/jwt-cpp/jwt.h), 0)
	cd $(JWT_CPP_Path) && patch -p1 <../0001-Add-a-macro-to-disable-time-support-in-jwt-for-SGX.patch && cd -
endif

# build SGXSSL
PREPARE_SGXSSL_SCRIPT := $(DCAP_QV_DIR)/prepare_sgxssl.sh
SGXSSL_HEADER_CHECK := $(SGXSSL_PACKAGE_PATH)/include/openssl/opensslconf.h
PREPARE_SGX_SSL:
	@test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TCRYPTO).a && test -f $(SGXSSL_PACKAGE_PATH)/lib64/lib$(SGXSSL_TLIB).a && test -f $(SGXSSL_HEADER_CHECK) || $(PREPARE_SGXSSL_SCRIPT)

$(SGXSSL_HEADER_CHECK): PREPARE_SGX_SSL

wasm_sgx_lib:
	@test -f $(WARM_Lib_SGX_Build)/libvmlib.a || \
	(cd $(WARM_Lib_SGX_Path) && cp CMakeLists_minimal.txt CMakeLists.txt && cmake -Bbuild $(WASM_CONFIG) && $(MAKE) -C build)

$(WARM_Lib_SGX_Build)/libvmlib.a: wasm_sgx_lib

all: prepare
	$(MAKE) $(Signed_Enclave_Name)

$(Gen_Trusted_Source): $(SGX_EDGER8R) qae.edl 
	@$(SGX_EDGER8R) --trusted qae.edl $(Enclave_Edl_Search_Path)
	@echo "GEN  =>  $@"

qae_t.h: $(Gen_Trusted_Source)

$(Gen_Trusted_Object): $(Gen_Trusted_Source)
	@$(CC) $(Enclave_Compile_CFlags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Cpp_Objects): %.o: %.cpp qae_t.h $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(Enclave_Compile_CXXFlags) -c $< -o $@
	@echo "CXX  <=  $<"

$(OPA_Cpp_Objects): %.o:$(DCAP_QV_DIR)/appraisal/qal/%.cpp qae_t.h $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(Enclave_Compile_CXXFlags) -c $< -o $@
	@echo "CXX  <=  $<"

$(COMMON_Cpp_Objects): %.o:$(DCAP_QV_DIR)/appraisal/common/%.cpp $(SGXSSL_HEADER_CHECK)
	@$(CXX) $(Enclave_Compile_CXXFlags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): $(Enclave_Objects) $(WARM_Lib_SGX_Build)/libvmlib.a
	@$(CXX) $(Enclave_Objects) $(WARM_Lib_SGX_Build)/libvmlib.a -o $@ $(Enclave_Link_Flags) -Wl,-soname=$(Signed_Enclave_Name).$(call get_major_version,QAE_VERSION)
	@echo "LINK =>  $@"
ifneq ($(DEBUG), 1)
	@$(STRIP) --strip-unneeded --remove-section=.comment --remove-section=.note $@
endif

$(Signed_Enclave_Name): $(Enclave_Name)
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key <$(Enclave_Test_Key)>."
	@echo "The project will generate a key <$(Enclave_Test_Key)> for testing."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean
clean:
	rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Test_Key) $(Enclave_Objects) $(Gen_Trusted_Source) *_t.h
	$(RM) -r $(WARM_Lib_SGX_Build)
