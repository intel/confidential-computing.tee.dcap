#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../../buildenv.mk

WARM_Top_Path :=../../../external/wasm-micro-runtime/

WARM_Lib_Path := $(WARM_Top_Path)/product-mini/platforms/linux/build/

JWT_CPP_Path := ../../../external/jwt-cpp/
RAPIDJSON_DIR :=  ../../QVL/Src/ThirdParty/rapidjson/include
PREBUILD_OPENSSL_PATH := ../../../prebuilt/openssl
QAL_Include_Path := -I./ \
                -I$(SGX_SDK)/include \
                -I$(PREBUILD_OPENSSL_PATH)/inc \
                -I$(DCAP_QG_DIR)/common/inc/internal/linux \
                -I$(WARM_Top_Path)/core/iwasm/include \
                -I$(JWT_CPP_Path)/include   \
                -I$(COMMON_DIR)/inc/internal \
                -I../../dcap_quoteverify/inc \
                -I../common/ \
                -I$(RAPIDJSON_DIR)/

QAL_Cpp_Flags := $(CXXFLAGS) -g -fPIC $(QAL_Include_Path)
QAL_C_Flags := $(CFLAGS) -g -fPIC $(QAL_Include_Path)

QAL_Link_Flags := $(COMMON_LDFLAGS) -L$(WARM_Lib_Path) -liwasm  -ldl -lm -lpthread \
                -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 -lcrypto \
                -Wl,--gc-sections -Wl,--version-script=sgx_dcap_qal.lds

WASM_CONFIG ?= -DCMAKE_BUILD_TYPE=Release
ifeq ($(DEBUG), 1)
    WASM_CONFIG := -DCMAKE_BUILD_TYPE=Debug
	QAL_Cpp_Flags += -fsanitize=undefined
    QAL_C_Flags += -fsanitize=undefined
    QAL_Link_Flags += -fsanitize=undefined
endif
# Disable HW bound check to allow potential usage with other languages, such as Golang, Java
WASM_CONFIG += -DWAMR_DISABLE_HW_BOUND_CHECK=1

ifeq ($(USE_LOCAL_WASM), 1)
    QAL_Cpp_Flags += -DUSE_LOCAL_WASM
endif

QAL_Cpp_Files := $(wildcard *.cpp)
QAL_CXX_Obj_Files := $(QAL_Cpp_Files:.cpp=.o)
QAL_CXX_Common_Objs := file_util.o ec_key.o format_util.o

QAL_C_Common_Objs := se_thread.o se_trace.o
QAL_C_Obj_Files := $(QAL_C_Common_Objs) qae_u.o
ifdef QAL_BUILD
QAL_Obj_Files := $(sort $(QAL_CXX_Obj_Files) $(QAL_CXX_Common_Objs) $(QAL_C_Obj_Files))
else
QVL_Cpp_Obj_Files := sgx_dcap_pcs_com.o config.o sgx_urts_wrapper.o
QAL_Obj_Files := $(sort $(QAL_CXX_Obj_Files) $(QAL_CXX_Common_Objs) $(QAL_C_Obj_Files))
endif
Target_Lib_Name := libsgx_dcap_qal.so

Target_Static_Lib_Name := libdcap_qal.a

Enclave_Edl_Search_Path := --search-path $(SGX_SDK)/include

.PHONY: all clean rebuild wasm_lib 

all: $(Target_Lib_Name) $(Target_Static_Lib_Name) | $(BUILD_DIR)
	$(CP) $(Target_Lib_Name) $|

$(BUILD_DIR):
	@$(MKDIR) $@

$(Target_Lib_Name): $(QAL_Obj_Files) wasm_lib $(QVL_Cpp_Obj_Files)
	$(CXX) $(CXXFLAGS) $(QAL_Obj_Files) $(QVL_Cpp_Obj_Files) -shared -Wl,-soname=$@.$(SGX_MAJOR_VER) $(QAL_Link_Flags) -o $@
	ln -sf $(Target_Lib_Name) $(Target_Lib_Name).$(SGX_MAJOR_VER)

$(Target_Static_Lib_Name): $(QAL_Obj_Files) wasm_lib
	 $(CP) $(WARM_Lib_Path)/libiwasm.a $@
	 $(AR) rsD $@ $(QAL_Obj_Files)

sgx_dcap_pcs_com.o: %.o:../../dcap_quoteverify/%.cpp
	$(CXX) $(QAL_Cpp_Flags) -c $< -o $@
config.o: %.o:../../dcap_quoteverify/linux/%.cpp
	$(CXX) $(QAL_Cpp_Flags) -c $< -o $@
sgx_urts_wrapper.o: %.o:../../dcap_quoteverify/sgx_urts_wrapper.cpp
	$(CXX) $(QAL_Cpp_Flags) -c $< -o $@

qae_u.h: $(SGX_EDGER8R) ../qae/qae.edl
	$(SGX_EDGER8R) --untrusted ../qae/qae.edl $(Enclave_Edl_Search_Path)
	@echo "GEN  =>  $@"

qae_u.c: qae_u.h
qae_u.o: qae_u.c
	$(CC) $(QAL_C_Flags) -c $< -o $@

$(QAL_CXX_Obj_Files): %.o: %.cpp qae_u.h
$(QAL_CXX_Obj_Files): %.o: %.cpp
	$(CXX) $(QAL_Cpp_Flags) -c $< -o $@

$(QAL_C_Common_Objs): %.o:$(COMMON_DIR)/src/%.c
	$(CC) $(QAL_C_Flags) -c $< -o $@

$(QAL_CXX_Common_Objs): %.o: ../common/%.cpp
	$(CXX) $(QAL_Cpp_Flags) -c $< -o $@

wasm_lib:
	test -f $(WARM_Lib_Path)/libiwasm.a || ($(MKDIR) $(WARM_Lib_Path) && cd $(WARM_Lib_Path) && cmake .. $(WASM_CONFIG) && $(MAKE) vmlib)

clean:
	$(RM) $(QAL_Obj_Files) $(Target_Lib_Name) $(Target_Lib_Name).$(SGX_MAJOR_VER) $(Target_Static_Lib_Name) $(BUILD_DIR)/$(Target_Lib_Name) $(QVL_Cpp_Obj_Files)
	$(RM) -r $(WARM_Lib_Path) qae_u.*

rebuild:
	$(MAKE)  clean
	$(MAKE)  all
