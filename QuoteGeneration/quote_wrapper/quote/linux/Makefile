#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR = ../../..
include $(TOP_DIR)/buildenv.mk

QE3_Dir := ../../../../ae/qe3/linux
QE3_Signed_Name := $(QE3_Dir)/libsgx_qe3.signed.so

ID_ENCLAVE_Dir := ../../../../ae/id_enclave/linux
ID_ENCLAVE_Signed_Name := $(ID_ENCLAVE_Dir)/libsgx_id_enclave.signed.so

######## Quote Settings ########


vpath %.c $(COMMON_DIR)/src
vpath %.cpp .. .
Quote_C_Files := qe3_u.c id_enclave_u.c se_thread.c se_trace.c
Quote_Cpp_Files := qe_logic.cpp sgx_ql_core_wrapper.cpp

Quote_Include_Paths := -I$(SGX_SDK)/include -I../inc -I../../common/inc -I./ -I$(QE3_Dir)/.. -I$(TOP_DIR)/pce_wrapper/inc -I$(COMMON_DIR)/inc/internal -I$(COMMON_DIR)/inc/internal/linux

Quote_C_Flags := $(COMMON_FLAGS) -g -fPIC -Werror -Wno-attributes $(Quote_Include_Paths)

Quote_Cpp_Flags := $(Quote_C_Flags)
Quote_Link_Flags := $(COMMON_LDFLAGS) -g -pthread -L$(ROOT_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -ldl

ifndef DEBUG
Quote_Cpp_Flags += -DDISABLE_TRACE
endif

Quote_Link_Flags += -Wl,--version-script=qe3_logic.lds -Wl,--gc-sections

Quote_C_Objects := $(Quote_C_Files:.c=.o)
Quote_Cpp_Objects := $(Quote_Cpp_Files:.cpp=.o)

Quote_Name := libsgx_qe3_logic.so

.PHONY: all
all: install_lib

install_lib: $(Quote_Name) | $(BUILD_DIR)
	@$(CP) $(Quote_Name) $|


######## Quote Objects ########

qe3_u.c: $(SGX_EDGER8R) $(QE3_Dir)/../qe3.edl
	$(SGX_EDGER8R) --untrusted $(QE3_Dir)/../qe3.edl --search-path $(QE3_Dir)/..
	@echo "GEN  =>  $@"

id_enclave_u.c: $(SGX_EDGER8R) $(ID_ENCLAVE_Dir)/../id_enclave.edl
	$(SGX_EDGER8R) --untrusted $(ID_ENCLAVE_Dir)/../id_enclave.edl
	@echo "GEN  =>  $@"

qe_logic.o : qe3_u.c id_enclave_u.c

%.o: %.c
	@$(CC) $(Quote_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Quote_Cpp_Objects): %.o: %.cpp
	@$(CXX) $(Quote_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Quote_Name): $(Quote_C_Objects) $(Quote_Cpp_Objects)
	$(CXX) $(Quote_C_Objects) $(Quote_Cpp_Objects) -shared -Wl,-soname=$@ $(Quote_Link_Flags) -o $@
	@echo "LINK =>  $@"

$(BUILD_DIR):
	@$(MKDIR) $@

$(QE3_Signed_Name): force_look
	@make -C $(QE3_Dir)

$(ID_ENCLAVE_Signed_Name): force_look
	@make -C $(ID_ENCLAVE_Dir)

force_look:
	true

.PHONY: clean

clean:
	@$(RM) .config_* $(Quote_Name) $(Quote_C_Objects) $(Quote_Cpp_Objects) qe3_u.* id_enclave_u.* $(BUILD_DIR)/$(Quote_Name)
	@make -C $(QE3_Dir) clean
	@make -C $(ID_ENCLAVE_Dir) clean

