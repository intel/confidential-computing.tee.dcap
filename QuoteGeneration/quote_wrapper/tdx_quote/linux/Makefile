#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

######## SGX SDK Settings ########
TOP_DIR = ../../..
include $(TOP_DIR)/buildenv.mk

PCE_Library_Dir := $(TOP_DIR)/pce_wrapper/linux
PCE_Library := $(PCE_Library_Dir)/libsgx_pce_logic.so

TDQE_Dir := ../../../../ae/tdqe/linux
TDQE_Signed_Name := $(TDQE_Dir)/libsgx_tdqe.signed.so

ID_ENCLAVE_Dir := ../../../../ae/id_enclave/linux
ID_ENCLAVE_Signed_Name := $(ID_ENCLAVE_Dir)/libsgx_id_enclave.signed.so

######## Quote Settings ########


vpath %.c $(COMMON_DIR)/src
Quote_C_Files := tdqe_u.c id_enclave_u.c se_thread.c se_trace.c
Quote_Cpp_Files := $(wildcard ../*.cpp)

Quote_Include_Paths := -I$(SGX_SDK)/include -I../inc -I../../common/inc -I./ \
                       -I../../../../ae/tdqe -I$(TOP_DIR)/pce_wrapper/inc \
					   -I$(COMMON_DIR)/inc/internal \
					   -I$(COMMON_DIR)/inc/internal/linux

Quote_C_Flags := $(CFLAGS) -g -MMD -fPIC -Werror -Wno-attributes $(Quote_Include_Paths)

Quote_Cpp_Flags := $(CXXFLAGS) -g -MMD -fPIC -Werror -Wno-attributes $(Quote_Include_Paths)
Quote_Link_Flags := $(COMMON_LDFLAGS) -g -L$(ROOT_DIR)/build/linux \
                    -L$(PCE_Library_Dir) -lsgx_pce_logic -L$(SGX_SDK)/lib64 \
					-lsgx_urts -lpthread -ldl

Quote_Link_Flags += -Wl,--version-script=td_ql_logic.lds -Wl,--gc-sections

Quote_C_Objects := $(Quote_C_Files:.c=.o)
Quote_C_Depends := $(Quote_C_Files:.c=.d)
Quote_Cpp_Objects := $(Quote_Cpp_Files:.cpp=.o)
Quote_Cpp_Depends := $(Quote_Cpp_Files:.cpp=.d)

Quote_Name := libsgx_tdx_logic.so
Quote_Full := $(Quote_Name).$(call get_full_version,TDQE_WRAPPER_VERSION)
Quote_Major := $(Quote_Name).$(call get_major_version,TDQE_WRAPPER_VERSION)

-include $(Quote_C_Depends)
-include $(Quote_Cpp_Depends)

.PHONY: all
all: install_lib

install_lib: $(Quote_Name) | $(BUILD_DIR)
	@$(CP) $(Quote_Name) $|/$(Quote_Full)
	@$(LN) $(Quote_Full) $|/$(Quote_Major)
	@$(LN) $(Quote_Major) $|/$(Quote_Name)

$(BUILD_DIR):
	@$(MKDIR) $@

######## Quote Objects ########

tdqe_u.c: $(SGX_EDGER8R) ../../../../ae/tdqe/tdqe.edl
	$(SGX_EDGER8R) --untrusted ../../../../ae/tdqe/tdqe.edl --search-path ../../../../ae/tdqe
	@echo "GEN  =>  $@"

id_enclave_u.c: $(SGX_EDGER8R) $(ID_ENCLAVE_Dir)/../id_enclave.edl
	$(SGX_EDGER8R) --untrusted $(ID_ENCLAVE_Dir)/../id_enclave.edl
	@echo "GEN  =>  $@"

%.o: %.c
	@$(CC) $(Quote_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Quote_Cpp_Objects): %.o: %.cpp
	$(CXX) $(Quote_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Quote_Name): $(Quote_C_Objects) $(Quote_Cpp_Objects) $(PCE_Library)
	$(CXX) $(Quote_C_Objects) $(Quote_Cpp_Objects) -shared $(Quote_Link_Flags) \
	       -Wl,-soname=$(Quote_Major) -o $@
	@echo "LINK =>  $@"

$(PCE_Library): force_look
	@make -C $(PCE_Library_Dir)

$(TDQE_Signed_Name): force_look
	@make -C $(TDQE_Dir)

$(ID_ENCLAVE_Signed_Name): force_look
	@make -C $(ID_ENCLAVE_Dir)

force_look:
	true

.PHONY: clean

clean:
	@$(RM) .config_* $(Quote_Name) $(Quote_C_Objects) $(Quote_Cpp_Objects) \
	    $(Quote_C_Depends) $(Quote_Cpp_Depends) tdqe_u.* id_enclave_u.*    \
	    $(addprefix $(BUILD_DIR)/,$(Quote_Name) $(Quote_Full) $(Quote_Major))
	@make -C $(PCE_Library_Dir) clean
	@make -C $(TDQE_Dir) clean
	@make -C $(ID_ENCLAVE_Dir) clean

