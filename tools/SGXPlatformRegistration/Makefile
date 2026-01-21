#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

print-%  : ; @echo $* = $($*)

CP := cp

######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0


CC_VERSION := $(shell $(CC) -dumpversion)
CC_VERSION_MAJOR := $(shell echo $(CC_VERSION) | cut -f1 -d.)
CC_VERSION_MINOR := $(shell echo $(CC_VERSION) | cut -f2 -d.)
CC_NO_LESS_THAN_8 := $(shell [ $(CC_VERSION_MAJOR) -ge 8 ] && echo 1 || echo 0)
CC_NO_LESS_THAN_12 := $(shell [ $(CC_VERSION_MAJOR) -ge 12 ] && echo 1 || echo 0)

ifeq ($(CC_NO_LESS_THAN_12), 1)
    FORTIFY_SOURCE_VAL:= 3
else
    FORTIFY_SOURCE_VAL:= 2
endif

MKFILE_PATH := .
SRC_PATH := $(MKFILE_PATH)/src
INCLUDE_PATH := $(MKFILE_PATH)/include
BUILD_PATH := $(MKFILE_PATH)/build
EXTERNAL_PATH := $(MKFILE_PATH)/../../external

DEST_PATH := $(BUILD_PATH)/release
INSTALL_PATH := $(DEST_PATH)/installer

GTEST_PATH := $(EXTERNAL_PATH)/gtest/build
TEST_PATH := $(MKFILE_PATH)/test

ifdef DEBUG
	DEST_PATH := $(BUILD_PATH)/debug
endif

OBJ_PATH := $(DEST_PATH)/obj
BIN_PATH := $(DEST_PATH)/bin
LIB_PATH := $(DEST_PATH)/lib64

AGENT_PATH := $(SRC_PATH)/agent
COMMON_PATH := $(SRC_PATH)/common
MANAGEMENT_PATH := $(SRC_PATH)/management
NETWORK_PATH := $(SRC_PATH)/network
UEFI_PATH := $(SRC_PATH)/uefi
MPA_REGI_PATH := $(SRC_PATH)/mpa_registration
MPA_MANAGE_PATH := $(SRC_PATH)/mpa_manage_tool

SDK_INCLUDE := -isystem$(SGX_SDK)/include
INCLUDE += -I$(MKFILE_PATH)/../../QuoteGeneration/common/inc/internal

INCLUDE += $(SDK_INCLUDE)
INCLUDE += -I$(INCLUDE_PATH)
INCLUDE += -I$(INCLUDE_PATH)/c_wrapper
INCLUDE += -I$(AGENT_PATH)/inc
INCLUDE += -I$(COMMON_PATH)/inc
INCLUDE += -I$(MANAGEMENT_PATH)/inc
INCLUDE += -I$(NETWORK_PATH)/inc
INCLUDE += -I$(UEFI_PATH)/inc

GTEST_INCLUDE := -isystem$(GTEST_PATH)/include
TESTS_INCLUDE := -I$(TEST_PATH) -I$(TEST_PATH)/mocks $(GTEST_INCLUDE)

SRC_AGENT := $(wildcard $(AGENT_PATH)/src/*cpp)
SRC_COMMON := $(wildcard $(COMMON_PATH)/src/*cpp)
SRC_MANAGEMENT := $(wildcard $(MANAGEMENT_PATH)/src/*cpp $(MANAGEMENT_PATH)/src/c_wrapper/*cpp)
SRC_NETWORK := $(wildcard $(NETWORK_PATH)/src/*cpp $(NETWORK_PATH)/src/c_wrapper/*cpp)
SRC_UEFI := $(wildcard $(UEFI_PATH)/src/*cpp $(UEFI_PATH)/src/c_wrapper/*cpp)
SRC_REGISTRATION_APP := $(MPA_REGI_PATH)/src/mpa_registration_service.cpp
SRC_MPA_MANAGE_APP := $(MPA_MANAGE_PATH)/src/main.cpp
SRC_TEST := $(wildcard $(TEST_PATH)/*cpp)

OBJ_SGX_CAPABLE_PATH := $(OBJ_PATH)/sgx_capable
OBJS_SGX_CAPABLE := $(OBJ_SGX_CAPABLE_PATH)/*.o
OBJS_SRC := $(OBJS_SGX_CAPABLE)

OBJ_AGENT_PATH := $(OBJ_PATH)/agent
OBJS_AGENT := $(patsubst $(AGENT_PATH)/src/%.cpp,$(OBJ_AGENT_PATH)/%.o, $(SRC_AGENT))
OBJS_SRC += $(OBJS_AGENT)

OBJ_COMMON_PATH := $(OBJ_PATH)/common
OBJS_COMMON := $(patsubst $(COMMON_PATH)/src/%.cpp,$(OBJ_COMMON_PATH)/%.o, $(SRC_COMMON))
OBJS_SRC += $(OBJS_COMMON)

OBJ_MANAGEMENT_PATH := $(OBJ_PATH)/management
OBJS_MANAGEMENT := $(patsubst $(MANAGEMENT_PATH)/src/%.cpp,$(OBJ_MANAGEMENT_PATH)/%.o, $(SRC_MANAGEMENT))
OBJS_SRC += $(OBJS_MANAGEMENT)

OBJ_NETWORK_PATH := $(OBJ_PATH)/network
OBJS_NETWORK := $(patsubst $(NETWORK_PATH)/src/%.cpp,$(OBJ_NETWORK_PATH)/%.o, $(SRC_NETWORK))
OBJS_SRC += $(OBJS_NETWORK)

OBJ_UEFI_PATH := $(OBJ_PATH)/uefi
OBJS_UEFI := $(patsubst $(UEFI_PATH)/src/%.cpp,$(OBJ_UEFI_PATH)/%.o, $(SRC_UEFI))
OBJS_SRC += $(OBJS_UEFI)

OBJ_REGISTRATION_APP_PATH := $(OBJ_PATH)/registration_app
OBJS_REGISTRATION_APP := $(patsubst $(MPA_REGI_PATH)/src/%.cpp,$(OBJ_REGISTRATION_APP_PATH)/%.o, $(SRC_REGISTRATION_APP))

OBJ_MPA_MANAGE_APP_PATH := $(OBJ_PATH)/mpa_manage_app
OBJS_MPA_MANAGE_APP := $(patsubst $(MPA_MANAGE_PATH)/src/%.cpp,$(OBJ_MPA_MANAGE_APP_PATH)/%.o, $(SRC_MPA_MANAGE_APP))

OBJ_TEST_PATH := $(OBJ_PATH)/test
OBJS_TEST := $(patsubst $(TEST_PATH)/%.cpp,$(OBJ_TEST_PATH)/%.o, $(SRC_TEST))

LDFLAGS_SO := -shared -Wl,-z,relro,-z,now,-z,noexecstack
LD_REGI_APP := -L$(LIB_PATH) -Wl,-Bstatic -lmpa_registration -Wl,-Bdynamic -lmpa_network -lmpa_uefi
LD_MANAGE_APP := -L$(LIB_PATH) -Wl,-Bstatic -lmpa_management -lmpa_registration -Wl,-Bdynamic -lmpa_uefi

LD_GTEST := -L$(GTEST_PATH)/lib -lgtest -lgmock_main -lgmock -lpthread

CXX_WARNINGS := -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security \
				-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align -Wconversion -Wredundant-decls
CXXFLAGS := -std=c++17 -fPIC -Wnon-virtual-dtor -fstack-protector-strong -ffunction-sections -DITT_ARCH_IA64 \
			-fdata-sections -D_GLIBCXX_ASSERTIONS $(CXX_WARNINGS)

ifeq ($(CC_NO_LESS_THAN_8), 1)
    CXXFLAGS += -fcf-protection -fstack-clash-protection
endif

# debug -O0 -UDEBUG -DNDEBUG
ifdef DEBUG
	CXXFLAGS += -O0 -ggdb -DDEBUG -UNDEBUG -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG -DDEBUG_MODE=1
	LDFLAGS_SO += -ggdb
else
	CXXFLAGS += -O2 -D_FORTIFY_SOURCE=$(FORTIFY_SOURCE_VAL) -UDEBUG -DNDEBUG
endif

# that was initially just for UEFI sources
ifeq ($(MP_VERIFY_DATA_STRUCTS), 1)
	CXXFLAGS += -DMP_VERIFY_INTERNAL_DATA_STRUCT_WRITE=1
else
	CXXFLAGS += -DMP_VERIFY_INTERNAL_DATA_STRUCT_WRITE=0
endif

.PHONY: all clean static dynamic deb_pkg rpm_pkg ThirdParty

all: post-build
debug: all
release: all

pre-build:
	@mkdir -p $(BIN_PATH) \
		$(LIB_PATH) \
		$(OBJ_AGENT_PATH) \
		$(OBJ_COMMON_PATH) \
		$(OBJ_MANAGEMENT_PATH) \
		$(OBJ_MANAGEMENT_PATH)/c_wrapper \
		$(OBJ_NETWORK_PATH) \
		$(OBJ_NETWORK_PATH)/c_wrapper \
		$(OBJ_UEFI_PATH) \
		$(OBJ_UEFI_PATH)/c_wrapper \
		$(OBJ_REGISTRATION_APP_PATH) \
		$(OBJ_MPA_MANAGE_APP_PATH) \
		$(OBJ_SGX_CAPABLE_PATH) \
		$(OBJ_TEST_PATH)

post-build: main-build

main-build: pre-build
	@$(MAKE) --no-print-directory $(BIN_PATH)/mpa_registration
	@$(MAKE) --no-print-directory $(BIN_PATH)/mpa_manage
	@$(MAKE) --no-print-directory $(BIN_PATH)/UnitTests

deb_pkg: post-build
	@mkdir -p $(INSTALL_PATH)
	./installer/deb/libsgx-ra-uefi/build.sh
	$(CP) ./installer/deb/libsgx-ra-uefi/libsgx-ra-uefi*deb $(INSTALL_PATH)
	./installer/deb/libsgx-ra-network/build.sh $(INSTALL_PATH)
	 $(CP) ./installer/deb/libsgx-ra-network/libsgx-ra-network*deb $(INSTALL_PATH)
	./installer/deb/sgx-ra-service/build.sh $(INSTALL_PATH)
	 $(CP) ./installer/deb/sgx-ra-service/sgx-ra-service*deb $(INSTALL_PATH)

rpm_pkg: post-build
	@mkdir -p $(INSTALL_PATH)
	./installer/rpm/libsgx-ra-uefi/build.sh
	$(CP) ./installer/rpm/libsgx-ra-uefi/libsgx-ra-uefi*rpm $(INSTALL_PATH)
	./installer/rpm/libsgx-ra-network/build.sh $(INSTALL_PATH)
	 $(CP) ./installer/rpm/libsgx-ra-network/libsgx-ra-network*rpm $(INSTALL_PATH)
	./installer/rpm/sgx-ra-service/build.sh $(INSTALL_PATH)
	 $(CP) ./installer/rpm/sgx-ra-service/sgx-ra-service*rpm $(INSTALL_PATH)

clean:
	rm -rf $(BUILD_PATH)
	./installer/deb/libsgx-ra-uefi/clean.sh
	./installer/deb/libsgx-ra-network/clean.sh
	./installer/deb/sgx-ra-service/clean.sh
	./installer/rpm/libsgx-ra-uefi/clean.sh
	./installer/rpm/libsgx-ra-network/clean.sh
	./installer/rpm/sgx-ra-service/clean.sh

$(BIN_PATH)/mpa_registration: $(OBJS_COMMON) $(OBJS_REGISTRATION_APP) static dynamic
	@$(CXX) $(INCLUDE) $(CXXFLAGS) $(OBJS_COMMON) $(OBJS_REGISTRATION_APP) $(LD_REGI_APP) -o $@
	@echo "$@"

$(BIN_PATH)/mpa_manage: $(OBJ_COMMON_PATH)/common.o $(OBJS_MPA_MANAGE_APP) static dynamic
	@$(CXX) $(INCLUDE) $(CXXFLAGS) $(OBJ_COMMON_PATH)/common.o $(OBJS_MPA_MANAGE_APP) $(LD_MANAGE_APP) -o $@
	@echo "$@"

$(BIN_PATH)/UnitTests: ThirdParty $(OBJS_TEST) $(OBJS_SRC)
	@$(CXX) $(INCLUDE) $(TESTS_INCLUDE) $(CXXFLAGS) $(OBJS_TEST) $(OBJS_SRC) $(LD_GTEST) -lcurl -o $@
	@echo "$@"

static: $(LIB_PATH)/libmpa_registration.a $(LIB_PATH)/libmpa_management.a
	@echo "$^"

dynamic: $(LIB_PATH)/libmpa_network.so $(LIB_PATH)/libmpa_uefi.so
	@echo "$<"

$(LIB_PATH)/libmpa_registration.a: $(OBJS_AGENT)
	@$(AR) rcs $@ $^
	@echo "$@"

$(LIB_PATH)/libmpa_management.a: $(OBJS_MANAGEMENT) $(OBJS_SGX_CAPABLE)
	@$(AR) rsD $@ $^ 
	@echo "$@"

ThirdParty:
	$(MAKE) -C $(EXTERNAL_PATH)

$(LIB_PATH)/libmpa_network.so: $(OBJS_NETWORK)
	@$(CXX) $^ -Wl,-soname=libmpa_network.so.1 $(LDFLAGS_SO) -lcurl -o $@
	@echo "$@"

$(LIB_PATH)/libmpa_uefi.so: $(OBJS_UEFI)
	@$(CXX) $^ -Wl,-soname=libmpa_uefi.so.1 $(LDFLAGS_SO) -o $@
	@echo "$@"

$(OBJ_SGX_CAPABLE_PATH)/%.o:
	@$(AR) x $(SGX_SDK)/lib64/libsgx_capable.a --output=$(OBJ_SGX_CAPABLE_PATH)

$(OBJ_AGENT_PATH)/%.o: $(AGENT_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_COMMON_PATH)/%.o: $(COMMON_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_MANAGEMENT_PATH)/%.o: $(MANAGEMENT_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_NETWORK_PATH)/%.o: $(NETWORK_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_UEFI_PATH)/%.o: $(UEFI_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_REGISTRATION_APP_PATH)/%.o: $(MPA_REGI_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_MPA_MANAGE_APP_PATH)/%.o: $(MPA_MANAGE_PATH)/src/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_TEST_PATH)/%.o: $(TEST_PATH)/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(GTEST_INCLUDE)  $< -o $@
	@echo "$<"
