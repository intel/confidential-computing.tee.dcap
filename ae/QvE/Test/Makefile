# Copyright(c) 2011-2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

include ../../../QuoteVerification/buildenv.mk

print-%  : ; @echo $* = $($*)

######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk

MKFILE_PATH := .
INCLUDE_PATH := $(MKFILE_PATH)/../Include
EXTERNAL_PATH := $(MKFILE_PATH)/../../../external
BUILD_PATH := $(MKFILE_PATH)/build
DEST_PATH := $(BUILD_PATH)/release
APPRAISAL_COMMON_PATH := $(MKFILE_PATH)/../../appraisal/common
GTEST_PATH := $(EXTERNAL_PATH)/gtest/build

SRC_PATH := $(MKFILE_PATH)/../qve
TEST_PATH := $(MKFILE_PATH)/src
MOCK_PATH := $(MKFILE_PATH)/src/mock

INCLUDE := -I$(INCLUDE_PATH) -I$(SRC_PATH) -I$(MOCK_PATH) -I$(PREBUILD_OPENSSL_PATH)/inc\
					-I$(MKFILE_PATH)/../../../QuoteVerification/QVL/Src/AttestationLibrary/src \
                    -I$(MKFILE_PATH)/../../../QuoteVerification/QVL/Src/AttestationLibrary/include \
                    -I$(MKFILE_PATH)/../../../QuoteVerification/QVL/Src/AttestationParsers/include \
                    -I$(MKFILE_PATH)/../../../QuoteVerification/QVL/Src/AttestationCommons/include \
                    -isystem$(SGX_SDK)/include \
					-isystem$(EXTERNAL_PATH)/jwt-cpp/include

TESTS_INCLUDE := -I$(TEST_PATH) -I$(SRC_PATH) -I$(MOCK_PATH)\
					-isystem$(GTEST_PATH)/include

QVE_BUILD_TYPE :=
ifeq ($(DEBUG), 1)
	QVE_BUILD_TYPE += DEBUG=1
	DEST_PATH := $(BUILD_PATH)/debug
endif

OBJ_PATH := $(DEST_PATH)/obj
BIN_PATH := $(DEST_PATH)/bin

SRC_QVE_LOGIC := $(SRC_PATH)/qve_logic.cpp
SRC_TEST := $(wildcard $(TEST_PATH)/*cpp)
SRC_MOCK := $(wildcard $(MOCK_PATH)/*cpp)

OBJ_TEST_PATH := $(OBJ_PATH)/test
OBJS_TEST := $(patsubst $(TEST_PATH)/%.cpp,$(OBJ_TEST_PATH)/%.o, $(SRC_TEST))

OBJ_MOCK_PATH := $(OBJ_PATH)/mock
OBJS_MOCK := $(patsubst $(MOCK_PATH)/%.cpp,$(OBJ_MOCK_PATH)/%.o, $(SRC_MOCK))

OBJ_SRC_PATH := $(OBJ_PATH)/qve
OBJS_SRC := $(OBJ_SRC_PATH)/$(notdir $(SRC_QVE_LOGIC:.cpp=.o))

LD_GTEST := -L$(GTEST_PATH)/lib -lgtest -lgmock_main -lgmock
LDFLAGS := -L$(PREBUILD_OPENSSL_PATH)/lib/linux64 -lcrypto -lpthread -ldl

CXX_WARNINGS := -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align -Wconversion -Wredundant-decls

CXXFLAGS := -std=c++17 -fPIE -fPIC -Wnon-virtual-dtor -fstack-protector -ffunction-sections -DITT_ARCH_IA64 -fcf-protection $(CXX_WARNINGS)

.PHONY: all

all: post-build

pre-build: ThirdParty
	@mkdir -p $(BIN_PATH) \
			$(OBJ_TEST_PATH) \
			$(OBJ_SRC_PATH) \
			$(OBJ_MOCK_PATH)

main-build: pre-build
	@echo "Main build"
	$(MAKE) $(BIN_PATH)/UnitTests

post-build: main-build run-tests

run-tests: $(BIN_PATH)/UnitTests
	@echo "Running unit tests..."
	@$(BIN_PATH)/UnitTests --gtest_output=xml:$(BIN_PATH)/report.xml

ThirdParty:
	$(MAKE) -C $(EXTERNAL_PATH)

clean:
	rm -rf $(BUILD_PATH)

$(BIN_PATH)/UnitTests: $(OBJS_TEST) $(OBJS_MOCK) $(OBJS_SRC)
	$(CXX) $(INCLUDE) $(TESTS_INCLUDE) $(CXXFLAGS) $(OBJS_TEST) $(OBJS_MOCK) $(OBJS_SRC) $(LD_GTEST) $(LDFLAGS) -o $@
	@echo "$@"

$(OBJ_TEST_PATH)/%.o: $(TEST_PATH)/%.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(TESTS_INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_SRC_PATH)/%.o: $(SRC_PATH)/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(TESTS_INCLUDE) $< -o $@
	@echo "$<"

$(OBJ_MOCK_PATH)/%.o: $(MOCK_PATH)/%.cpp
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(TESTS_INCLUDE) $< -o $@
	@echo "$<"
