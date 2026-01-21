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

#
# main make file for PCK Cert Selection library project
#
############ SGX SDK Settings ###################
TOP_DIR = ../../../QuoteGeneration
include $(TOP_DIR)/buildenv.mk

ifndef VERBOSE
	PCKCERTSEL_VERBOSE:=@
endif

######## Project Settings ########

# project root directory and output directory
ifndef PROJ_ROOT_DIR
	PROJ_ROOT_DIR	:= $(CURDIR)/..
endif
ifndef BIN_DIR
	BIN_DIR		:= $(PROJ_ROOT_DIR)/out
endif

# QVL Attestation Parsers root directory
# other projects, like tests project, that needs to build this library from a different tree must define QVL_DIR
ifndef QVL_DIR
	QVL_DIR		:= $(PROJ_ROOT_DIR)/../../QuoteVerification/QVL/Src
endif

# QG root directory
# include the se_version.h file from there
ifndef QG_DIR
	QG_DIR     := $(PROJ_ROOT_DIR)/../../QuoteGeneration
endif

# openssl include dir
OPENSSL_INC 		:= $(PROJ_ROOT_DIR)/../../prebuilt/openssl/inc

# openssl lib dir
OPENSSL_LIB 		:= $(PROJ_ROOT_DIR)/../../prebuilt/openssl/lib/linux64

# JSON parser include dir
JSON_INC		:= $(QVL_DIR)/ThirdParty/rapidjson/include

# QVL Attestation Parsers include directory
PARSERS_INC 		:= $(QVL_DIR)/AttestationParsers/include
PARSERS_COMM_INC 		:= $(QVL_DIR)/AttestationCommons/include
PARSERS_UTIL_INC 		:= $(QVL_DIR)/AttestationCommons/include/Utils

######## Library Settings ########

# QVL Attestation Parsers source dirs
PARSERS_DIR 		:= $(QVL_DIR)/AttestationParsers/src
PARSERS_COMM_DIR 		:= $(QVL_DIR)/AttestationCommons/src
JSON_DIR		:= $(PARSERS_DIR)/Json
X509_DIR 		:= $(PARSERS_DIR)/X509
HELPERS_DIR 		:= $(PARSERS_DIR)/OpensslHelpers
UTILS_DIR 		:= $(PARSERS_COMM_DIR)/Utils
VER_DIR       := $(QG_DIR)/common/inc/internal

# source files from QVL Attestation Parsers dirs
PARSER_CPP_FILES	:= ParserUtils.cpp
X509_CPP_FILES		:= Certificate.cpp DistinguishedName.cpp Extension.cpp PckCertificate.cpp Signature.cpp Tcb.cpp Validity.cpp
HELPERS_CPP_FILES	:= OidUtils.cpp
JSON_CPP_FILES		:= JsonParser.cpp TcbInfo.cpp TcbLevel.cpp TdxModule.cpp TcbComponent.cpp TdxModuleTcb.cpp TdxModuleTcbLevel.cpp TdxModuleIdentity.cpp
UTILS_CPP_FILES		:= GMTime.cpp TimeUtils.cpp

# source files from local dir
LOCAL_CPP_FILES		:= pck_sorter.cpp pck_cert_selection.cpp config_selector.cpp tcb_manager.cpp

# create source files list, add dir prefix to QVL files
LIB_CPP_FILES		:= \
	$(addprefix $(PARSERS_DIR)/, PARSER_CPP_FILES) \
	$(addprefix $(X509_DIR)/, X509_CPP_FILES) \
	$(addprefix $(HELPERS_DIR)/, HELPERS_CPP_FILES) \
	$(addprefix $(JSON_DIR)/, JSON_CPP_FILES) \
	$(addprefix $(UTILS_DIR)/, UTILS_CPP_FILES) \
	$(LOCAL_CPP_FILES)

# generate object files in local dir, also for QVL files
LIB_CPP_OBJECTS 	:= \
	$(LOCAL_CPP_FILES:.cpp=.o) \
	$(PARSER_CPP_FILES:.cpp=.o) \
	$(X509_CPP_FILES:.cpp=.o) \
	$(HELPERS_CPP_FILES:.cpp=.o) \
	$(JSON_CPP_FILES:.cpp=.o) \
	$(UTILS_CPP_FILES:.cpp=.o)

# include paths, local, parser and openssl
LIB_INCLUDE_PATHS	:= -I. -I$(PROJ_ROOT_DIR)/include -I$(OPENSSL_INC) -I$(JSON_INC) -I$(PARSERS_INC) -I$(PARSERS_COMM_INC) -I$(PARSERS_DIR) -I$(VER_DIR) -I$(PARSERS_UTIL_INC)

# the library shared object name
LIB_NAME		:= libPCKCertSelection.so
LIB_SYM			:= $(LIB_NAME).sym


####### Build Flags ##############

CXXFLAGS += -m64 -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -Werror -Wno-overloaded-virtual $(LIB_INCLUDE_PATHS)
CXXFLAGS += -UPCK_CERT_SELECTION_WITH_COMPONENT

# Link flags
LINK_FLAGS := -m64 -shared $(COMMON_LDFLAGS) -L$(OPENSSL_LIB) -lcrypto -lpthread -ldl
LINK_FLAGS += -Wl,--version-script=pck_cert_selection.lds -Wl,--gc-sections

# Strip only in RELEASE builds
ifndef DEBUG
        STRIP_CMD = strip -s
else
        STRIP_CMD = echo "\t Debug mode - no strip"
endif


####### Build Targets ##############

.PHONY: all clean

# default targetparser
all: $(BIN_DIR) $(LIB_NAME)

# local source files compiling
%.o: %.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# parser source files compiling
%.o: $(PARSERS_DIR)/%.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# x509 source files compiling
%.o: $(X509_DIR)/%.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# helpers source files compiling
%.o: $(HELPERS_DIR)/%.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# json source files compiling
%.o: $(JSON_DIR)/%.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# utils source files compiling
%.o: $(UTILS_DIR)/%.cpp
	$(PCKCERTSEL_VERBOSE)echo "Compiling $<..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $(CXXFLAGS) -c $< -o $@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

# build library - link into output dir
$(LIB_NAME): $(LIB_CPP_OBJECTS)
	$(PCKCERTSEL_VERBOSE)echo "Linking..."
	$(PCKCERTSEL_VERBOSE)$(CXX) $^ -o $(BIN_DIR)/$@ $(LINK_FLAGS) -Wl,-soname=$@.$(SGX_MAJOR_VER)
	$(PCKCERTSEL_VERBOSE)cp $(BIN_DIR)/$@ $(BIN_DIR)/$(LIB_SYM)
	$(PCKCERTSEL_VERBOSE)echo "Stripping..."
	$(PCKCERTSEL_VERBOSE)$(STRIP_CMD) $(BIN_DIR)/$@
	$(PCKCERTSEL_VERBOSE)echo "\t -> $@ done"

debug:
	$(PCKCERTSEL_VERBOSE)$(MAKE) DEBUG=1 all

release:
	$(PCKCERTSEL_VERBOSE)$(MAKE) all

clean:
	$(PCKCERTSEL_VERBOSE)echo -n "Clean $(LIB_NAME)..."
	$(PCKCERTSEL_VERBOSE)rm -rf $(BIN_DIR)/$(LIB_NAME)* $(LIB_CPP_OBJECTS)
	$(PCKCERTSEL_VERBOSE)rm -rf $(BIN_DIR)
	$(PCKCERTSEL_VERBOSE)echo done

$(BIN_DIR):
	$(PCKCERTSEL_VERBOSE)mkdir -p $@

