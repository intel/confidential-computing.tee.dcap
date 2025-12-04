/**
 * Copyright (c) 2011-2025, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <tuple>
#include <string>

#define VERSION_STRING \
    "\nThis is tee_appraisal_tool for SGX/TDX policy generation, version %s\n\n%s\n\n"

#define USAGE                                                                                                                          \
    "\ntee_appraisal_tool <Command> <options> <files>\n"                                                                               \
    "Command:\n"                                                                                                                       \
    "   gen_payload:        Generate the policy payload file with Json format based on the input enclave or TDX Report.\n"             \
    "   sign_policy:        Sign the input policy payload with the input EC key and generate the final policy file with JWT format.\n" \
    "   verify_policy:      Verify the JWT policy file.\n"                                                                             \
    "Options:\n"                                                                                                                       \
    "   -in                 Specify the input file path\n"                                                                             \
    "   -key                Specify the  key file. The key file must be a PEM-formatted, 384-byte EC private key\n"                               \
    "                       It is a required option for \"sign_policy\"\n"                                                             \
    "   -out                Speicify the output file path\n"                                                                           \
    "   -v                  Enable showing the extra dump message for each command\n\n"                                                \
    "Example:\n"                                                                                                                       \
    "   tee_appraisal_tool gen_payload -in {enclave/TDReport} -out payload.json [-v]\n"                                                \
    "   tee_appraisal_tool sign_policy -in payload.json -key ec_private.pem -out policy.jwt [-v]\n"                                    \
    "   tee_appraisal_tool verify_policy -in policy.jwt [-v]\n"                                                                        \
    "\n"                                                                                                                               \
    "Run \"tee_appraisal_tool -help\" to get this help and exit.\n"                                                                    \
    "Run \"tee_appraisal_tool -version\" to output version information and exit.\n\n"

typedef enum _cmd_t
{
    UNKNOWN_CMD = 0,
    GENERATE_PAYLOAD,
    SIGN_POLICY,
    VERIFY_POLICY,
    PRINT_USAGE,
    PRINT_VERSION
} cmd_t;

// EC KEY 384
#define ECP384_KEY_SIZE 48
#define CLAIM_NAME "policy_payload"

class CAppraisalUtil
{
public:
    CAppraisalUtil();
    ~CAppraisalUtil();
    bool run(int argc, char **argv);

private:
    cmd_t parse_cmd(int argc, char **argv);
    bool generate_payload();
    bool sign_policy();
    bool verify_policy();
    std::tuple<std::string, std::string> parse_ec_key();

    char *m_infile;
    char *m_outfile;
    char *m_keyfile;
    bool m_verbose;
};
