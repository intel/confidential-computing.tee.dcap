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

#include <sstream>

#define TENANT_ENCLAVE_CLASS_ID 	"bef7cb8c-31aa-42c1-854c-10db005d5c41"
#define TENANT_TDX10_CLASS_ID 		"a1e4ee9c-a12e-48ac-bed0-e3f89297f687"
#define TENANT_TDX15_CLASS_ID 		"45b734fc-aa4e-4c3d-ad28-e43d08880e68"

#define SGX_PLATFORM_CLASS_ID       "3123ec35-8d38-4ea5-87a5-d6c48b567570"
#define TDX15_PLATFORM_CLASS_ID     "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3"
#define TDX10_PLATFORM_CLASS_ID     "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f"
#define TDX_TDQE_CLASS_ID           "3769258c-75e6-4bc7-8d72-d2b0e224cad2"

#define TENANT_ENCLAVE_DESCRIPTION  "Tenant Enclave Identity policy"
#define TENANT_TDX10_DESCRIPTION    "Tenant TDX 1.0 Identity policy"
#define TENANT_TDX15_DESCRIPTION    "Tenant TDX 1.5 Identity policy"
#define SGX_PLATFORM_DESCRIPTION    "SGX platform TCB policy"
#define TDX15_PLATFORM_DESCRIPTION  "TDX 1.5 platform TCB policy"
#define TDX10_PLATFORM_DESCRIPTION  "TDX 1.0 platform TCB policy"
#define TDX_TDQE_DESCRIPTION        "Verified TD QE Identity policy"

const std::stringstream default_sgx_platform_policy{R"(
{
    "environment": {
        "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
        "description": "Default Strict SGX platform TCB policy from Intel"
    },
    "reference": {
        "accepted_tcb_status": ["UpToDate"],
        "collateral_grace_period": 0
    }
}
)"};

const std::stringstream default_tdx15_platform_policy{R"(
{
    "environment": {
        "class_id": "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3",
        "description": "Default Strict TDX 1.5 platform TCB policy from Intel"
    },
    "reference": {
        "accepted_tcb_status": ["UpToDate"],
        "collateral_grace_period": 0
    }
}
)"};

const std::stringstream default_tdx10_platform_policy{R"(
{
    "environment": {
        "class_id": "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f",
        "description": "Default Strict TDX 1.0 platform TCB policy from Intel"
    },
    "reference": {
        "accepted_tcb_status": ["UpToDate"],
        "collateral_grace_period": 0
    }
}
)"};

const std::stringstream default_verified_TDQE_policy{R"(
{
    "environment": {
        "class_id": "3769258c-75e6-4bc7-8d72-d2b0e224cad2",
        "description": "Default Strict Verified TD QE Identity policy from Intel"
    },
    "reference": {
        "accepted_tcb_status": [
            "UpToDate"
        ],
        "collateral_grace_period": 0
    }
}
)"};
