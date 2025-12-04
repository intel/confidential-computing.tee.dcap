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

#include "wasm_export.h"
#include "sgx_dcap_qal.h"


#define DEFAULT_STACK_SIZE 8 * 1024
#define DEFAULT_HEAP_SIZE 0

class OPAEvaluateEngine
{
public:
    OPAEvaluateEngine();
    ~OPAEvaluateEngine();

    quote3_error_t prepare_wasm(uint8_t *wasm_buf, size_t wasm_size, uint32_t stack_size = DEFAULT_STACK_SIZE, uint32_t heap_size = DEFAULT_HEAP_SIZE);

    quote3_error_t start_eval(const uint8_t *input_json_buf, uint32_t json_size, time_t appraisal_check_date,
                              uint32_t *p_appraisal_result_token_buffer_size, uint8_t **p_appraisal_result_token);

private:
    OPAEvaluateEngine(const OPAEvaluateEngine &);
    OPAEvaluateEngine &operator=(const OPAEvaluateEngine &);

    uint32_t m_stack_size;
    uint32_t m_heap_size;
    wasm_module_inst_t m_wasm_module_inst;
    wasm_exec_env_t m_exec_env;
};