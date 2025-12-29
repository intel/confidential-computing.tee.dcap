/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef OPA_WASM_H
#define OPA_WASM_H

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

#endif // OPA_WASM_H
