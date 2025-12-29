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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <pthread.h>
#include "jwt-cpp/jwt.h"
#include "opa_builtins.h"
#include "opa_helper.h"
#include "qal_common.h"
#include "opa_wasm.h"
#include "ec_key.h"

std::map<int, std::string> g_builtins;
std::map<std::string, void *> g_builtin_func_map;

static bool g_builtin_prepared = false;
static pthread_mutex_t g_wasm_mutex;
static int g_wasm_init = 0;
static uint8_t *g_wasm_buf = NULL;
static size_t g_wasm_size = 0;
static wasm_module_t g_wasm_module = NULL;

#define CHECK_OPA_RET(val) if(val == 0) {return SGX_QL_ERROR_UNEXPECTED;}

static NativeSymbol native_symbols[6] = {
    {"opa_builtin0", (void *)opa_builtin0, "(i*)i", NULL},
    {"opa_builtin1", (void *)opa_builtin1, "(i**)i", NULL},
    {"opa_builtin2", (void *)opa_builtin2, "(i***)i", NULL},
    {"opa_builtin3", (void *)opa_builtin3, "(i****)i", NULL},
    {"opa_builtin4", (void *)opa_builtin4, "(i*****)i", NULL},
    {"opa_abort", (void *)opa_abort, "($)", NULL}};

static void __attribute__((constructor)) _sgx_qal_qae_init()
{
    pthread_mutex_init(&g_wasm_mutex, NULL);
}

static void __attribute__((destructor)) _sgx_qal_qae_fini()
{
    pthread_mutex_destroy(&g_wasm_mutex);
    if (g_wasm_init == 1)
    {
        wasm_runtime_unload(g_wasm_module);
        wasm_runtime_destroy();
    }
    if (g_wasm_buf)
    {
        free(g_wasm_buf);
    }
}

static int init_wasm_runtime_once(uint8_t *wasm_buf, size_t wasm_size)
{
    if (g_wasm_init != 0)
    {
        return g_wasm_init;
    }
    else
    {
        pthread_mutex_lock(&g_wasm_mutex);
        if (g_wasm_init == 0)
        {
            do
            {
                RuntimeInitArgs init_args;
                memset(&init_args, 0, sizeof(RuntimeInitArgs));
                init_args.mem_alloc_type = Alloc_With_Allocator;
                init_args.mem_alloc_option.allocator.malloc_func = (void *)malloc;
                init_args.mem_alloc_option.allocator.realloc_func = (void *)realloc;
                init_args.mem_alloc_option.allocator.free_func = (void *)free;

                init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
                init_args.native_module_name = "env";
                init_args.native_symbols = native_symbols;
                char error_buf[128] = {0};
                // Initialize runtime environment
                if (!wasm_runtime_full_init(&init_args))
                {
                    se_trace(SE_TRACE_ERROR, "Init runtime environment failed.\n");
                    g_wasm_init = -1;
                    break;
                }

                g_wasm_buf = (uint8_t *)malloc(wasm_size);
                if (g_wasm_buf == NULL)
                {
                    wasm_runtime_destroy();
                    g_wasm_init = -1;
                    break;
                }
                memcpy(g_wasm_buf, wasm_buf, wasm_size);
                g_wasm_size = wasm_size;

                // Load WASM module from the WASM file buf
                if (!(g_wasm_module = wasm_runtime_load(g_wasm_buf, (uint32_t)g_wasm_size,
                                                        error_buf, sizeof(error_buf))))
                {
                    se_trace(SE_TRACE_ERROR, "Read WASM file failed.\n");
                    wasm_runtime_destroy();
                    free(g_wasm_buf);
                    g_wasm_buf = NULL;
                    g_wasm_init = -1;
                    break;
                }
                else
                {
                    SE_TRACE(SE_TRACE_DEBUG, "Init runtime environment successfully.\n");
                    g_wasm_init = 1;
                }
            } while (0);
        }
        pthread_mutex_unlock(&g_wasm_mutex);
        return g_wasm_init;
    }
}

static int prepare_builtin_once(const char *json_buffer_builtins)
{
    if (g_builtin_prepared == true)
    {
        // The global variables g_binutils and g_builtin_func_map only need to prepare once
        return 0;
    }
    else
    {
        pthread_mutex_lock(&g_wasm_mutex);
        if (g_builtin_prepared == false)
        {
            // Prepare g_builtins
            picojson::value v;
            std::string err;
            picojson::parse(v, json_buffer_builtins, json_buffer_builtins + strlen(json_buffer_builtins), &err);
            if (!err.empty())
            {
                SE_TRACE(SE_TRACE_DEBUG, "%s\n", err.c_str());
                pthread_mutex_unlock(&g_wasm_mutex);
                return -1;
            }
            if (!v.is<picojson::object>())
            {
                SE_TRACE(SE_TRACE_DEBUG, "JSON is not an object\n");
                pthread_mutex_unlock(&g_wasm_mutex);
                return -1;
            }
            const picojson::value::object &obj = v.get<picojson::object>();
            for (picojson::value::object::const_iterator i = obj.begin(); i != obj.end(); ++i)
            {
                g_builtins.insert(std::pair<int, std::string>(stoi(i->second.to_str()), i->first));
                if (i->first == "time.parse_rfc3339_ns")
                    g_builtin_func_map.insert(std::pair<std::string, void *>("time.parse_rfc3339_ns", (void *)get_ns_since_epoch));
                else if (i->first == "time.now_ns")
                    g_builtin_func_map.insert(std::pair<std::string, void *>("time.now_ns", (void *)get_now_ns));
                else if (i->first == "rand.intn")
                    g_builtin_func_map.insert(std::pair<std::string, void *>("rand.intn", (void *)get_rand_n));
                else
                {
                    SE_TRACE(SE_TRACE_DEBUG, "Warning: No implementation is provided for the builtin function %s.\n", i->first.c_str());
                }
            }
            g_builtin_prepared = true;
        }
        pthread_mutex_unlock(&g_wasm_mutex);
        return 0;
    }
}

OPAEvaluateEngine::OPAEvaluateEngine()
: m_stack_size(DEFAULT_STACK_SIZE)
, m_heap_size(DEFAULT_HEAP_SIZE)
, m_wasm_module_inst(NULL)
, m_exec_env(NULL)
{
}

OPAEvaluateEngine::~OPAEvaluateEngine()
{
    if (m_exec_env)
        wasm_runtime_destroy_exec_env(m_exec_env);
    if (m_wasm_module_inst)
    {
        wasm_runtime_deinstantiate(m_wasm_module_inst);
    }
    wasm_runtime_destroy_thread_env();
}

quote3_error_t OPAEvaluateEngine::prepare_wasm(uint8_t *wasm_buf, size_t wasm_size, uint32_t stack_size, uint32_t heap_size)
{
    char error_buf[128] = {0};
    // Set the heap/stack size
    m_stack_size = stack_size;
    m_heap_size = heap_size;

    if (init_wasm_runtime_once(wasm_buf, wasm_size) != 1)
    {
        se_trace(SE_TRACE_ERROR, "Failed to initialize the wasm global environment.\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    if (wasm_runtime_init_thread_env() == false)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Failed to initialize the wasm thread environment.\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    // Instantiate the module
    if (!(m_wasm_module_inst = wasm_runtime_instantiate(g_wasm_module, m_stack_size, m_heap_size,
                                                        error_buf, sizeof(error_buf))))
    {
        SE_TRACE(SE_TRACE_DEBUG, "%s\n", error_buf);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    if (!(m_exec_env = wasm_runtime_create_exec_env(m_wasm_module_inst, m_stack_size)))
    {
        SE_TRACE(SE_TRACE_DEBUG, "Failed to create wasm execution environment.\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }
    int builtins = opa_builtins(m_wasm_module_inst, m_exec_env);
    CHECK_OPA_RET(builtins);

    int json_builtins = opa_json_dump(m_wasm_module_inst, m_exec_env, builtins);
    CHECK_OPA_RET(json_builtins);

    char *json_buffer_builtins = (char *)wasm_runtime_addr_app_to_native(m_wasm_module_inst, json_builtins);
    if (json_buffer_builtins == NULL)
        return SGX_QL_ERROR_UNEXPECTED;

    int ret = prepare_builtin_once(json_buffer_builtins);
    if (ret != 0)
        return SGX_QL_ERROR_UNEXPECTED;
    return SGX_QL_SUCCESS;
}

quote3_error_t OPAEvaluateEngine::start_eval(const uint8_t *input_json_buf, uint32_t json_size, const time_t appraisal_check_date, uint32_t *p_appraisal_result_token_buffer_size, uint8_t **p_appraisal_result_token)
{
    // Set the check data as `current time` for OPA builtin
    g_current_time = appraisal_check_date;
    int ctx = opa_eval_ctx_new(m_wasm_module_inst, m_exec_env);
    CHECK_OPA_RET(ctx);

    int input_buffer = opa_malloc(m_wasm_module_inst, m_exec_env, json_size);
    CHECK_OPA_RET(input_buffer);

    void *json_buffer = wasm_runtime_addr_app_to_native(m_wasm_module_inst, input_buffer);
    memset(json_buffer, 0, json_size);

    memcpy_s((void *)json_buffer, json_size, input_json_buf, json_size);

    int input = opa_json_parse(m_wasm_module_inst, m_exec_env, input_buffer, json_size);
    CHECK_OPA_RET(input);

    opa_eval_ctx_set_input(m_wasm_module_inst, m_exec_env, ctx, input);

    int ret = eval(m_wasm_module_inst, m_exec_env, ctx);
    if (ret != 0)
    {
        SE_TRACE(SE_TRACE_DEBUG, "OPA eval() returns failure\n");
        return SGX_QL_ERROR_UNEXPECTED;
    }

    int result = opa_eval_ctx_get_result(m_wasm_module_inst, m_exec_env, ctx);
    CHECK_OPA_RET(result);
    int json_result = opa_json_dump(m_wasm_module_inst, m_exec_env, result);
    CHECK_OPA_RET(json_result);

    char *json_buffer_result = (char *)wasm_runtime_addr_app_to_native(m_wasm_module_inst, json_result);
    se_trace(SE_TRACE_NOTICE, "eval result is: %s\n", (char *)json_buffer_result);
    opa_free(m_wasm_module_inst, m_exec_env, input_buffer);

    std::string str(json_buffer_result);

#ifndef BUILD_QAE
    auto token = jwt::create()
                     .set_type("JWT")
                     .set_issuer("quote appraisal entity")
                     .set_payload_claim("appraisal_result", jwt::claim(str))
                     .sign(jwt::algorithm::none{});
    se_trace(SE_TRACE_NOTICE, "Unsigned token: %s\n", token.c_str());
#else
    std::string jwk, priv_key;
    if (generate_ec384_keys(jwk, priv_key) != 0)
    {
        // Retry to generate ec key pair in case key generation fails randomly
        if (generate_ec384_keys(jwk, priv_key) != 0)
        {
            return SGX_QL_ERROR_UNEXPECTED;
        }
    }

    auto token = jwt::create()
                     .set_type("JWT")
                     .set_issuer("quote appraisal entity")
                     .set_header_claim("jwk", jwt::claim(jwk))
                     .set_payload_claim("appraisal_result", jwt::claim(str))
                     .sign(jwt::algorithm::es384("", priv_key, "", ""));
#endif

    uint8_t *result_token_buf = (uint8_t *)malloc(token.length() + 1);
    if(result_token_buf == NULL)
    {
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    memcpy_s(result_token_buf, token.length(), token.c_str(), token.length());
    result_token_buf[token.length()] = 0;
    *p_appraisal_result_token = result_token_buf;
    *p_appraisal_result_token_buffer_size = (uint32_t)token.length() + 1;

    return SGX_QL_SUCCESS;
}
