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

#include "opa_helper.h"
#include "opa_builtins.h"
#include "qal_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* opa export functions */

// value_addr builtins(void)
int opa_builtins(wasm_module_inst_t module_inst,  wasm_exec_env_t exec_env)
{
    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "builtins"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for builtins\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 0, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for builtins\n");
        return 0;
    }

    return rets[0].of.i32;

}

//opa_eval_ctx_t *opa_eval_ctx_new()
int opa_eval_ctx_new(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env)
{
    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_eval_ctx_new"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_eval_ctx_new\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 0, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_eval_ctx_new\n");
        return 0;
    }
    return rets[0].of.i32;
}

//void opa_eval_ctx_set_input(opa_eval_ctx_t *ctx, opa_value *v)
void opa_eval_ctx_set_input(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int ctx, int v)
{

    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_eval_ctx_set_input"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_eval_ctx_set_input\n");
	    return;
    }

    wasm_val_t rets[1];
    wasm_val_t args[2];
    args[0].kind = WASM_I32;
    args[0].of.i32 = ctx;
    args[1].kind = WASM_I32;
    args[1].of.i32= v;


    if(!wasm_runtime_call_wasm_a(exec_env, func, 0, rets, 2, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_eval_ctx_set_input\n");
        return;
    }

    return;
}
#if 0
//void opa_eval_ctx_set_data(opa_eval_ctx_t *ctx, opa_value *v)
void opa_eval_ctx_set_data(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, void *ctx, void *v)
{

}

//void opa_eval_ctx_set_entrypoint(opa_eval_ctx_t *ctx, int entrypoint)
void opa_eval_ctx_set_entrypoint(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, void *ctx, int entrypoint)
{
}
#endif
//int32_t eval(opa_eval_ctx_t *ctx)
int eval(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int ctx)
{

    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "eval"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for eval\n");
	    return -1;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = ctx;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for eval\n");
        return -1;
    }
    // eval's return value is reserved. So we will directly return 0 instead of rets.
    return 0;
}

//opa_value *opa_eval_ctx_get_result(opa_eval_ctx_t *ctx)
int opa_eval_ctx_get_result(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int ctx)
{
    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_eval_ctx_get_result"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_eval_ctx_get_result\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = ctx;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_eval_ctx_get_result\n");
        return 0;
    }

    return rets[0].of.i32;
}

//void *opa_malloc(size_t size)
int opa_malloc(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, uint32_t size)
{

    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_malloc"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_malloc\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = (int)size;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_malloc\n");
        return 0;
    }

    return rets[0].of.i32;
}

// opa_free
void opa_free(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int addr)
{
   wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_free"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_free\n");
	    return;
    }
    
    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = addr;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 0, NULL, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_free\n");
        return;
    }

    return;
}
//opa_value *opa_json_parse(const char *input, size_t len);
int opa_json_parse(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int input, uint32_t len)
{

    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_json_parse"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_json_parse\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[2];
    args[0].kind = WASM_I32;
    args[0].of.i32 = input;
    args[1].kind = WASM_I32;
    args[1].of.i32 = (int)len;


    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 2, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_json_parse\n");
        return 0;
    }

    return rets[0].of.i32;
}


//char *opa_json_dump(opa_value *v)
int opa_json_dump(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int v)
{

    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_json_dump"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_json_dump\n");
	    return 0;
    }

    wasm_val_t rets[1];
    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = v;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_json_dump\n");
        return 0;
    }

    return rets[0].of.i32;

}

//addr opa_heap_ptr_get(void)
int opa_heap_ptr_get(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env)
{
    wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_heap_ptr_get"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_heap_ptr_get\n");
	    return 0;
    }

    wasm_val_t rets[1];


    if(!wasm_runtime_call_wasm_a(exec_env, func, 1, rets, 0, NULL)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_heap_ptr_get\n");
        return 0;
    }

    return rets[0].of.i32;
}

//void opa_heap_ptr_set(addr)
void opa_heap_ptr_set(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env, int addr)
{
       wasm_function_inst_t func = NULL;

    if(!(func = wasm_runtime_lookup_function(module_inst, "opa_heap_ptr_set"))){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_lookup_function for opa_heap_ptr_set\n");
	    return;
    }

    wasm_val_t args[1];
    args[0].kind = WASM_I32;
    args[0].of.i32 = addr;

    if(!wasm_runtime_call_wasm_a(exec_env, func, 0, NULL, 1, args)){
        SE_TRACE(SE_TRACE_DEBUG, "Failed in wasm_runtime_call_wasm_a for opa_heap_ptr_set\n");
        return;
    }

    return;
}




/* opa import functions */

//opa_value *opa_builtin0(wasm_exec_env_t exec_env, int, void *)
int opa_builtin0(wasm_exec_env_t exec_env, int builtin_id, void *ctx)
{
    UNUSED(ctx);

    std::map<int,std::string>::iterator it = g_builtins.find(builtin_id);
    if(it != g_builtins.end())
    {
        std::string str = it->second;
        std::map<std::string, void *>::iterator it2 = g_builtin_func_map.find(str);
        if (it2 != g_builtin_func_map.end())
        {
            // currently we only have one function for opa_builtin0
            now_ns_t func = (now_ns_t)it2->second;
            uint64_t result = func();
            std::string s = std::to_string(result);
            wasm_module_inst_t wasm_inst = get_module_inst(exec_env);

            int input_buffer = opa_malloc(wasm_inst, exec_env, (uint32_t)s.length()+1);
            if( input_buffer == 0)
            {
                abort();
            }

            void *json_buffer = wasm_runtime_addr_app_to_native(wasm_inst, input_buffer);
            memset(json_buffer, 0, s.length()+1);
            memcpy_s((void *)json_buffer, s.length(), s.c_str(), s.length());
            int memory = opa_json_parse(wasm_inst, exec_env, input_buffer, (uint32_t)s.length());
            if(memory == 0)
            {
                abort();
            }
            return memory;
        }
        else
        {
            SE_TRACE(SE_TRACE_DEBUG, "\n Didn't find the function - builtID: %d, function_name: %s\n", builtin_id, str.c_str());
            abort();
        }
    }

    return 0;
}

//opa_value *opa_builtin1(wasm_exec_env_t exec_env, int, void *, opa_value *)
int opa_builtin1(wasm_exec_env_t exec_env, int builtin_id, void *ctx, opa_value* a1)
{   
    UNUSED(ctx);

    std::map<int,std::string>::iterator it = g_builtins.find(builtin_id);
    if(it != g_builtins.end())
    {
        std::string str = it->second;
        std::map<std::string, void *>::iterator it2 = g_builtin_func_map.find(str);
        if (it2 != g_builtin_func_map.end())
        {
            // Currently we only have one function for opa builtin1
            time_func_t func = (time_func_t)it2->second;
            wasm_module_inst_t wasm_inst = get_module_inst(exec_env);
            int addr = wasm_runtime_addr_native_to_app(wasm_inst, a1);
            int arg = opa_json_dump(wasm_inst, exec_env, addr);
            char *json_arg = (char *)wasm_runtime_addr_app_to_native(wasm_inst, arg);
            uint64_t result = func(json_arg);
            std::string s = std::to_string(result);

            int input_buffer = opa_malloc(wasm_inst, exec_env, (uint32_t)s.length()+1);
            if( input_buffer == 0)
            {
                abort();
            }

            void *json_buffer = wasm_runtime_addr_app_to_native(wasm_inst, input_buffer);
            memset(json_buffer, 0, s.length()+1);
            memcpy_s((void *)json_buffer, s.length(), s.c_str(), s.length());
            int memory = opa_json_parse(wasm_inst, exec_env, input_buffer, (uint32_t)s.length());
            if(memory == 0)
            {
                abort();
            }
            return memory;
        }
        else
        {
            SE_TRACE(SE_TRACE_DEBUG, "Didn't find the function - builtID: %d, function_name: %s\n", builtin_id, str.c_str());
            abort();
        }
    }
    return 0;
}

// opa_value *opa_builtin2(wasm_exec_env_t exec_env, int, void *, opa_value *, opa_value *)
int opa_builtin2(wasm_exec_env_t exec_env, int builtin_id, void *ctx, opa_value *a1, opa_value *a2)
{
    UNUSED(ctx);
    std::map<int, std::string>::iterator it = g_builtins.find(builtin_id);
    if (it != g_builtins.end())
    {
        std::string str = it->second;
        std::map<std::string, void *>::iterator it2 = g_builtin_func_map.find(str);
        if (it2 != g_builtin_func_map.end())
        {
            // Currently we only have one function for opa builtin2
            rand_n_func_t func = (rand_n_func_t)it2->second;
            wasm_module_inst_t wasm_inst = get_module_inst(exec_env);

            int addr1 = wasm_runtime_addr_native_to_app(wasm_inst, a1);
            int arg1 = opa_json_dump(wasm_inst, exec_env, addr1);
            char *json_arg1 = (char *)wasm_runtime_addr_app_to_native(wasm_inst, arg1);

            int addr2 = wasm_runtime_addr_native_to_app(wasm_inst, a2);
            int arg2 = opa_json_dump(wasm_inst, exec_env, addr2);
            char *json_arg2 = (char *)wasm_runtime_addr_app_to_native(wasm_inst, arg2);
            uint64_t val = strtoull(json_arg2, NULL, 10);
            uint64_t result = func(json_arg1, val);
            std::string s = std::to_string(result);

            int input_buffer = opa_malloc(wasm_inst, exec_env, (uint32_t)s.length() + 1);
            if( input_buffer == 0)
            {
                abort();
            }

            void *json_buffer = wasm_runtime_addr_app_to_native(wasm_inst, input_buffer);
            memset(json_buffer, 0, s.length()+1);
            memcpy_s((void *)json_buffer, s.length(), s.c_str(), s.length());
            int memory = opa_json_parse(wasm_inst, exec_env, input_buffer, (uint32_t)s.length());
            if (memory == 0)
            {
                abort();
            }
            return memory;
        }
        else
        {
            SE_TRACE(SE_TRACE_DEBUG, "Didn't find the function - builtID: %d, function_name: %s\n", builtin_id, str.c_str());
            abort();
        }
    }

    return 0;
}
// opa_value *opa_builtin3(wasm_exec_env_t exec_env, int, void *, opa_value *, opa_value *, opa_value *)
int opa_builtin3(wasm_exec_env_t exec_env, int builtin_id, void *ctx, opa_value* a1, opa_value* a2, opa_value* a3)
{   
    UNUSED(exec_env);
    UNUSED(builtin_id);
    UNUSED(ctx);
    UNUSED(a1);
    UNUSED(a2);
    UNUSED(a3);
    
    SE_TRACE(SE_TRACE_DEBUG, "opa_builtin3\n");
    return 0;
}
//opa_value *opa_builtin4(wasm_exec_env_t exec_env, int, void *, opa_value *, opa_value *, opa_value *, opa_value *)
int opa_builtin4(wasm_exec_env_t exec_env, int builtin_id, void *ctx, opa_value* a1, opa_value* a2, opa_value* a3, opa_value* a4)
{   
    UNUSED(exec_env);
    UNUSED(builtin_id);
    UNUSED(ctx);
    UNUSED(a1);
    UNUSED(a2);
    UNUSED(a3);
    UNUSED(a4);

    SE_TRACE(SE_TRACE_DEBUG, "opa_builtin4\n");
    return 0;
}

void opa_abort(wasm_exec_env_t exec_env, const char *msg)
{
    wasm_module_inst_t wasm_inst = get_module_inst(exec_env);
    int addr = wasm_runtime_addr_native_to_app(wasm_inst, (void *)msg);
    int arg = opa_json_dump(wasm_inst, exec_env, addr);
    char *json_arg = (char *)wasm_runtime_addr_app_to_native(wasm_inst, arg);
    se_trace(SE_TRACE_ERROR, "abort message = %s\n", json_arg);
    abort();
}
