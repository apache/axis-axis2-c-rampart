/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *
 */
#include <stdio.h>
#include <rampart_util.h>
#include <axis2_util.h>
#include <axutil_base64.h>
#include <axutil_property.h>
#include <time.h>
#include <axis2_msg_ctx.h>
#include <rampart_constants.h>
#include <rampart_callback.h>
#include <rampart_credentials.h>
#include <rampart_replay_detector.h>
#include <rampart_sct_provider.h>
#include <oxs_buffer.h>
#include <oxs_utility.h>
#include <rampart_context.h>

/*Calculate the hash of concatenated string of
 * nonce, created and the password.
 *
 */
#define SIZE 256
#define SIZE_HASH 32
#define SIZE_NONCE 24


/*#define PRINTINFO 1 */

AXIS2_EXTERN void* AXIS2_CALL
rampart_load_module(const axutil_env_t *env,
                    axis2_char_t *module_name,
                    axutil_param_t **param)
{
    axutil_dll_desc_t *dll_desc = NULL;
    axutil_param_t *impl_info_param = NULL;
    void *ptr = NULL;

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Trying to load module = %s", module_name);
    dll_desc = axutil_dll_desc_create(env);
    axutil_dll_desc_set_name(dll_desc, env, module_name);
    impl_info_param = axutil_param_create(env, NULL, dll_desc);
    /*Set the free function*/
    axutil_param_set_value_free(impl_info_param, env, axutil_dll_desc_free_void_arg);
    axutil_class_loader_init(env);
    ptr = axutil_class_loader_create_dll(env, impl_info_param);

    *param = impl_info_param;

    if (!ptr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to load the module %s. ERROR", module_name);
        return NULL;
    }

    return ptr;
}

AXIS2_EXTERN rampart_credentials_status_t AXIS2_CALL
rampart_call_credentials(const axutil_env_t *env,
                         rampart_credentials_t *cred_module,
                         axis2_msg_ctx_t *msg_ctx,
                         axis2_char_t **username,
                         axis2_char_t **password)
{
    rampart_credentials_status_t cred_status = RAMPART_CREDENTIALS_GENERAL_ERROR;

    cred_status = RAMPART_CREDENTIALS_USERNAME_GET(cred_module, env, msg_ctx, username, password);
    return cred_status;
}

AXIS2_EXTERN rampart_credentials_t* AXIS2_CALL
rampart_load_credentials_module(const axutil_env_t *env,
                                axis2_char_t *cred_module_name)
{
    rampart_credentials_t *cred = NULL;
    axutil_param_t *param = NULL;

    cred = (rampart_credentials_t*)rampart_load_module(env, cred_module_name, &param);
    if (!cred)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to identify the credentials  module %s. ERROR", cred_module_name);
        return AXIS2_FAILURE;
    }
    if(param){
        cred->param = param;
    }

    return cred;
}

AXIS2_EXTERN rampart_authn_provider_t* AXIS2_CALL
rampart_load_auth_module(const axutil_env_t *env,
                         axis2_char_t *auth_module_name)
{
    rampart_authn_provider_t *authp = NULL;
    axutil_param_t *param = NULL;

    authp = (rampart_authn_provider_t*)rampart_load_module(env, auth_module_name, &param);
    if (!authp)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to identify the authentication module %s. ERROR", auth_module_name);
        return AXIS2_FAILURE;
    }
    if(param){
        authp->param = param;
    }

    return authp;
}

AXIS2_EXTERN rampart_replay_detector_t* AXIS2_CALL
rampart_load_replay_detector(const axutil_env_t *env,
                         axis2_char_t *replay_detector_name)
{
    rampart_replay_detector_t *rd = NULL;
    axutil_param_t *param = NULL;

    rd = (rampart_replay_detector_t*)rampart_load_module(env, replay_detector_name, &param);
    if (!rd)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to identify the replay detection  module %s. ERROR", replay_detector_name);
        return AXIS2_FAILURE;
    }
    if(param){
        rd->param = param;
    }

    return rd;
}

AXIS2_EXTERN rampart_sct_provider_t* AXIS2_CALL
rampart_load_sct_provider(const axutil_env_t *env,
                         axis2_char_t *sct_provider_name)
{
    rampart_sct_provider_t *sct_provider = NULL;
    axutil_param_t *param = NULL;

    sct_provider = (rampart_sct_provider_t*)rampart_load_module(env, sct_provider_name, &param);
    if (!sct_provider)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to identify the security context token provider module %s. ERROR", sct_provider_name);
        return AXIS2_FAILURE;
    }
    if(param)
    {
        sct_provider->param = param;
    }

    return sct_provider;
}

AXIS2_EXTERN rampart_callback_t* AXIS2_CALL
rampart_load_pwcb_module(const axutil_env_t *env,
                         axis2_char_t *callback_module_name)
{
    rampart_callback_t *cb = NULL;
    axutil_param_t *param = NULL;

    cb = (rampart_callback_t*)rampart_load_module(env, callback_module_name, &param);
    if (!cb)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_util] Unable to identify the callback module %s. ERROR", callback_module_name);
        if (param)
        {
			axutil_param_free(param, env);
            param = NULL;
        }
        return AXIS2_FAILURE;
    }
    if(param){
        cb->param = param;
    }
    return cb;

}

AXIS2_EXTERN rampart_authn_provider_status_t AXIS2_CALL
rampart_authenticate_un_pw(const axutil_env_t *env,
                           rampart_authn_provider_t *authp,
                           const axis2_char_t *username,
                           const axis2_char_t *password,
                           const axis2_char_t *nonce,/*Can be NULL if plain text*/
                           const axis2_char_t *created,/*Can be NULL if plain text*/
                           const axis2_char_t *password_type,
                           axis2_msg_ctx_t *msg_ctx)
{
    rampart_authn_provider_status_t auth_status = RAMPART_AUTHN_PROVIDER_GENERAL_ERROR;

    if (!authp)
    {
        return RAMPART_AUTHN_PROVIDER_GENERAL_ERROR;
    }
    /*If password digest*/
    if(0 == axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST_URI)){
        auth_status = RAMPART_AUTHN_PROVIDER_CHECK_PASSWORD_DIGEST(authp, env, msg_ctx, username, nonce, created, password);
    }else{
        auth_status = RAMPART_AUTHN_PROVIDER_CHECK_PASSWORD(authp, env, msg_ctx, username, password);
    }

    return auth_status;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_callback_password(const axutil_env_t *env,
                          rampart_callback_t *callback_module,
                          const axis2_char_t *username)
{
    axis2_char_t *password = NULL;
    void *cb_prop_val= NULL;

    /*Get the password thru the callback*/
    password = RAMPART_CALLBACK_CALLBACK_PASSWORD(callback_module, env, username, cb_prop_val);

    AXIS2_LOG_INFO(env->log, "[rampart][rampart_util] Password taken from the callback module . SUCCESS");
    return password;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_generate_nonce(const axutil_env_t *env, int length)
{
    return oxs_util_generate_nonce(env, length);
}


AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_generate_time(const axutil_env_t *env, int ttl)
{
    axutil_date_time_t *dt = NULL;
    axis2_char_t *dt_str = NULL;

    dt = axutil_date_time_create_with_offset(env, ttl);
    dt_str =  axutil_date_time_serialize_date_time(dt, env);
    axutil_date_time_free(dt, env);
    return dt_str;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_compare_date_time(const axutil_env_t *env, axis2_char_t *dt1_str, axis2_char_t *dt2_str)
{
    axis2_status_t status = AXIS2_FAILURE;
    axutil_date_time_t *dt1 = NULL;
    axutil_date_time_t *dt2 = NULL;
    axutil_date_time_comp_result_t res = AXIS2_DATE_TIME_COMP_RES_UNKNOWN;
#if 0
    int yyyy1, mm1, dd1, hh1, mi1, ss1, ml1;
    int yyyy2, mm2, dd2, hh2, mi2, ss2, ml2;
#endif
    dt1 = axutil_date_time_create(env);
    dt2 = axutil_date_time_create(env);

    status =  axutil_date_time_deserialize_date_time(dt1, env, dt1_str);
    if (status == AXIS2_FAILURE)
    {
        axutil_date_time_free(dt1, env);
        axutil_date_time_free(dt2, env);
        return AXIS2_FAILURE;
    }

    status =  axutil_date_time_deserialize_date_time(dt2, env, dt2_str);
    if (status == AXIS2_FAILURE)
    {
        axutil_date_time_free(dt1, env);
        axutil_date_time_free(dt2, env);
        return AXIS2_FAILURE;
    }

    /*dt1<dt2 for SUCCESS*/
    res = axutil_date_time_compare(dt1, env, dt2);
    axutil_date_time_free(dt1, env);
    axutil_date_time_free(dt2, env);
    if(AXIS2_DATE_TIME_COMP_RES_NOT_EXPIRED == res){
        return AXIS2_SUCCESS;
    }else{
        return AXIS2_FAILURE;
    }

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_print_info(const axutil_env_t *env, axis2_char_t* info)
{
#ifdef PRINTINFO
    printf("[rampart]: %s\n", info);
#endif
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
is_different_session_key_for_encryption_and_signing(const axutil_env_t *env,
                                                    rampart_context_t *rampart_context)
{
    rp_property_t *binding = NULL;
    binding = rp_secpolicy_get_binding(rampart_context_get_secpolicy(rampart_context, env),env);
    if(binding)
    {
        if(rp_property_get_type(binding,env) == RP_PROPERTY_SYMMETRIC_BINDING)
        {
            rp_symmetric_binding_t *sym_binding = NULL;
            rp_property_t *token = NULL;
            sym_binding = (rp_symmetric_binding_t *)rp_property_get_value(binding,env);
            if(sym_binding)
            {
                /*check protection tokens have being specified. If not, use the different session key for 
                  encryption and signature */
                token = rp_symmetric_binding_get_protection_token(sym_binding,env);
                if(!token)
                    return AXIS2_TRUE;
            }
        }
    }

    return AXIS2_FALSE;
}


