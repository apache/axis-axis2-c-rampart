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

#include <rampart_engine.h>
#include <axis2_ctx.h>
#include <axis2_svc.h>
#include <axis2_desc.h>
#include <axis2_policy_include.h>
#include <rp_secpolicy_builder.h>
#include <neethi_policy.h>
#include <rampart_authn_provider.h>
#include <rampart_util.h>
#include <rampart_constants.h>
#include <rampart_callback.h>
#include <axis2_msg.h>
#include <axis2_conf_ctx.h>
#include <rampart_handler_util.h>
#include <rampart_config.h>
#include <axis2_options.h>
#include <openssl_pkcs12_keystore.h>

/*This method sets all the configurations
 loads required modules and start rampart.*/


neethi_policy_t *AXIS2_CALL
build_policy(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_bool_t is_inflow);


axis2_status_t AXIS2_CALL
set_rampart_user_properties(
    const axutil_env_t *env,
    rampart_context_t *rampart_context);

axis2_status_t AXIS2_CALL
rampart_engine_retrieve_key_mgr_prop_from_policy(
	rampart_context_t *rampart_context, 
	const axutil_env_t *env);

AXIS2_EXTERN rampart_context_t *AXIS2_CALL
rampart_engine_build_configuration(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_bool_t is_inflow)
{

    rp_secpolicy_t *secpolicy = NULL;
    rampart_context_t *rampart_context = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    /*axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;*/
    axis2_bool_t is_server_side = AXIS2_TRUE;
    neethi_policy_t *policy = NULL;
    axutil_property_t *property = NULL;
    void *value = NULL;

	/* Key Manager related */
    oxs_key_mgr_t *key_mgr = NULL;
    axis2_char_t *password = NULL;
    axis2_char_t *enc_user = NULL;
    axis2_char_t *pkcs12_file = NULL;
    axis2_char_t *pkcs12_password = NULL;
    axis2_char_t *pkcs12_buf = NULL;
    password_callback_fn password_function = NULL;
    rampart_callback_t *password_callback = NULL;
    void *param = NULL;
    pkcs12_keystore_t *key_store = NULL;

    is_server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);

    /*policy has to be created for inflow and outflow for server side. 
    but for client side, it will be created only on outflow*/
    if(is_server_side || (!is_server_side && !is_inflow))
    {
        policy = build_policy(env, msg_ctx, is_inflow);
        if(!policy)
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Error in the Internal configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_engine] Policy creation failed.");
            return NULL;
        }
    }
    
    /*for server side's outflow and client side's inflow, we have to use rampart context created in 
    server side's inflow or client side's out flow*/
    if((is_server_side && !is_inflow) || (!is_server_side && is_inflow))
    {
        property = axis2_msg_ctx_get_property(msg_ctx, env, RAMPART_CONTEXT);
        if(property)
        {
            rampart_context = (rampart_context_t *)axutil_property_get_value(property, env);

            /*for serverside, recreate security policy and attach it to rampart context. This is because, 
            there might be differnt policy for inflow and outflow (only for server side. we are still not 
            supporting this feature for client side*/
            if(is_server_side)
            {
                secpolicy = rp_secpolicy_builder_build(env, policy);
                if(!secpolicy)
                {
                    rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                                  "Error in the Internal security policy configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][rampart_engine] Cannot create security policy from policy.");
                    return NULL;
                }
                rampart_context_set_secpolicy(rampart_context, env, secpolicy);
            }
            return (rampart_context_t *)axutil_property_get_value(property, env);
        }
        else
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Error in the Internal security policy configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_engine] Cannot get saved rampart_context");
            return NULL;
        }
    }

    /*rampart context will be created for server side's inflow and client side's out flow*/
    value = rampart_get_rampart_configuration(env, msg_ctx, RAMPART_CONFIGURATION);
    if(value)
    {
        rampart_context = (rampart_context_t *)value;
        rampart_context_increment_ref(rampart_context, env);
        if(!rampart_context_get_secpolicy(rampart_context, env))
        {
            secpolicy = rp_secpolicy_builder_build(env, policy);
            if(!secpolicy)
            {
                rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                              "Error in the Internal security policy configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_engine] Cannot create security policy from policy.");

                return NULL;
            }
            rampart_context_set_secpolicy(rampart_context, env, secpolicy);
        }
    }
    else
    {
        rampart_context = rampart_context_create(env);
        secpolicy = rp_secpolicy_builder_build(env, policy);
        if(!secpolicy)
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Error in the Internal configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_engine] Cannot create security policy from policy.");

            rampart_context_free(rampart_context, env);
            rampart_context = NULL;
            return NULL;
        }

        rampart_context_set_secpolicy(rampart_context, env, secpolicy);
        status = set_rampart_user_properties(env, rampart_context);
        if(status != AXIS2_SUCCESS)
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Error in the Internal configuration.", RAMPART_FAULT_IN_POLICY, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_engine] rampc policies creation failed.");

            rampart_context_free(rampart_context, env);
            rampart_context = NULL;
            return NULL;
        }  
        
        rampart_engine_retrieve_key_mgr_prop_from_policy(rampart_context, env);
    }
    
    key_mgr = rampart_context_get_key_mgr(rampart_context, env);
    if (!key_mgr)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][engine] Key mgr creation failed.");
            return NULL;
    }		

    /* Retrieve the password for obtaining private keys */
    enc_user = rampart_context_get_encryption_user(rampart_context, env);
    if(!enc_user)
    {
        enc_user = rampart_context_get_user(rampart_context, env);
    }
    if(enc_user)
    {
        password_function = rampart_context_get_pwcb_function(rampart_context, env);
        if(password_function)
        {
            password = (*password_function)(env, enc_user, param);
            pkcs12_password = password;
        }
        else
        {
            password_callback = rampart_context_get_password_callback(
                                    rampart_context, env);
            if(password_callback)
            {
                password = rampart_callback_password(env, password_callback, enc_user);
                pkcs12_password = rampart_callback_pkcs12_password(env, password_callback, enc_user);
            }
            else
            {
                password = rampart_context_get_password(rampart_context, env);
                pkcs12_password = password;
            }
        }
    } 
    
    pkcs12_file = rampart_context_get_pkcs12_file_name(rampart_context, env);
    if(pkcs12_file && pkcs12_password)
    {
        key_store = pkcs12_keystore_create(env, pkcs12_file, pkcs12_password);
        if(!key_store)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][engine] PKCS12 KeyStore creation failed.");
            return NULL;	
        }        
    }
    else if(pkcs12_password && (pkcs12_buf = (axis2_char_t*)rampart_context_get_key_store_buff(rampart_context, env)))
    {
        key_store = pkcs12_keystore_create_from_buffer(env, pkcs12_buf, password,
                    oxs_key_mgr_get_key_store_buff_len(key_mgr, env));
        if(!key_store)
        {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][engine] PKCS12 KeyStore creation failed.");
                return NULL;	
        }  
    }
    
    oxs_key_mgr_set_key_store(key_mgr, env, key_store);

    if (password)
    {
        oxs_key_mgr_set_prv_key_password(key_mgr, env, password);
    }
    
    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST ,
               AXIS2_TRUE, (void *)rampart_context_free, rampart_context);
    axis2_msg_ctx_set_property(msg_ctx, env, RAMPART_CONTEXT, property);

    /*For the client side*/
    if(!is_server_side)
    {
        value = axis2_msg_ctx_get_property_value(msg_ctx, env, RAMPART_CLIENT_CONFIGURATION);
        if(value)
        {
            rampart_config_t *client_config = NULL;
            axutil_array_list_t *saml_tokens = NULL;
            axis2_char_t *config_value = NULL;
            issued_token_callback_func issued_token_aquire = NULL;
            int ttl = 0;

            client_config = (rampart_config_t*)value;
            config_value = rampart_config_get_username(client_config, env);
            if(config_value)
            {
                rampart_context_set_user(rampart_context, env, config_value);
            }
            
            config_value = rampart_config_get_password(client_config, env);
            if(config_value)
            {
                rampart_context_set_password(rampart_context, env, config_value);
            }

            config_value = rampart_config_get_password_type(client_config, env);
            if(config_value)
            {
                rampart_context_set_password_type(rampart_context, env, config_value);
            }

            ttl = rampart_config_get_ttl(client_config, env);
            if(ttl > 0)
            {
                rampart_context_set_ttl(rampart_context, env, ttl);
            }
            saml_tokens = rampart_config_get_saml_tokens(client_config, env);
            if (saml_tokens)
            {
                rampart_context_set_saml_tokens(rampart_context, env, saml_tokens);
            }
            issued_token_aquire = rampart_config_get_issued_token_aquire_function(client_config, env);
            if (issued_token_aquire)
            {
                rampart_context_set_issued_token_aquire_function(rampart_context, env, issued_token_aquire); 
            }
        }
    }
    else
    { /*Server side only*/
        /*We set our default impl of replay detection function. if the module is not set, then 
		 * this function will be used*/
        if(is_inflow)
        {
            rampart_context_set_replay_detect_function(rampart_context, env, rampart_replay_detector_with_linked_list);
        }
    }
    return rampart_context;
}


neethi_policy_t *AXIS2_CALL
build_policy(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axis2_bool_t is_inflow)
{

    axis2_svc_t *svc = NULL;
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    neethi_policy_t *service_policy = NULL;
    axis2_op_t *op = NULL;
    axis2_msg_t *msg = NULL;

    svc =  axis2_msg_ctx_get_svc(msg_ctx,env);
    if(!svc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_neethi] Service is NULL.");
        return NULL;
    }

    op = axis2_msg_ctx_get_op(msg_ctx, env);
    if(!op)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_engine] Operation is NULL.");
        return NULL;
    }

    if(is_inflow)
    {
        msg = axis2_op_get_msg(op, env, "in");
    }
    else
    {
        msg = axis2_op_get_msg(op, env, "out");
    }

    if(!msg)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_engine] Message is NULL.");
        return NULL;
    }

    /*desc = axis2_svc_get_base(svc, env);*/

    desc = axis2_msg_get_base(msg, env);
    if(!desc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_engine] axis2 description is NULL.");
        return NULL;
    }

    policy_include = axis2_desc_get_policy_include(desc, env);
    if(!policy_include)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_engine] Policy include is NULL.");
        return NULL;
    }
    /*service_policy = axis2_policy_include_get_policy(policy_include, env);*/

    service_policy = axis2_policy_include_get_effective_policy(policy_include, env);

    if(!service_policy)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_engine] Policy is NULL.");
        return NULL;
    }

    return service_policy;

}


axis2_status_t AXIS2_CALL
set_rampart_user_properties(
    const axutil_env_t *env,
    rampart_context_t *rampart_context)
{

    rampart_callback_t* password_callback_module = NULL;
    rampart_authn_provider_t *authn_provider = NULL;
	rampart_replay_detector_t *replay_detector = NULL;
    rampart_sct_provider_t* sct_provider = NULL;
    axis2_char_t *pwcb_module_name = NULL;
    axis2_char_t *authn_provider_name = NULL;
	axis2_char_t *replay_detector_name = NULL;
    axis2_char_t *sct_provider_name = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    status = rampart_context_set_user_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    status = rampart_context_set_ttl_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    status = rampart_context_set_rd_val_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    status = rampart_context_set_password_type_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    pwcb_module_name = rampart_context_get_password_callback_class(rampart_context,env);
    if(pwcb_module_name)
    {
        password_callback_module = rampart_load_pwcb_module(env, pwcb_module_name);
        if(password_callback_module)
            rampart_context_set_password_callback(rampart_context,env,password_callback_module);
    }

    authn_provider_name = rampart_context_get_authn_module_name(rampart_context,env);
    if(authn_provider_name)
    {
        authn_provider = rampart_load_auth_module(env,authn_provider_name);
        if(authn_provider)
            rampart_context_set_authn_provider(rampart_context,env,authn_provider);
    }

    replay_detector_name = rampart_context_get_replay_detector_name(rampart_context,env);
    if(replay_detector_name)
    {
        replay_detector = rampart_load_replay_detector(env,replay_detector_name);
        if(replay_detector)
            rampart_context_set_replay_detector(rampart_context,env,(void*)replay_detector);
    }

    sct_provider_name = rampart_context_get_sct_provider_name(rampart_context,env);
    if(sct_provider_name)
    {
        sct_provider = rampart_load_sct_provider(env,sct_provider_name);
        if(sct_provider)
            rampart_context_set_sct_provider(rampart_context,env,(void*)sct_provider);
    }
    return status;
}

axis2_status_t AXIS2_CALL
rampart_engine_retrieve_key_mgr_prop_from_policy(rampart_context_t *rampart_context, 
												 const axutil_env_t *env)
{	
	axis2_char_t *value = NULL;
	rp_rampart_config_t *config = NULL;    
	oxs_key_mgr_t *key_mgr = NULL;
	rp_secpolicy_t *secpolicy = NULL;
	secpolicy = rampart_context_get_secpolicy(rampart_context, env);
    config = rp_secpolicy_get_rampart_config(secpolicy, env);
    if (!config)
        return AXIS2_FAILURE;    

	key_mgr = rampart_context_get_key_mgr(rampart_context, env);

	value = rp_rampart_config_get_certificate_file(config, env);
	if (value)
	{
		oxs_key_mgr_set_certificate_file(key_mgr, env, value);
	}

	value = rp_rampart_config_get_private_key_file(config, env);
	if (value)
	{
		oxs_key_mgr_set_private_key_file(key_mgr, env, value);
	}

	value = rp_rampart_config_get_receiver_certificate_file(config, env);
	if (value)
	{
		oxs_key_mgr_set_reciever_certificate_file(key_mgr, env, value);
	}
	return AXIS2_SUCCESS;
}
