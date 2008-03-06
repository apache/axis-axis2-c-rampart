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
#include <rampart_handler_util.h>
#include <rampart_constants.h>
#include <oxs_constants.h>
#include <oxs_axiom.h>
#include <oxs_utility.h>
#include <rampart_sec_processed_result.h>

/*Private functions*/

static axis2_status_t
rampart_pv_validate_ts(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    if(rampart_context_is_include_timestamp(rampart_context, env)){
        axis2_char_t *ts_found = NULL;
        ts_found = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_TS_CHECKED);
        if(0 == axutil_strcmp(RAMPART_YES, ts_found)){
            return AXIS2_SUCCESS;
        }else{
            /*Error*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Timestamp token required. Not found");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Timestamp token required. Cannot find in the security header",
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }else{
        return AXIS2_SUCCESS;
    }
}

static axis2_status_t
rampart_pv_validate_ut(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    if(!axis2_msg_ctx_get_server_side(msg_ctx,env))
        return AXIS2_SUCCESS;

    if(rampart_context_is_include_username_token(rampart_context, env)){
        axis2_char_t *ut_found = NULL;
        ut_found = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_UT_CHECKED);
        if(0 == axutil_strcmp(RAMPART_YES, ut_found)){
            return AXIS2_SUCCESS;
        }else{
            /*Error*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Username token required. Not found");
            AXIS2_ERROR_SET(env->error, RAMPART_ERROR_INVALID_SECURITY , AXIS2_FAILURE);
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Username token required. Cannot find in the security header",
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }else{
        return AXIS2_SUCCESS;
    }
}

static axis2_status_t
rampart_pv_validate_signature_confirmation(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    axis2_bool_t sig_conf_reqd = AXIS2_FALSE;
    if(axis2_msg_ctx_get_server_side(msg_ctx,env))
        return AXIS2_SUCCESS;

    sig_conf_reqd = rampart_context_is_sig_confirmation_reqd(rampart_context, env);
    
    if(AXIS2_TRUE == sig_conf_reqd){
        axis2_char_t* sig_conf_found = NULL;
        sig_conf_found = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_CONFIRM_FOUND);
        if(0 == axutil_strcmp(RAMPART_YES, sig_conf_found)){
            return AXIS2_SUCCESS;
        }else{
            /*Error*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Signature confirmation required.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "SignatureConfirmation is not found",
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }else{
        return AXIS2_SUCCESS;
    } 
}

static axis2_status_t
rampart_pv_validate_signature_encryption(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    axis2_bool_t signature_protection = AXIS2_FALSE;

    signature_protection = rampart_context_is_encrypt_signature(
                                   rampart_context, env);
    if(AXIS2_TRUE == signature_protection){
        axis2_char_t* sig_encrypted = NULL;
        sig_encrypted = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_ENCRYPTED);
        if(0 == axutil_strcmp(RAMPART_YES, sig_encrypted)){
            return AXIS2_SUCCESS;
        }else{
            /*Error*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Signature need to be encrypted.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Signature need to be encrypted", 
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }else{
        return AXIS2_SUCCESS;
    }
}
/*We validate only the body encryption*/
static axis2_status_t
rampart_pv_validate_encryption(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    axis2_bool_t body_encryption = AXIS2_FALSE;
    axis2_status_t status = AXIS2_SUCCESS;
    axutil_array_list_t *nodes_to_encrypt = NULL;
    axiom_soap_envelope_t *soap_envelope = NULL;
    int i = 0;

    nodes_to_encrypt = axutil_array_list_create(env, 0);
    soap_envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
   
    status = rampart_context_get_nodes_to_encrypt(
                  rampart_context, env, soap_envelope, nodes_to_encrypt);

    status = rampart_context_get_elements_to_encrypt(
                  rampart_context, env, soap_envelope, nodes_to_encrypt);

    /*See if the body need to be encrypted*/
    if(nodes_to_encrypt && (axutil_array_list_size(nodes_to_encrypt, env) > 0))
	{
        for(i=0 ; i < axutil_array_list_size(nodes_to_encrypt, env); i++)
        {
            axiom_node_t *node_to_enc = NULL;
            
            /*Get the node to be encrypted*/
            node_to_enc = (axiom_node_t *)axutil_array_list_get
                      (nodes_to_encrypt, env, i);
            if(node_to_enc)
			{
                if(0 == axutil_strcmp( OXS_NODE_BODY , axiom_util_get_localname(axiom_node_get_parent(node_to_enc,env), env)))
				{
                    body_encryption = AXIS2_TRUE;
                    break;
                }
            }
        }/*Eof loop*/
    }
	else
	{
		axutil_array_list_free(nodes_to_encrypt, env);
        return AXIS2_SUCCESS;
    }
    
	axutil_array_list_free(nodes_to_encrypt, env);

    if(AXIS2_TRUE == body_encryption)
	{
        axis2_char_t* body_encrypted = NULL;
        body_encrypted = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_BODY_ENCRYPTED);
        if(0 == axutil_strcmp(RAMPART_YES, body_encrypted))
		{
            return AXIS2_SUCCESS;
        }
		else
		{
            /*Error*/
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Body need to be encrypted.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Body need to be encrypted", 
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }
	else
	{
        return AXIS2_SUCCESS;
    }
}

/*We validate only the body encryption*/
static axis2_status_t
rampart_pv_validate_signature(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axis2_msg_ctx_t *msg_ctx)
{
    axis2_status_t status = AXIS2_SUCCESS;
    axutil_array_list_t *nodes_to_sign = NULL;
    axiom_soap_envelope_t *soap_envelope = NULL;
    axis2_char_t* signature_verified = NULL;

    nodes_to_sign = axutil_array_list_create(env, 0);
    soap_envelope = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
   
    status = rampart_context_get_nodes_to_sign(
                  rampart_context, env, soap_envelope, nodes_to_sign);

    status = rampart_context_get_elements_to_sign(
                  rampart_context, env, soap_envelope, nodes_to_sign);

    signature_verified = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VERIFIED);
    if(0 == axutil_strcmp(RAMPART_YES, signature_verified))
    {
        if(axutil_array_list_size(nodes_to_sign, env) <= 0)
        {
			axutil_array_list_free(nodes_to_sign, env);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Signature is not expected.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Signature is not expected", 
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }
    else
    {
        if(axutil_array_list_size(nodes_to_sign, env) > 0)
        {
			axutil_array_list_free(nodes_to_sign, env);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][rpv] Could not find signature.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Could not find signature", 
                        RAMPART_FAULT_INVALID_SECURITY, msg_ctx);
            return AXIS2_FAILURE;
        }
    }

	axutil_array_list_free(nodes_to_sign, env);
    return AXIS2_SUCCESS;
}

/*Public functions*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_pv_validate_sec_header(const axutil_env_t *env,
        rampart_context_t *rampart_context,
        axiom_node_t *sec_node,
        axis2_msg_ctx_t *msg_ctx)
{
    
    /*Check if the signature needed to be encrypted*/ 
    if(!rampart_pv_validate_signature_encryption(env, rampart_context, msg_ctx)){
        return AXIS2_FAILURE;
    } 
    /*Check if the Signature Confirmation is set*/
    if(!rampart_pv_validate_signature_confirmation(env, rampart_context, msg_ctx)){
        return AXIS2_FAILURE;
    }
    /*Check if Usernametoken found*/
    if(!rampart_pv_validate_ut(env, rampart_context, msg_ctx)){
        return AXIS2_FAILURE;
    }
    /*Check if Timestamp found*/
    if(!rampart_pv_validate_ts(env, rampart_context, msg_ctx)){
        return AXIS2_FAILURE;
    }
    /*Check if encryption is valid found*/
    if(!rampart_pv_validate_encryption(env, rampart_context, msg_ctx)){
        return AXIS2_FAILURE;
    }
    /*Check if signature is valid found*/
    if(!rampart_pv_validate_signature(env, rampart_context, msg_ctx))
    {
        return AXIS2_FAILURE;
    }
    /*All the policy reqmnts are met. We are good to go*/
    return AXIS2_SUCCESS;
}



