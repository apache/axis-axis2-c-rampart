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
#include <rampart_sct_provider.h>
#include <oxs_constants.h>
#include <oxs_buffer.h>
#include <axiom_element.h>
#include <rampart_constants.h>
#include <trust_sts_client.h>
#include <oxs_utility.h>

#define RAMPART_SCT_PROVIDER_HASH_PROB "Rampart_SCT_Prov_DB_Prop"

static security_context_token_t* 
sct_provider_obtain_token_from_sts(
    const axutil_env_t* env, 
    rp_security_context_token_t* rp_sct, 
    axis2_msg_ctx_t* msg_ctx);

static security_context_token_t*
sct_provider_get_sct(
    const axutil_env_t* env, 
    rp_property_t *token, 
    axis2_bool_t is_encryption, 
    axis2_char_t *sct_id,
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    rampart_sct_provider_t* sct_provider = NULL;
    security_context_token_t* sct = NULL;

    /* if sct id is not given, check whether it is stored in rampart context */
    if(!sct_id)
    {
        if(is_encryption)
            sct_id = rampart_context_get_encryption_token_id(rampart_context, env);
        else
            sct_id = rampart_context_get_signature_token_id(rampart_context, env);
    }

    if(!sct_id)
    {
        /* if sct id is not there in rampart context, then it is not created. 
         * (1) If it is secure conversation token
         *      (a) If server side, we can't do anything. We have to fail.
         *      (b) If client side, we can request from STS
         * (2) If it is security context token - sct agreed by server and client offline
         *      (a) If server side, can call get_sct method and if returned successfully, store it
         *      (b) If client side, same as server_side
         */
        void* user_params = NULL;
        rp_security_context_token_t* rp_sct = NULL;

        /* to check whether security context token or secure conversation token, rp_property (token)
         * should be valid. If valid, we can extract the security context token property */
        if(!token)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]rampart policy property 'token' is not valid. Could not find whether \
                token is SecureConversationToken or SecurityContextToken.");
            return NULL;
        }

        rp_sct = (rp_security_context_token_t*)rp_property_get_value(token, env);
        if(!rp_sct)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]value of rampart policy property 'token' is not valid. Could not find \
                whether token is SecureConversationToken or SecurityContextToken.");
            return NULL;
        }

        user_params = rampart_context_get_security_context_token_user_params(rampart_context, env);

        if(rp_security_context_token_get_is_secure_conversation_token(rp_sct, env))
        {
            /* this is a secure conversation token */
            
            axis2_bool_t is_server_side = AXIS2_FALSE;
            is_server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
            if(!is_server_side)
            {
                /* we can request sct from sts */

                sct = sct_provider_obtain_token_from_sts(env, rp_sct, msg_ctx);
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart] Secure conversation token is requested without giving ID of SCT. \
                    This cannot be done in server side.");
            }
        }
        else
        {
            /* this is a security context token */
            
            obtain_security_context_token_fn fn_get_sct = NULL;
            fn_get_sct = rampart_context_get_obtain_security_context_token_fn(rampart_context, env);
            sct = (security_context_token_t*)fn_get_sct(
                env, is_encryption, msg_ctx, sct_id, RAMPART_SCT_ID_TYPE_UNKNOWN, user_params);
        }

        /* if valid sct, then we have to store it */
        if(sct)
        {
            axis2_char_t *local_id = NULL;
            axis2_char_t *global_id = NULL;
            store_security_context_token_fn fn_store_sct = NULL;

            local_id = security_context_token_get_local_identifier(sct, env);
            global_id = security_context_token_get_global_identifier(sct, env);
            fn_store_sct = rampart_context_get_store_security_context_token_fn(
                rampart_context, env);
            if(fn_store_sct(env, msg_ctx, global_id, local_id, (void*)sct, user_params)
                != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart] Cannot store newly created security context token.");
                security_context_token_free(sct, env);
                sct = NULL;
            }

            /* store the global id as encryption/signature id. if same key is used for encryption 
             * and signature, then store it at both place*/
            if(is_different_session_key_for_encryption_and_signing(env, rampart_context))
            {
                if(is_encryption)
                    rampart_context_set_encryption_token_id(rampart_context, env, global_id);
                else
                    rampart_context_set_signature_token_id(rampart_context, env, global_id);
            }
            else
            {
                rampart_context_set_encryption_token_id(rampart_context, env, global_id);
                rampart_context_set_signature_token_id(rampart_context, env, global_id);
            }
        }
    }
    else
    {
        /* sct_id is given. So get it from sct provider function. */
        
        void* user_params = NULL;
        obtain_security_context_token_fn fn_get_sct = NULL;
        int id_type = RAMPART_SCT_ID_TYPE_GLOBAL;

        user_params = rampart_context_get_security_context_token_user_params(rampart_context, env);
        fn_get_sct = rampart_context_get_obtain_security_context_token_fn(rampart_context, env);

        /* by looking at the first character of sct_id, we can say whether it is local id or global 
         * id. If first character is '#' then it is a local id */
        if(*sct_id == '#')
        {
            id_type = RAMPART_SCT_ID_TYPE_LOCAL;
        }
        sct = fn_get_sct(env, is_encryption, msg_ctx, sct_id, id_type, user_params);
    }

    if(!sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Cannot find security context token for id [%s]", sct_id);
    }
    
    return sct;
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
sct_provider_get_secret(
    const axutil_env_t* env, 
    rp_property_t *token, 
    axis2_bool_t is_encryption, 
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, token, is_encryption, NULL, rampart_context, msg_ctx);
    if(!sct)
        return NULL;

    return security_context_token_get_secret(sct, env);
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
sct_provider_get_secret_using_id(
    const axutil_env_t* env, 
    axis2_char_t* sct_id, 
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    /* since we are getting secret using id, we don't need to specify whether encryption or 
     * signature. Also we don't need to care about policy property of token */
    sct = sct_provider_get_sct(env, NULL, AXIS2_TRUE, sct_id, rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_secret(sct, env);
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
sct_provider_get_token(
    const axutil_env_t* env, 
    rp_property_t *token, 
    axis2_bool_t is_encryption,
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;
    sct = sct_provider_get_sct(env, token, is_encryption, NULL, rampart_context, msg_ctx);
    if(!sct)
        return NULL;

    return security_context_token_get_token(sct, env);
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
sct_provider_get_attached_reference(
    const axutil_env_t* env, 
    rp_property_t *token, 
    axis2_bool_t is_encryption,
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;
    sct = sct_provider_get_sct(env, token, is_encryption, NULL, rampart_context, msg_ctx);
    if(!sct)
        return NULL;

    return security_context_token_get_attached_reference(sct, env); 
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
sct_provider_get_unattached_reference(
    const axutil_env_t* env, 
    rp_property_t *token, 
    axis2_bool_t is_encryption,
    rampart_context_t* rampart_context, 
    axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;
    sct = sct_provider_get_sct(env, token, is_encryption, NULL, rampart_context, msg_ctx);
    if(!sct)
        return NULL;

    return security_context_token_get_unattached_reference(sct, env); 
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_validate_security_context_token(
    const axutil_env_t *env, 
    axiom_node_t *sct_node, 
    rampart_context_t *rampart_context, 
    axis2_msg_ctx_t *msg_ctx)
{
    validate_security_context_token_fn validate_fn = NULL;
    void *user_param = NULL;

    validate_fn = rampart_context_get_validate_security_context_token_fn(rampart_context, env);
    user_param = rampart_context_get_security_context_token_user_params(rampart_context, env);
    return validate_fn(env, sct_node, msg_ctx, user_param);
}

static security_context_token_t* 
sct_provider_obtain_token_from_sts(
    const axutil_env_t* env, 
    rp_security_context_token_t* rp_sct, 
    axis2_msg_ctx_t* msg_ctx)
{
    axis2_char_t* issuer_address = NULL;
    axis2_char_t* client_home = NULL;
    axis2_conf_ctx_t* conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axis2_char_t *addressing_version_from_msg_ctx = NULL;
    axis2_bool_t is_soap11 = AXIS2_FALSE;
    trust_sts_client_t* sts_client = NULL;    
    trust_context_t* trust_context = NULL;
    trust_rst_t* rst = NULL;
    trust_rstr_t* rstr = NULL;
    security_context_token_t *sct = NULL;
	neethi_policy_t *sts_policy = NULL;
	neethi_policy_t *cloned_policy = NULL;
    oxs_buffer_t *buffer = NULL;

    /* Get the token issuer address. If the address is not valid, then issuer should be same as 
    the service. So get the service end point */
    issuer_address = rp_security_context_token_get_issuer(rp_sct, env);
    if(!issuer_address)
    {
        axis2_endpoint_ref_t *endpoint = NULL;
        endpoint = axis2_msg_ctx_get_to(msg_ctx, env);

        if(endpoint)
        {
            issuer_address = axis2_endpoint_ref_get_address(endpoint, env);
        }

        if(!issuer_address)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Token issuer address is not valid.");
            return NULL;
        }
    }

    /* Get the client home from msg_ctx */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(conf_ctx)
    {
        axis2_conf_t *conf = NULL;
        conf = axis2_conf_ctx_get_conf(conf_ctx, env);
        if(conf)
        {
            client_home = axis2_conf_get_repo(conf, env);
        }
    }
    
    if(!client_home)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get client home. Unable to send request to Security Token Service.");
        return NULL;
    }

    /* Get the addressing namespace to be used from msg_ctx */
    ctx = axis2_msg_ctx_get_base(msg_ctx, env);
    property = axis2_ctx_get_property(ctx, env, AXIS2_WSA_VERSION);
    if(property)
    {
        addressing_version_from_msg_ctx = axutil_property_get_value(property, env);  
    }

    /* get the soap version */
    is_soap11 = axis2_msg_ctx_get_is_soap_11(msg_ctx, env);

    /* Create sts client and set the values (client home, issuer_address, etc.) */
    sts_client = trust_sts_client_create(env);
    if(!sts_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot create client to Security Token Service.");
        return NULL;
    }

    trust_sts_client_set_home_dir(sts_client, env, client_home);
    trust_sts_client_set_issuer_address(sts_client, env, issuer_address);

    /* create trust context and populate it */
    trust_context = trust_context_create(env);
    if(!trust_context)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot create trust context. Cannot communicate with Token Service.");
        return NULL;
    }
    rst = trust_rst_create(env);
    if(!trust_context)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot create token request. Cannot communicate with Token Service.");
        return NULL;
    }
    trust_rst_set_request_type(rst, env, TRUST_REQ_TYPE_ISSUE);
    trust_rst_set_token_type(rst, env, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN);
    trust_rst_set_wst_ns_uri(rst, env, TRUST_WST_XMLNS_05_02);
    trust_rst_set_wsa_action(rst, env, SECCONV_200502_REQUEST_ACTION);
    trust_context_set_rst(trust_context, env, rst);

    /* call sts_client to get the token from sts. We should create a clone of that policy */
	sts_policy = rp_security_context_token_get_bootstrap_policy(rp_sct, env);
	if(sts_policy)
	{
        cloned_policy = neethi_engine_get_normalize(env, AXIS2_FALSE, sts_policy); 
	}
		
    buffer = trust_sts_client_request_security_token_using_policy(
        sts_client, env, trust_context, cloned_policy, addressing_version_from_msg_ctx, is_soap11);

    /* Obtain the reply from sts */
    rstr = trust_context_get_rstr(trust_context, env);
    if(!rstr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get token response from Token Service. RSTR is invalid.");
        return NULL;
    }

    /* Create security context token and populate it with details given */
    sct = security_context_token_create(env);
    security_context_token_set_token(sct, env, trust_rstr_get_requested_security_token(rstr, env));
    security_context_token_set_attached_reference(
        sct, env, trust_rstr_get_requested_attached_reference(rstr, env));
    security_context_token_set_unattached_reference(
        sct, env, trust_rstr_get_requested_unattached_reference(rstr, env));
    if(buffer)
    {
        security_context_token_set_secret(sct, env, buffer);
    }
    else
    {
        security_context_token_set_requested_proof_token(
            sct, env, trust_rstr_get_requested_proof_token(rstr, env));
    }

    /* Now we can clear unwanted stuff */
    trust_context_free(trust_context, env);
	trust_sts_client_free(sts_client, env);

    return sct;
}


static void 
sct_provider_sct_hash_store_free(
    axutil_hash_t *sct_hash_store,
    const axutil_env_t *env)
{
	axutil_hash_index_t *hi = NULL;

	for (hi = axutil_hash_first(sct_hash_store, env); hi != NULL; hi = axutil_hash_next(env, hi))
	{
		void *v = NULL;
        axutil_hash_this(hi, NULL, NULL, &v);
		if (v)
		{
			security_context_token_free((security_context_token_t*)v, env);        	
		}
	}

	axutil_hash_free(sct_hash_store, env);
}

static axutil_hash_t *
sct_provider_get_sct_hash_store(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_hash_t *hash_store = NULL;
    
    /* Get the conf ctx */
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
            "[rampart]Config context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    ctx = axis2_conf_ctx_get_base(conf_ctx,env);
    if(!ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]Axis2 context is NULL. Cannot get security context token hash store.");
        return NULL;
    }

    /* Get the hash store property */
    property = axis2_ctx_get_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB);
    if(property)
    {
        /* Get the store */
        hash_store = (axutil_hash_t*)axutil_property_get_value(property, env);
    }
    else
    {
        axutil_property_t *hash_store_prop = NULL;

        hash_store = axutil_hash_make(env);
        hash_store_prop = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION,
               AXIS2_TRUE, (void *)sct_provider_sct_hash_store_free, hash_store);
        axis2_ctx_set_property(ctx, env, RAMPART_SCT_PROVIDER_HASH_PROB, hash_store_prop);
    }

    return hash_store;
}

AXIS2_EXTERN void* AXIS2_CALL
sct_provider_obtain_sct_default(
    const axutil_env_t *env, 
    axis2_bool_t is_encryption, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_id, 
    int sct_id_type,
    void* user_params)
{
    axutil_hash_t *hash_store = NULL;
    security_context_token_t *sct = NULL;

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Using default sct provider obtain function.");

    /* sct should be get from global pool */
    axutil_allocator_switch_to_global_pool(env->allocator);
    
    /* Get sct hash store */
    hash_store = sct_provider_get_sct_hash_store(env, msg_ctx);
    if(!hash_store)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot find security context token storage.");
        return NULL;
    }

    /* get the sct if sct_id is given */
    if(sct_id)
    {
        sct = (security_context_token_t *)axutil_hash_get(
            hash_store, sct_id, AXIS2_HASH_KEY_STRING);
    }
    else
    {
        /* we can create an sct and send it */

        sct = security_context_token_create(env);
        if(sct)
        {
            oxs_buffer_t* key_buffer = NULL;
            key_buffer = oxs_buffer_create(env);
            oxs_buffer_populate(
                key_buffer, env, (unsigned char*)"01234567012345670123456701234567", 32);
            security_context_token_set_secret(sct, env, key_buffer);
            sct_id = oxs_util_generate_id(env,"urn:uuid:");
            security_context_token_set_global_identifier(sct, env, sct_id);
            security_context_token_set_local_identifier(
                sct, env, axutil_strdup(env, "#sctId-29530019"));
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot create security context token. Insufficient memory.");
        }
    }
    axutil_allocator_switch_to_local_pool(env->allocator);
    
    return sct;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_store_sct_default(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_global_id, 
    axis2_char_t *sct_local_id, 
    void *sct, 
    void *user_params)
{
    axutil_hash_t *hash_store = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Using default sct provider store function.");

    /* if given sct is null, then we can't store it */
    if(!sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Security context token to be stored in not valid.");
        return AXIS2_FAILURE;
    }

    /* sct should be stored in global pool */
    axutil_allocator_switch_to_global_pool(env->allocator);
    
    /* Get sct hash store */
    hash_store = sct_provider_get_sct_hash_store(env, msg_ctx);
    if(hash_store)
    {
        /* store sct */
        if(sct_global_id)
        {
            axutil_hash_set(hash_store, sct_global_id, AXIS2_HASH_KEY_STRING, sct);
            if(sct_local_id)
            {
                security_context_token_increment_ref(sct, env);
                axutil_hash_set(hash_store, sct_local_id, AXIS2_HASH_KEY_STRING, sct);
            }
        }
        else
        {
            if(sct_local_id)
            {
                axutil_hash_set(hash_store, sct_local_id, AXIS2_HASH_KEY_STRING, sct);
            }
            else
            {
                /* if both local_id and global_id are NULL, then we can't store it */
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Security context token identifiers are not valid. \
                    Cannot store security context token. ");
                status = AXIS2_FAILURE;
            }
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot find security context token storage.");
        status = AXIS2_FAILURE;
    }

    axutil_allocator_switch_to_local_pool(env->allocator);
    return status;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_delete_sct_default(
    const axutil_env_t *env, 
    axis2_msg_ctx_t* msg_ctx, 
    axis2_char_t *sct_id, 
    int sct_id_type,
    void* user_params)
{
    /* delete method is not implemented, because we are still not supporting sct cancel function */

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Using default sct provider delete function.");

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_validate_sct_default(
    const axutil_env_t *env, 
    axiom_node_t *sct_node, 
    axis2_msg_ctx_t *msg_ctx,
    void *user_params)
{
    /* default implementation does not need to validate anything. We haven't extended the 
     * functionality of sct */

    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Using default sct provider validate function.");

    return AXIS2_SUCCESS;
}