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

#include <stdio.h>
#include <rampart_sct_provider.h>
#include <axutil_string.h>
#include <axutil_utils.h>
#include <oxs_utility.h>
#include <trust_sts_client.h>

#define SCT_DB_LABLE_ENC "Encryption"
#define SCT_DB_LABLE_SIG "Signature"
#define SCT_DB_LABLE_COM "Common"

static security_context_token_t* 
sct_provider_obtain_token_from_sts(const axutil_env_t* env, rp_property_t *token, axis2_msg_ctx_t* msg_ctx);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sct_provider_free(rampart_sct_provider_t *sct_provider,
								const axutil_env_t* env)
{
	if (sct_provider)
	{
		if (sct_provider->ops)
		{
			AXIS2_FREE(env->allocator, sct_provider->ops);
		}
		AXIS2_FREE(env->allocator, sct_provider);
	}
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN security_context_token_t* AXIS2_CALL
sct_provider_obtain_token(rampart_sct_provider_t *sct_provider, const axutil_env_t* env, 
                            rp_property_t *token, axis2_bool_t server_side, 
                            axis2_bool_t is_encryption, axis2_char_t* sct_id, 
                            rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;
    rp_security_context_token_t* rp_sct = NULL;
    axis2_char_t *sct_db_lable = NULL;
    axutil_hash_t *sct_db = NULL;

    /* assume token is secure conversation token. In client side, we have to check whether the token is already 
     * obtained from STS. in that case, it will be available in sct_db. but, we don't know the sct_id, so the key 
     * should be "Encryption" or "Signature" or "Common". In server side, sct has to be in the sct_db and the key should be sct_id.

     */

    /*find the sct_db lable to be used*/
    if(sct_id)
        sct_db_lable = sct_id;
    else if (!server_side)
    {
        if(is_different_session_key_for_encryption_and_signing(env, rampart_context))
        {
            if(is_encryption)
                sct_db_lable = SCT_DB_LABLE_ENC;
            else
                sct_db_lable = SCT_DB_LABLE_SIG;
        }
        else
        {
            sct_db_lable = SCT_DB_LABLE_COM;
        }
    }

    /*get the sct_db*/
    axutil_allocator_switch_to_global_pool(env->allocator);
    sct_db = sct_provider_get_sct_hash(env, msg_ctx);
    if(!sct_db)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot find sct datastore");
        return NULL;
    }

    /*get the sct*/
    sct = (security_context_token_t *)axutil_hash_get(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING);
    axutil_allocator_switch_to_local_pool(env->allocator);
    if(sct)
        return sct;

    /*sct is not in the db. So we have to get it*/

    /*check whether rp_property is valid*/
    if(!token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] token property is not valid");
        return NULL;
    }

    rp_sct = (rp_security_context_token_t*)rp_property_get_value(token, env);
    if(!rp_sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] value of token property is not valid");
        return NULL;
    }

    /*check whether the assertion is SecureConversationToken. If not (e.g. SecurityContextToken) then you can't
    request the token from STS. We'll get it from stored token*/
    if(!rp_security_context_token_get_is_secure_conversation_token(rp_sct, env))
    {
        /*sct = sct_provider_get_stored_token(env, sct_id);
        if(sct)
            axutil_hash_set(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING, sct);

        return sct;*/
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] SecurityContextToken assertion is not supported. Only SecureConversationToken assertion is supported by this module.");
        return NULL;
    }

    /*so the token is secure conversation token. If client side then we can request from sts. If server side, can't do anything*/
    if(server_side)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot find security context token in server side");
        return NULL;
    }
    
    sct = sct_provider_obtain_token_from_sts(env, token, msg_ctx);
    if(sct)
    {
        axutil_hash_set(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING, sct);
        sct_db_lable = security_context_token_get_global_identifier(sct, env);
        security_context_token_increment_ref(sct, env);
        axutil_hash_set(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING, sct);
    }

    return sct;
}

/**
 * Following block distinguish the exposed part of the dll.
 */
AXIS2_EXPORT int
axis2_get_instance(rampart_sct_provider_t **inst,
        const axutil_env_t *env)
{
    rampart_sct_provider_t* sct_provider = NULL;

    sct_provider = AXIS2_MALLOC(env->allocator,
            sizeof(rampart_sct_provider_t));

    sct_provider->ops = AXIS2_MALLOC(
                env->allocator, sizeof(rampart_sct_provider_ops_t));

    /*assign function pointers*/

    sct_provider->ops->get_token = sct_provider_obtain_token;
    sct_provider->ops->free = sct_provider_free;

    *inst = sct_provider;

    if (!(*inst))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot initialize the sct provider module");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXPORT int
axis2_remove_instance(rampart_sct_provider_t *inst,
        const axutil_env_t *env)
{
    axis2_status_t status = AXIS2_FAILURE;
    if (inst)
    {
        status = RAMPART_SCT_PROVIDER_FREE(inst, env);
    }
    return status;
}

static neethi_policy_t *
clone_policy(neethi_policy_t *policy, const axutil_env_t* env)
{
	neethi_policy_t *return_policy = NULL;

	if (policy)
    {
		axutil_array_list_t *policy_components = NULL;
		axis2_char_t *name = NULL;
		axis2_char_t* id = NULL;
		
		return_policy = neethi_policy_create(env);
		policy_components = neethi_policy_get_policy_components(policy, env);
		neethi_policy_add_policy_components(return_policy, policy_components, env);

		name = neethi_policy_get_name(policy, env);
        if (name)
        {
            neethi_policy_set_name(return_policy, env, name);
        }
        id = neethi_policy_get_id(policy, env);
        if (id)
        {
            neethi_policy_set_id(return_policy, env, id);
        }
    }
	return return_policy;
}

static security_context_token_t* 
sct_provider_obtain_token_from_sts(const axutil_env_t* env, rp_property_t *token, axis2_msg_ctx_t* msg_ctx)
{
    axis2_char_t* client_home = NULL;
    trust_sts_client_t* sts_client = NULL;
    axis2_char_t* issuer_address = NULL;
    rp_security_context_token_t* rp_sct = NULL;
    trust_context_t* trust_context = NULL;
    trust_rst_t* rst = NULL;
    trust_rstr_t* rstr = NULL;
    security_context_token_t *sct = NULL;
	neethi_policy_t *sts_policy = NULL;
	neethi_policy_t *cloned_policy = NULL;
    axis2_ctx_t *ctx = NULL;
    axis2_char_t *addressing_version_from_msg_ctx = NULL;
    axutil_property_t *property = NULL;
    oxs_buffer_t *buffer = NULL;
    axis2_bool_t is_soap11 = AXIS2_FALSE;

    /*check whether rp_property is valid*/
    rp_sct = (rp_security_context_token_t*)rp_property_get_value(token, env);
    if(!rp_sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] token property is not valid");
        return NULL;
    }

    /*check whether the assertion is SecureConversationToken. If not (e.g. SecurityContextToken) then you can't
    request the token from STS.*/
    if(!rp_security_context_token_get_is_secure_conversation_token(rp_sct, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] token is not a secure conversation token.");
        return NULL;
    }

    /*get the token issuer address. If the address is not valid, then issuer should be same as the service.
    so get the service end point*/
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
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] issuer address is not valid.");
            return NULL;
        }
    }

    /*get the client home from msg_ctx */
    client_home = axis2_conf_get_repo(axis2_conf_ctx_get_conf(axis2_msg_ctx_get_conf_ctx(msg_ctx, env), env), env);
    if(!client_home)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot get client home");
        return NULL;
    }

    /*get the addressing namespace to be used from msg_ctx*/
    ctx = axis2_msg_ctx_get_base(msg_ctx, env);
    property = axis2_ctx_get_property(ctx, env, AXIS2_WSA_VERSION);
    if(property)
        addressing_version_from_msg_ctx = axutil_property_get_value(property, env);  

    is_soap11 = axis2_msg_ctx_get_is_soap_11(msg_ctx, env);

    /*Create sts client and set the values*/
    sts_client = trust_sts_client_create(env);    
    trust_sts_client_set_home_dir(sts_client, env, client_home);
    trust_sts_client_set_issuer_address(sts_client, env, issuer_address);

    /*create trust context and populate it*/
    trust_context = trust_context_create(env);
    rst = trust_rst_create(env);
    trust_rst_set_request_type(rst, env, TRUST_REQ_TYPE_ISSUE);
    trust_rst_set_token_type(rst, env, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN);
    trust_rst_set_wst_ns_uri(rst, env, TRUST_WST_XMLNS_05_02);
    trust_rst_set_wsa_action(rst, env, "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT");
    trust_context_set_rst(trust_context, env, rst);

    /*call sts_client to get the token from sts*/
	sts_policy = rp_security_context_token_get_bootstrap_policy(rp_sct, env);
	if(sts_policy)
	{
		/*cloned_policy = clone_policy(sts_policy, env);*/
        cloned_policy = neethi_engine_get_normalize(env, AXIS2_FALSE, sts_policy); 
	}
		
    buffer = trust_sts_client_request_security_token_using_policy(sts_client, env, 
                        trust_context, cloned_policy, addressing_version_from_msg_ctx, is_soap11);

    /*obtain the reply from sts*/
    rstr = trust_context_get_rstr(trust_context, env);
    if(!rstr)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot get RSTR from STS");
        return NULL;
    }

    /*create security context token and populate it with details given*/
    sct = security_context_token_create(env);
    security_context_token_set_token(sct, env, trust_rstr_get_requested_security_token(rstr, env));
    security_context_token_set_attached_reference(sct, env, trust_rstr_get_requested_attached_reference(rstr, env));
    security_context_token_set_unattached_reference(sct, env, trust_rstr_get_requested_unattached_reference(rstr, env));
    if(buffer)
        security_context_token_set_secret(sct, env, buffer);
    else
        security_context_token_set_requested_proof_token(sct, env, trust_rstr_get_requested_proof_token(rstr, env));

    /*now we can clear unwanted stuff*/
    trust_context_free(trust_context, env);
	trust_sts_client_free(sts_client, env);

    return sct;
}

/*
static security_context_token_t *
sct_provider_get_stored_token(const axutil_env_t *env, axis2_char_t *sct_id)
{
    security_context_token_t* sct = NULL;
    oxs_buffer_t* key_buffer = NULL;
   
    sct = security_context_token_create(env);
    if(!sct)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot create security context token");
        return NULL;
    }

    key_buffer = oxs_buffer_create(env);
    oxs_buffer_populate(key_buffer, env, (unsigned char*)"01234567012345670123456701234567", 32);
    security_context_token_set_secret(sct, env, key_buffer);

    if(!sct_id)
        sct_id = oxs_util_generate_id(env,"urn:uuid:");
    security_context_token_set_global_identifier(sct, env, axutil_strdup(env, sct_id));
    security_context_token_set_local_identifier(sct, env, axutil_strdup(env, "#sctId-29530019"));

    return sct;
}*/
