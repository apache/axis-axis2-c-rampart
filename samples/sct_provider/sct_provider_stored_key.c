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
#include <axutil_string.h>
#include <axutil_utils.h>
#include <oxs_utility.h>
#include <rampart_util.h>
#include <rampart_sct_provider.h>

#define SCT_DB_LABLE_ENC "Encryption"
#define SCT_DB_LABLE_SIG "Signature"
#define SCT_DB_LABLE_COM "Common"

static security_context_token_t *
sct_provider_get_stored_token(const axutil_env_t *env, axis2_char_t *sct_id);

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

    /* We have to check whether the token is already created/loaded. in that case, it will be available in sct_db. 
     * in client side the key should be "Encryption" or "Signature" or "Common". In server side the key should be sct_id.
     */

    /*find the sct_db lable to be used*/
    if(server_side)
        sct_db_lable = sct_id;
    else
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
    sct_db = sct_provider_get_sct_hash(env, msg_ctx);
    if(!sct_db)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][sct_provider_sample] Cannot find sct datastore");
        return NULL;
    }

    /*get the sct*/
    sct = (security_context_token_t *)axutil_hash_get(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING);
    if(sct)
        return sct;

    /*sct is not in the db. So we have to get it*/
    sct = sct_provider_get_stored_token(env, sct_id);
    if(sct)
        axutil_hash_set(sct_db, sct_db_lable, AXIS2_HASH_KEY_STRING, sct);

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

static security_context_token_t *
sct_provider_get_stored_token(const axutil_env_t *env, axis2_char_t *sct_id)
{
    security_context_token_t* sct = NULL;
    oxs_buffer_t* key_buffer = NULL;
    axis2_bool_t *free_sctid = AXIS2_FALSE;
   
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
    {
        sct_id = oxs_util_generate_id(env,"urn:uuid:");
        free_sctid = AXIS2_TRUE;
    }
    security_context_token_set_global_identifier(sct, env, axutil_strdup(env, sct_id));
    security_context_token_set_local_identifier(sct, env, axutil_strdup(env, "#sctId-29530019"));
    
    if(free_sctid)
        AXIS2_FREE(env->allocator, sct_id);

    return sct;
}
