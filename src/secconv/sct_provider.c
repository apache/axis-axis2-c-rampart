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

security_context_token_t*
sct_provider_get_sct(const axutil_env_t* env, rp_property_t *token, 
                    axis2_bool_t server_side, axis2_bool_t is_encryption, axis2_char_t *sct_id,
                    rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    rampart_sct_provider_t* sct_provider = NULL;
    security_context_token_t* sct = NULL;

    if(!sct_id)
    {
        if(is_encryption)
            sct_id = rampart_context_get_encryption_sct_id(rampart_context, env);
        else
            sct_id = rampart_context_get_signature_sct_id(rampart_context, env);
    }

    sct_provider = rampart_context_get_sct_provider(rampart_context, env);
    if(!sct_provider)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][sct_provider] Security context token provider module is not set");
        return NULL;
    }

    sct = RAMPART_SCT_PROVIDER_GET_TOKEN(sct_provider, env, token, server_side, is_encryption, 
        sct_id, rampart_context, msg_ctx);

    if(!sct)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][sct_provider] Security context token is not valid");
    }
    
    return sct;
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
sct_provider_get_secret(const axutil_env_t* env, rp_property_t *token, 
                        axis2_bool_t server_side, axis2_bool_t is_encryption, 
                        rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, token, server_side, is_encryption, NULL,
                        rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_secret(sct, env);
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
sct_provider_get_secret_using_id(const axutil_env_t* env, axis2_char_t* sct_id, 
                        rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, NULL, axis2_msg_ctx_get_server_side(msg_ctx,env), AXIS2_TRUE, sct_id, 
                        rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_secret(sct, env);
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
sct_provider_get_token(const axutil_env_t* env, rp_property_t *token, 
                       axis2_bool_t server_side, axis2_bool_t is_encryption,
                       rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, token, server_side, is_encryption, NULL,
                        rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_token(sct, env);
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
sct_provider_get_attached_reference(const axutil_env_t* env, rp_property_t *token, 
                                    axis2_bool_t server_side, axis2_bool_t is_encryption,
                                    rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
    security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, token, server_side, is_encryption, NULL,
                        rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_attached_reference(sct, env); 
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
sct_provider_get_unattached_reference(const axutil_env_t* env, rp_property_t *token, 
                                        axis2_bool_t server_side, axis2_bool_t is_encryption,
                                        rampart_context_t* rampart_context, axis2_msg_ctx_t* msg_ctx)
{
   security_context_token_t* sct = NULL;

    sct = sct_provider_get_sct(env, token, server_side, is_encryption, NULL,
                        rampart_context, msg_ctx);

    if(!sct)
        return NULL;

    return security_context_token_get_unattached_reference(sct, env); 
}
