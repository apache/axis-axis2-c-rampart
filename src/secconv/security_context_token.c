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

#include <secconv_security_context_token.h>
#include <oxs_buffer.h>
#include <oxs_tokens.h>
#include <trust_constants.h>

struct security_context_token_t
{
    oxs_buffer_t *buffer;
    axis2_char_t *global_id;
    axis2_char_t *local_id;
    axiom_node_t *sct_node;
    axiom_node_t *attached_reference;
    axiom_node_t *unattached_reference;
    int ref;
};

AXIS2_EXTERN security_context_token_t *AXIS2_CALL
    security_context_token_create(
    const axutil_env_t * env)
{
    security_context_token_t *sct = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    sct =  (security_context_token_t *) AXIS2_MALLOC (env->allocator,
                       sizeof (security_context_token_t));

    if(sct == NULL)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }
    
    sct->buffer = NULL;
    sct->global_id = NULL;
    sct->local_id = NULL;
    sct->sct_node = NULL;
    sct->attached_reference = NULL;
    sct->unattached_reference = NULL;
    sct->ref = 1;
    return sct;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_increment_ref(
    security_context_token_t *sct,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    sct->ref++;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void AXIS2_CALL
security_context_token_free(
    security_context_token_t *sct, 
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (--sct->ref > 0)
        return;

    if(sct->buffer)
    {
        oxs_buffer_free(sct->buffer, env);
    }
    if(sct->local_id)
    {
        AXIS2_FREE(env->allocator, sct->local_id);
    }
    if(sct->global_id)
    {
        AXIS2_FREE(env->allocator, sct->global_id);
    }
    if(sct->sct_node)
    {
        axiom_node_free_tree(sct->sct_node, env);
    }
    if(sct->attached_reference)
    {
        axiom_node_free_tree(sct->attached_reference, env);
    }
    if(sct->unattached_reference)
    {
        axiom_node_free_tree(sct->unattached_reference, env);
    }

    AXIS2_FREE(env->allocator, sct);
    return;
}

AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
security_context_token_get_secret(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->buffer;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
security_context_token_get_global_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->global_id;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
security_context_token_get_local_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env)
{
    return sct->local_id;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_secret(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    oxs_buffer_t *buffer)
{
    if(sct->buffer)
    {
        oxs_buffer_free(sct->buffer, env);
    }
    sct->buffer = buffer;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_global_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    axis2_char_t *global_id)
{
    if(sct->global_id)
    {
        AXIS2_FREE(env->allocator, sct->global_id);
    }
    sct->global_id = global_id;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_local_identifier(
    security_context_token_t * sct, 
    const axutil_env_t * env,
    axis2_char_t *local_id)
{
    if(sct->local_id)
    {
        AXIS2_FREE(env->allocator, sct->local_id);
    }
    sct->local_id = local_id;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_requested_proof_token(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    int encodedlen;
    axis2_char_t *encoded_str = NULL;
    axiom_node_t* proof_token = NULL;
    axiom_element_t *proof_token_ele = NULL;
    axiom_node_t* secret_node = NULL;
    axiom_element_t *secret_ele = NULL;
    axiom_namespace_t *ns_obj_wst = NULL;

    if(!sct->buffer)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][security context token] Security context token does not have a shared secret");
        return NULL;
    }
    
    ns_obj_wst = axiom_namespace_create(env, TRUST_WST_XMLNS, TRUST_WST);
    proof_token_ele = axiom_element_create(env, NULL, TRUST_REQUESTED_PROOF_TOKEN, ns_obj_wst, &proof_token);
    if (!proof_token_ele)
	{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot create requested proof token");
        return NULL;
    }

    secret_ele = axiom_element_create(env, proof_token, TRUST_BINARY_SECRET, ns_obj_wst, &secret_node);
    if(!secret_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot create binary secret token");
        return NULL;
    }

	encodedlen = axutil_base64_encode_len(oxs_buffer_get_size(sct->buffer, env));
    encoded_str = AXIS2_MALLOC(env->allocator, encodedlen);
    axutil_base64_encode(encoded_str, (const char *)oxs_buffer_get_data(sct->buffer, env), oxs_buffer_get_size(sct->buffer, env));
    axiom_element_set_text(secret_ele, env, encoded_str, secret_node);
	AXIS2_FREE(env->allocator, encoded_str);

    return proof_token;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_attached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t *str_token = NULL;
    axiom_node_t *ref_token = NULL;

    if(sct->attached_reference)
        return oxs_axiom_clone_node(env, sct->attached_reference);

    if(!sct->local_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Security context token does not have a local identifier");
        return NULL;
    }

    str_token = oxs_token_build_security_token_reference_element(env, NULL); 
    ref_token = oxs_token_build_reference_element(env, str_token, sct->local_id, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN);   
    return str_token; 
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_unattached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t *str_token = NULL;
    axiom_node_t *ref_token = NULL;
    
    if(sct->unattached_reference)
        return oxs_axiom_clone_node(env, sct->unattached_reference);

    if(!sct->global_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Security context token does not have a global identifier");
        return NULL;
    }

    str_token = oxs_token_build_security_token_reference_element(env, NULL); 
    ref_token = oxs_token_build_reference_element(env, str_token, sct->global_id, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN);   
    return str_token; 
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
security_context_token_get_token(
    security_context_token_t *sct, 
    const axutil_env_t * env)
{
    axiom_node_t* sct_token = NULL;
    axiom_element_t *token_ele = NULL;
    axiom_node_t* identifier_node = NULL;
    axiom_element_t *identifier_ele = NULL;
    axiom_namespace_t *ns_obj_sc = NULL;
    axiom_namespace_t *ns_obj_wsu = NULL;
    axiom_attribute_t *id_attr = NULL;

    if(sct->sct_node)
        return oxs_axiom_clone_node(env, sct->sct_node);

    if(!sct->global_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Security context token does not have an identifier.");
        return NULL;
    }

    ns_obj_sc = axiom_namespace_create(env, OXS_WSC_NS, OXS_WSC);
    token_ele = axiom_element_create(env, NULL, OXS_NODE_SECURITY_CONTEXT_TOKEN, ns_obj_sc, &sct_token);
    if (!token_ele)
    {
        oxs_error(env, ERROR_LOCATION,
                  OXS_ERROR_ELEMENT_FAILED, "Error creating SecurityContextToken element");
        return NULL;
    }

    if(sct->local_id)
    {
		axis2_char_t *id = NULL;
		id = axutil_string_substring_starting_at(axutil_strdup(env, sct->local_id), 1);
        ns_obj_wsu = axiom_namespace_create(env, OXS_WSU_XMLNS, OXS_WSU);
        id_attr = axiom_attribute_create(env, OXS_ATTR_ID, id, ns_obj_wsu);
        axiom_element_add_attribute(token_ele, env, id_attr, sct_token);
		AXIS2_FREE(env->allocator, id);
    }

    identifier_ele = axiom_element_create(env, sct_token, OXS_NODE_IDENTIFIER, ns_obj_sc, &identifier_node);
    if(!identifier_ele)
    {
        oxs_error(env, ERROR_LOCATION,
                  OXS_ERROR_ELEMENT_FAILED, "Error creating SecurityContextToken element");
        return NULL;
    }
    axiom_element_set_text(identifier_ele, env, sct->global_id, identifier_node);

    return sct_token;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_requested_proof_token(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    /*axiom_node_t *secret_node = NULL;*/
    axis2_char_t *shared_secret = NULL;
    int decoded_len = 0;
    axis2_char_t *decoded_shared_secret = NULL;
    oxs_buffer_t *buffer = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    /*secret_node = oxs_axiom_get_first_child_node_by_name(env, node, TRUST_BINARY_SECRET, TRUST_WST_XMLNS, NULL);
    if(!secret_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get binary secret node from proof token");
        return AXIS2_FAILURE;
    }*/

    shared_secret = oxs_axiom_get_node_content(env, node);
    if(!shared_secret)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get content of binary secret node");
        return AXIS2_FAILURE;
    }
    
    decoded_len = axutil_base64_decode_len(shared_secret);
	decoded_shared_secret = AXIS2_MALLOC(env->allocator, decoded_len);
	axutil_base64_decode_binary((unsigned char*)decoded_shared_secret, shared_secret);

    buffer = oxs_buffer_create(env);
    oxs_buffer_populate(buffer, env, (unsigned char*)decoded_shared_secret, decoded_len);
    AXIS2_FREE(env->allocator, decoded_shared_secret);

    return security_context_token_set_secret(sct, env, buffer);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_attached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    axiom_node_t *ref_token = NULL;
    axis2_char_t *local_id = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    ref_token = oxs_axiom_get_first_child_node_by_name(env, node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get reference node from attached reference");
        return AXIS2_FAILURE;
    }

    local_id = oxs_token_get_reference(env, ref_token);
    if(!local_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get attached reference");
        return AXIS2_FAILURE;
    }
    
    sct->attached_reference = oxs_axiom_clone_node(env, node);
    return security_context_token_set_local_identifier(sct, env, axutil_strdup(env, local_id));
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_unattached_reference(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    axiom_node_t *ref_token = NULL;
    axis2_char_t *reference_id = NULL;

    AXIS2_PARAM_CHECK(env->error, node, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, sct, AXIS2_FAILURE);

    ref_token = oxs_axiom_get_first_child_node_by_name(env, node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get reference node from unattached reference");
        return AXIS2_FAILURE;
    }

    reference_id = oxs_token_get_reference(env, ref_token);
    if(!reference_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][security context token] Cannot get unattached reference");
        return AXIS2_FAILURE;
    }
    
    sct->unattached_reference = oxs_axiom_clone_node(env, node);

    return security_context_token_set_global_identifier(sct, env, axutil_strdup(env, reference_id));
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
security_context_token_set_token(
    security_context_token_t *sct, 
    const axutil_env_t * env,
    axiom_node_t *node)
{
    sct->sct_node = oxs_axiom_clone_node(env, node);
    return AXIS2_SUCCESS;
}



