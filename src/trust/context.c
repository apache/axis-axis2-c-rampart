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
#include <trust_context.h>

struct trust_context
{
    /* in message context of STS */
    axis2_msg_ctx_t *in_msg_ctx;

    /* Axiom node which holds payload of RST message */
    axiom_node_t *rst_node;

    /** Request Type
      * e.g. wsse:ReqIssue/Validate/Renew etc 
      */
    axis2_char_t *request_type;

    /** Required Token Type
      * e.g. wsse:X509v3
      */
    axis2_char_t *token_type;

    /*optional element specifies the scope for which this security token is desired */
    axiom_node_t *applies_to_epr_node;

    axis2_char_t *applies_to_address;

    /** RST Context attribute	
      * This optional URI specifies an identifier/context for this request
      */
    axis2_char_t *rst_context_attr;

    /* KeyType element of the RST */
    axis2_char_t *key_type;

    int key_size;

    axis2_char_t *request_entropy;

    axis2_char_t *response_entropy;

    /*optional element for specific set of requested claims */
    axiom_node_t *claims_node;

    /**wst:RequestSecurityToken/wst:Claims@Dialect
      *Attribute specifies a URI to indicate the syntax of the claims
      */
    axis2_char_t *claims_dialect;

    /* SOAP Namespace */
    axis2_char_t *soap_namespace;

    /* WS-Trust Namespace */
    axis2_char_t *wst_namespace;

    /*Addressing NS */
    axis2_char_t *addressing_namespace;
};

AXIS2_EXTERN trust_context_t *AXIS2_CALL
trust_context_create(
    const axutil_env_t * env,
    axis2_msg_ctx_t * in_msg_ctx)
{
    axiom_soap_envelope_t *soap_env = NULL;
    axiom_soap_body_t *soap_body = NULL;
    axiom_namespace_t *soap_ns = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *body_base_node = NULL;
    axiom_element_t *rst_ele = NULL;

    trust_context_t *trust_context = NULL;
    trust_context = (trust_context_t *) AXIS2_MALLOC(env->allocator, sizeof(trust_context_t));

    /* Processing Message Context*/
    soap_env = axis2_msg_ctx_get_soap_envelope(in_msg_ctx, env);
    soap_body = axiom_soap_envelope_get_body(soap_env, env);
    body_base_node = axiom_soap_body_get_base_node(soap_body, env);
    trust_context->rst_node = axiom_node_get_first_child(body_base_node, env); 

    /* rocessing SOAP Namespace */
    soap_ns = axiom_soap_envelope_get_namespace(soap_env, env);
    trust_context->soap_namespace = axiom_namespace_get_uri(soap_ns, env);

    /* Processing WS-Trust namespace*/
    rst_ele = (axiom_element_t *) axiom_node_get_data_element(trust_context->rst_node, env);
    wst_ns = axiom_element_get_namespace(rst_ele, env, trust_context->rst_node);

    trust_context->wst_namespace = axiom_namespace_get_uri(wst_ns, env);

    trust_context_process_request_context(trust_context, env);
    trust_context_process_request_type(trust_context, env);
    trust_context_process_token_type(trust_context, env);
    trust_context_process_applies_to(trust_context, env);
    trust_context_process_claims(trust_context, env);
    trust_context_process_entropy(trust_context, env);
    trust_context_process_key_type(trust_context, env);
    trust_context_process_key_size(trust_context, env);

    return trust_context;
}

AXIS2_EXTERN void AXIS2_CALL
trust_context_free(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    if (trust_context)
    {
        AXIS2_FREE(env->allocator, trust_context);
    }
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_applies_to(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    axutil_qname_t *applies_to_qname = NULL;
    axutil_qname_t *addr_qname = NULL;
    axiom_node_t *appliesto_node = NULL;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *epr_node = NULL;
    axiom_node_t *addr_node = NULL;
    axiom_element_t *appliesto_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axiom_element_t *epr_ele = NULL;
    axiom_element_t *addr_ele = NULL;
    axiom_namespace_t *addr_namespace = NULL;
    

    rst_node = trust_context->rst_node;
    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(rst_node, env));

    applies_to_qname = axutil_qname_create(env, TRUST_APPLIES_TO, TRUST_WSP_XMLNS, TRUST_WSP);

    appliesto_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, applies_to_qname, rst_node,
                                                 &appliesto_node);
    if (appliesto_ele)
    {
        epr_ele = axiom_element_get_first_element(appliesto_ele, env, appliesto_node, &epr_node);
        
        trust_context->applies_to_epr_node = epr_node;

        if (!trust_context->addressing_namespace)
        {
            addr_namespace =  axiom_element_find_namespace(epr_ele, env, epr_node, "http://schemas.xmlsoap.org/ws/2004/08/addressing", NULL);
            if(!addr_namespace)
            {
                addr_namespace = axiom_element_find_namespace(epr_ele, env, epr_node, "http://www.w3.org/2005/08/addressing", NULL);
            }
            if(addr_namespace)
            {
                trust_context->addressing_namespace = axiom_namespace_get_uri(addr_namespace, env);
            }            
        }

        if (epr_ele && addr_namespace)
        {
            addr_qname =
                axutil_qname_create(env, EPR_ADDRESS, trust_context->addressing_namespace, NULL);
            addr_ele =
                axiom_element_get_first_child_with_qname(epr_ele, env, addr_qname, epr_node,
                                                         &addr_node);
            if (addr_ele && axiom_element_get_text(addr_ele, env, addr_node))
            {
                trust_context->applies_to_address = axiom_element_get_text(addr_ele, env, addr_node);
            }
        }
        else
        {
            AXIS2_FREE(env->allocator, applies_to_qname);
            return AXIS2_FAILURE;
        }

    }
    else
    {
        AXIS2_FREE(env->allocator, applies_to_qname);
        return AXIS2_FAILURE;
    }
    AXIS2_FREE(env->allocator, applies_to_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_request_context(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *attr_ctx_qname = NULL;
    axis2_char_t *context = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    attr_ctx_qname = axutil_qname_create(env, TRUST_RST_CONTEXT, TRUST_WST_XMLNS, TRUST_WST);
    if (!attr_ctx_qname)
        return AXIS2_FAILURE;

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(trust_context->rst_node, env));
    context = axiom_element_get_attribute_value(rst_ele, env, attr_ctx_qname);

    if (context)
    {
        trust_context->rst_context_attr = context;
        AXIS2_FREE(env->allocator, attr_ctx_qname);
        return AXIS2_SUCCESS;
    }
    AXIS2_FREE(env->allocator, attr_ctx_qname);
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_request_type(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    axiom_element_t *req_type_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *req_type_node = NULL;
    axutil_qname_t *req_type_qname = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    rst_node = trust_context->rst_node;
    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(rst_node, env));

    req_type_qname =
        axutil_qname_create(env, TRUST_REQUEST_TYPE, trust_context->wst_namespace, TRUST_WST);

    req_type_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, req_type_qname, rst_node,
                                                 &req_type_node);
    if (!req_type_ele)
    {
        AXIS2_FREE(env->allocator, req_type_qname);
        return AXIS2_FAILURE;
    }

    trust_context->request_type = axiom_element_get_text(req_type_ele, env, req_type_node);

    AXIS2_FREE(env->allocator, req_type_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_token_type(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    axiom_node_t *token_type_node = NULL;
    axiom_element_t *token_type_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *token_type_qname = NULL;

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(trust_context->rst_node, env));

    token_type_qname =
        axutil_qname_create(env, TRUST_TOKEN_TYPE, trust_context->wst_namespace, TRUST_WST);

    token_type_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, token_type_qname,
                                                 trust_context->rst_node, &token_type_node);
    if (!token_type_ele)
    {
        AXIS2_FREE(env->allocator, token_type_qname);
        return AXIS2_FAILURE;
    }

    trust_context->token_type = axiom_element_get_text(token_type_ele, env, token_type_node);

    AXIS2_FREE(env->allocator, token_type_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_claims(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    axiom_node_t *claims_node = NULL;
    axiom_element_t *claims_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *claims_qname = NULL;
    axutil_qname_t *attr_dialect_qname = NULL;
    axis2_char_t *dialect = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(trust_context->rst_node, env));

    claims_qname = axutil_qname_create(env, TRUST_CLAIMS, trust_context->wst_namespace, TRUST_WST);

    claims_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, claims_qname, trust_context->rst_node,
                                                 &claims_node);
    if (!claims_ele)
    {
        AXIS2_FREE(env->allocator, claims_qname);
        return AXIS2_FAILURE;
    }

    trust_context->claims_node = claims_node;

    attr_dialect_qname =
        axutil_qname_create(env, TRUST_CLAIMS_DIALECT, trust_context->wst_namespace, TRUST_WST);
    if (!attr_dialect_qname)
    {
        AXIS2_FREE(env->allocator, claims_qname);
        return AXIS2_FAILURE;
    }

    dialect = axiom_element_get_attribute_value(claims_ele, env, attr_dialect_qname);

    if (!dialect)
    {
        AXIS2_FREE(env->allocator, claims_qname);
        AXIS2_FREE(env->allocator, attr_dialect_qname);
        return AXIS2_FAILURE;
    }
    trust_context->claims_dialect = dialect;

    AXIS2_FREE(env->allocator, claims_qname);
    AXIS2_FREE(env->allocator, attr_dialect_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_entropy(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    /* TO DO: Complete the entropy processing */
    axiom_node_t *entropy_node = NULL;
    axiom_node_t *binary_secret_node = NULL;
    axiom_element_t *entropy_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axiom_element_t *binary_secret_ele = NULL;
    axutil_qname_t *entropy_qname = NULL;
    axis2_char_t *bin_sec_str = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(trust_context->rst_node, env));

    entropy_qname = axutil_qname_create(env, TRUST_ENTROPY, trust_context->wst_namespace, TRUST_WST);

    entropy_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, entropy_qname, trust_context->rst_node,
                                                 &entropy_node);
    if (!entropy_ele)
    {
        AXIS2_FREE(env->allocator, entropy_qname);
        return AXIS2_FAILURE;
    }

    binary_secret_ele =
        axiom_element_get_first_element(entropy_ele, env, entropy_node, &binary_secret_node);
    bin_sec_str = axiom_element_get_text(binary_secret_ele, env, binary_secret_node);

    if (binary_secret_ele && bin_sec_str && (axutil_strcmp("", bin_sec_str) != 0))
    {
        /*axutil_base64_decode(trust_context->request_entropy, bin_sec_str);*/
        trust_context->request_entropy = bin_sec_str;
    }
    else
    {
        AXIS2_FREE(env->allocator, entropy_qname);
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_key_type(
    trust_context_t * data,
    const axutil_env_t * env)
{
    axiom_node_t *key_type_node = NULL;
    axiom_element_t *key_type_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *key_type_qname = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(data->rst_node, env));

    key_type_qname = axutil_qname_create(env, TRUST_KEY_TYPE, data->wst_namespace, TRUST_WST);

    key_type_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, key_type_qname, data->rst_node,
                                                 &key_type_node);
    if (!key_type_ele)
    {
        AXIS2_FREE(env->allocator, key_type_qname);
        return AXIS2_FAILURE;
    }

    data->key_type = axiom_element_get_text(key_type_ele, env, key_type_node);

    AXIS2_FREE(env->allocator, key_type_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_key_size(
    trust_context_t * data,
    const axutil_env_t * env)
{
    axiom_node_t *key_size_node = NULL;
    axiom_element_t *key_size_ele = NULL;
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *key_size_qname = NULL;
    axis2_char_t *size_str = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    rst_ele = (axiom_element_t *) (axiom_node_get_data_element(data->rst_node, env));

    key_size_qname = axutil_qname_create(env, TRUST_KEY_SIZE, data->wst_namespace, TRUST_WST);

    key_size_ele =
        axiom_element_get_first_child_with_qname(rst_ele, env, key_size_qname, data->rst_node,
                                                 &key_size_node);
    if (!key_size_ele)
    {
        AXIS2_FREE(env->allocator, key_size_qname);
        return AXIS2_FAILURE;
    }

    size_str = axiom_element_get_text(key_size_ele, env, key_size_node);

    if (!size_str)
    {
        AXIS2_FREE(env->allocator, key_size_qname);
        return AXIS2_FAILURE;
    }

    data->key_size = atoi(size_str);
    AXIS2_FREE(env->allocator, key_size_qname);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_context_get_request_type(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    return trust_context->request_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_set_request_type(
    trust_context_t * trust_context,
    const axutil_env_t * env,
    axis2_char_t *request_type)
{
    if(request_type)
    {
        trust_context->request_type = request_type;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_context_get_token_type(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    return trust_context->token_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_set_token_type(
    trust_context_t * trust_context,
    const axutil_env_t * env,
    axis2_char_t *token_type)
{
    if(token_type)
    {
        trust_context->token_type = token_type;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_context_get_rst_node(
        trust_context_t * trust_context,
        const axutil_env_t * env)
{
    return trust_context->rst_node;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_set_rst_node(
        trust_context_t * trust_context,
        const axutil_env_t * env,
        axiom_node_t *rst_node)
{
    if(rst_node)
    {
        trust_context->rst_node = rst_node;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_context_get_wst_ns(
    trust_context_t * trust_context,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return trust_context->wst_namespace;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_context_get_appliesto_address(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->applies_to_address;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_context_get_appliesto_epr_node(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->applies_to_epr_node;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_context_get_rst_context_attr(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->rst_context_attr;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_context_get_key_type(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->key_type;
}

AXIS2_EXTERN int AXIS2_CALL
trust_context_get_key_size(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->key_size;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_context_get_request_entropy(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->request_entropy;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_context_get_claims_node(
        trust_context_t *trust_context,
        const axutil_env_t *env)
{
    return trust_context->claims_node;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_context_get_claims_dialect(
        trust_context_t * trust_context,
        const axutil_env_t *env)
{
    return trust_context->claims_dialect;
}

