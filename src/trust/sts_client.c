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

#include <trust_sts_client.h>

#ifndef TRUST_COMPUTED_KEY_PSHA1
#define TRUST_COMPUTED_KEY_PSHA1	"P-SHA1"
#endif

struct trust_sts_client
{

    /*WS Trust version */
    int version;

    /* Key size */
    int key_size;

    /* Algorithm Suite for Entropy */
    rp_algorithmsuite_t *algo_suite;

    /* Trust 1.0 Assertions */
    rp_trust10_t *trust10;

    /* Requestor Entropy */
    axis2_char_t *requestor_entropy;
    
    axis2_char_t *appliesto;
    
    axis2_char_t *token_type;

    /* Time To Live */
    int ttl;

    /* Issuer Address */
    axis2_char_t *issuer_address;

    /* STS Client Home Directory */
    axis2_char_t *home_dir;

    /* Location of the issuer's policy file */
    axis2_char_t *issuer_policy_location;

    /* Location of the service's (relying party's) policy file */
    axis2_char_t *service_policy_location;
};

AXIS2_EXTERN trust_sts_client_t *AXIS2_CALL
trust_sts_client_create(
    const axutil_env_t * env)
{
    trust_sts_client_t *sts_client = NULL;

    sts_client = (trust_sts_client_t *) AXIS2_MALLOC(env->allocator, sizeof(trust_sts_client_t));

    sts_client->version = TRUST_VERSION_05_02;
    sts_client->key_size = 0;
    sts_client->ttl = 0;
    sts_client->requestor_entropy = NULL;
    sts_client->trust10 = NULL;
    sts_client->appliesto = NULL;
    sts_client->token_type = NULL;
    sts_client->home_dir = NULL;
    sts_client->issuer_address = NULL;
    sts_client->issuer_policy_location = NULL;
    sts_client->service_policy_location = NULL;

    return sts_client;
}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_free(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (sts_client)
    {
        AXIS2_FREE(env->allocator, sts_client);
    }

}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_request_security_token(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * applies_to,
    axis2_char_t * token_type)
{
    axis2_svc_client_t *svc_client = NULL;
    neethi_policy_t *issuer_policy = NULL;
    neethi_policy_t *service_policy = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *return_node = NULL;
    
    sts_client->appliesto = applies_to;
    sts_client->token_type = token_type;

    issuer_policy = neethi_util_create_policy_from_file(env, sts_client->issuer_policy_location);

    service_policy = neethi_util_create_policy_from_file(env, sts_client->service_policy_location);

    if (!issuer_policy || !service_policy)
    {
        status = AXIS2_FAILURE;
    }
    else
    {
        trust_sts_client_process_policies(sts_client, env, issuer_policy, service_policy);
    }

    /* TODO : Fix action logic */
    svc_client =
        trust_sts_client_get_svc_client(sts_client, env,
                                        "http://schemas.xmlsoap.org/ws/2005/02/RST/issue");

    if (status == AXIS2_SUCCESS)
    {
        status = axis2_svc_client_set_policy(svc_client, env, issuer_policy);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
        }

        return_node =
            axis2_svc_client_send_receive(svc_client, env,
                                          trust_sts_client_create_issue_request(sts_client, env,
                                                                                "/Issue",
                                                                                applies_to,
                                                                                token_type));
    }
    if (svc_client)
    {
        axis2_svc_client_free(svc_client, env);
        svc_client = NULL;
    }

    return;
}

AXIS2_EXTERN axis2_svc_client_t *AXIS2_CALL
trust_sts_client_get_svc_client(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * action)
{
    axis2_endpoint_ref_t *endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t *svc_client = NULL;

    endpoint_ref = axis2_endpoint_ref_create(env, sts_client->issuer_address);

    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env, action);

    svc_client = axis2_svc_client_create(env, sts_client->home_dir);
    if (!svc_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:" " %d :: %s",
                        env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /* Engage addressing module */
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);

    return svc_client;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_process_policies(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    neethi_policy_t * issuer_policy,
    neethi_policy_t * service_policy)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (issuer_policy)
    {
        sts_client->algo_suite = trust_policy_util_get_algorithmsuite(env, issuer_policy);
    }

    if (service_policy)
    {
        sts_client->trust10 = trust_policy_util_get_trust10(env, service_policy);
    }

    return AXIS2_SUCCESS;
}
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
trust_sts_client_create_issue_request(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * request_type,
    axis2_char_t * applies_to,
    axis2_char_t * token_type)
{
    axiom_node_t *rst_node = NULL;
    axiom_node_t *entropy_node = NULL;
    axiom_node_t *binsec_node = NULL;
    int maxkey_len = 0;

    rst_node = trust_util_create_rst_element(env, sts_client->version, NULL);

    /* Setting up the request type */
    trust_util_create_request_type_element(env, sts_client->version, rst_node, request_type);

    /* Setting up the token type */
    if (token_type)
    {
        trust_util_create_token_type_element(env, sts_client->version, rst_node, token_type);
    }

    if (applies_to)
        trust_util_create_applies_to_element(env, rst_node, applies_to, TRUST_WSA_XMLNS);

    if (sts_client->trust10 && sts_client->algo_suite)
    {
        if (rp_trust10_get_require_client_entropy(sts_client->trust10, env) == AXIS2_TRUE)
        {
            entropy_node = trust_util_create_entropy_element(env, sts_client->version, rst_node);
            maxkey_len = rp_algorithmsuite_get_max_symmetric_keylength(sts_client->algo_suite, env);
            sts_client->requestor_entropy =
                (axis2_char_t *) rampart_generate_nonce(env, maxkey_len);

            binsec_node =
                trust_util_create_binary_secret_element(env, sts_client->version, entropy_node,
                                                        sts_client->requestor_entropy,
                                                        TRUST_BIN_SEC_TYPE_NONCE);

            trust_util_create_computed_key_algo_element(env, sts_client->version, rst_node,
                                                        TRUST_COMPUTED_KEY_PSHA1);
        }
    }
    else
    {
        printf("Algo Suite or Trust10 Error!\n");
    }

    trust_sts_client_free(sts_client, env);

    return rst_node;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_sts_client_create_renew_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *token_type,
        axis2_char_t *request_type,
        axiom_node_t *renew_target,
        axis2_bool_t allow_postdating,
        trust_allow_t renew_allow,
        trust_ok_t ok_flag)
{
    axiom_node_t *rst_node = NULL;
    
    rst_node = trust_util_create_rst_element(env, sts_client->version, NULL);
    
    if(token_type)
    {
        trust_util_create_token_type_element(env, sts_client->version, rst_node, token_type);
    }
    trust_util_create_request_type_element(env, sts_client->version, rst_node, request_type);
    
    if(renew_target)
    {
        trust_util_create_renew_traget_element(env, sts_client->version, rst_node, renew_target);
    }
    else
    {
        return NULL;
    }
    
    if(allow_postdating)
    {
        trust_util_create_allow_postdating_element(env, sts_client->version, rst_node);
    }
    
    trust_util_create_renewing_element(env, sts_client->version, rst_node, renew_allow, ok_flag);
    
    return rst_node;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
tust_sts_client_create_cancel_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *request_type,
        axiom_node_t *cancel_target)
{
    axiom_node_t *rst_node = NULL;
    
    rst_node = trust_util_create_rst_element(env, sts_client->version, NULL);
    
    trust_util_create_request_type_element(env, sts_client->version, rst_node, request_type);
    
    if(cancel_target)
    {
        if(!trust_util_create_cancel_target_element(env, sts_client->version, rst_node, cancel_target))
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
    
    return rst_node;
}
   
AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_sts_client_create_validate_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *token_type,
        axis2_char_t *request_type)
{
    axiom_node_t *rst_node = NULL;
    
    rst_node = trust_util_create_rst_element(env, sts_client->version, NULL);
    
    if(token_type)
    {
        trust_util_create_token_type_element(env, sts_client->version, rst_node, token_type);
    }
    
    if(request_type)
    {
        trust_util_create_request_type_element(env, sts_client->version, rst_node, request_type);
    }
    
    return rst_node;
}
/* Process ISSUE RESPONSE */
AXIS2_EXTERN trust_token_t *AXIS2_CALL
trust_sts_client_process_issue_response(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    int wst_version,
    axiom_node_t * response_node,
    axiom_node_t * payload_sent)
{
    /* Token */
    trust_token_t *token = NULL;

    /* RSTR */
    axiom_node_t *rstr_node = NULL;
    axiom_element_t *rstr_ele = NULL;

    axis2_char_t *wst_ns_uri = NULL;

    /* Attached Reference */
    axiom_node_t *attached_ref_node = NULL;
    axiom_element_t *attached_ref_ele = NULL;
    axutil_qname_t *attached_ref_qname = NULL;
    axiom_node_t *req_attached_ref_node = NULL;

    /* Unattached Reference */
    axiom_node_t *unattached_ref_node = NULL;
    axiom_element_t *unattached_ref_ele = NULL;
    axutil_qname_t *unattached_ref_qname = NULL;
    axiom_node_t *req_unattached_ref_node = NULL;

    /*Requsted Security Token */
    axiom_node_t *req_sec_token_node = NULL;
    axiom_element_t *req_sec_token_ele = NULL;
    axutil_qname_t *req_sec_token_qname = NULL;
    axiom_node_t *sec_token = NULL;

    /* Life Time */
    axiom_node_t *life_time_node = NULL;
    axiom_element_t *life_time_ele = NULL;
    axutil_qname_t *life_time_qname = NULL;

    rstr_node = response_node;

    if (TRUST_VERSION_05_12 == wst_version)
    {
        rstr_node = axiom_node_get_first_element(rstr_node, env);
    }

    wst_ns_uri = trust_util_get_wst_ns(env, wst_version);
    rstr_ele = axiom_node_get_data_element(rstr_node, env);

    /* Extract Attached Reference */

    attached_ref_qname =
        axutil_qname_create(env, TRUST_REQUESTED_ATTACHED_REFERENCE, wst_ns_uri, TRUST_WST);

    attached_ref_ele =
        axiom_element_get_first_child_with_qname(rstr_ele, env, attached_ref_qname, rstr_node,
                                                 &attached_ref_node);

    if (attached_ref_ele)
    {
        req_attached_ref_node = axiom_node_get_first_element(attached_ref_node, env);
    }

    /* Extract unattached Reference */
    unattached_ref_qname =
        axutil_qname_create(env, TRUST_REQUESTED_UNATTACHED_REFERENCE, wst_ns_uri, TRUST_WST);

    unattached_ref_ele =
        axiom_element_get_first_child_with_qname(rstr_ele, env, unattached_ref_qname, rstr_node,
                                                 &unattached_ref_node);
    if (unattached_ref_ele)
    {
        req_unattached_ref_node = axiom_node_get_first_element(unattached_ref_node, env);
    }

    /* Extract Requested Security Token */
    req_sec_token_qname =
        axutil_qname_create(env, TRUST_REQUESTED_SECURITY_TOKEN, wst_ns_uri, TRUST_WST);
    req_sec_token_ele =
        axiom_element_get_first_child_with_qname(rstr_ele, env, req_sec_token_qname, rstr_node,
                                                 &req_sec_token_node);

    if (req_sec_token_node)
    {
        sec_token = axiom_node_get_first_element(req_sec_token_node, env);
    }
    else
    {
        /*Requsted Token Missing - Handle */
    }

    /* Extract Life Time */
    life_time_qname = axutil_qname_create(env, TRUST_LIFE_TIME, wst_ns_uri, TRUST_WST);
    life_time_ele =
        axiom_element_get_first_child_with_qname(rstr_ele, env, life_time_qname, rstr_node,
                                                 &life_time_node);

    if (NULL == life_time_ele)
    {
        /* Handle NULL - life time ele */
    }

    /* TOKEN Creation */
    /* FIX id- NULL :-> ID should be computed here */
    token = trust_token_create(env, NULL, sec_token, life_time_node);

    return token;

}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_find_identifier(
    trust_sts_client_t * sts_client,
    axiom_node_t * req_att_ref_node,
    axiom_node_t * req_unatt_ref_node,
    axiom_node_t * sec_token_node,
    const axutil_env_t * env)
{
    axis2_char_t *id_str = NULL;

    if (req_att_ref_node)
    {
        id_str = trust_sts_client_get_id_from_str(sts_client, req_att_ref_node, env);
    }
    else if (req_unatt_ref_node)
    {
        id_str = trust_sts_client_get_id_from_str(sts_client, req_unatt_ref_node, env);
    }
    else
    {
        /* FIX : WSConstants based wsu:Id */

    }
    return id_str;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_id_from_str(
    trust_sts_client_t * sts_client,
    axiom_node_t * ref_node,
    const axutil_env_t * env)
{
    /*FIX : implementation requires WS.Consatants paramaters */
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_ttl(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    int ttl)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, ttl, AXIS2_FAILURE);

    sts_client->ttl = ttl;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
trust_sts_client_get_ttl(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->ttl;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * address)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, address, AXIS2_FAILURE);

    sts_client->issuer_address = address;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_address;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * directory)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, directory, AXIS2_FAILURE);

    sts_client->home_dir = directory;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->home_dir;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->issuer_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_policy_location;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->service_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->service_policy_location;
}
