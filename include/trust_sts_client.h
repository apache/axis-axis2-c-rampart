
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

#ifndef TRUST_STS_CLIENT
#define TRUST_STS_CLIENT

/**
  * @file trust_sts_client.h
  * @brief contains the specific sts client interface
  */

#include <stdio.h>
#include <stdlib.h>
#include <axiom.h>
#include <axutil_utils.h>
#include <axis2_client.h>
#include <rp_includes.h>
#include <rp_secpolicy.h>
#include <neethi_policy.h>
#include <neethi_util.h>
#include <rampart_util.h>
#include <trust_constants.h>
#include <trust_util.h>
#include <trust_policy_util.h>
#include <trust_token.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct trust_sts_client trust_sts_client_t;

    AXIS2_EXTERN trust_sts_client_t *AXIS2_CALL
    trust_sts_client_create(
        const axutil_env_t * env);

    AXIS2_EXTERN void AXIS2_CALL
    trust_sts_client_free(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env);

    AXIS2_EXTERN void AXIS2_CALL
    trust_sts_client_request_security_token(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * applies_to,
        axis2_char_t * token_type);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    trust_sts_client_create_issue_request(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * request_type,
        axis2_char_t * applies_to,
        axis2_char_t * token_type);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_sts_client_create_renew_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *token_type,
        axis2_char_t *request_type,
        axiom_node_t *renew_target,
        axis2_bool_t allow_postdating,
        trust_allow_t renew_allow,
        trust_ok_t ok_flag);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    tust_sts_client_create_cancel_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *request_type,
        axiom_node_t *cancel_target);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_sts_client_create_validate_request(
        trust_sts_client_t *sts_client,
        const axutil_env_t *env,
        axis2_char_t *token_type,
        axis2_char_t *request_type);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_sts_client_process_policies(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        neethi_policy_t * issuer_policy,
        neethi_policy_t * service_policy);

    AXIS2_EXTERN axis2_svc_client_t *AXIS2_CALL
    trust_sts_client_get_svc_client(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        axis2_char_t * action);

    AXIS2_EXTERN trust_token_t *AXIS2_CALL
    trust_sts_client_process_issue_response(
        trust_sts_client_t * sts_client,
        const axutil_env_t * env,
        int wst_version,
        axiom_node_t * response_node,
        axiom_node_t * payload_sent);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_sts_client_find_identifier(
        trust_sts_client_t * sts_client,
        axiom_node_t * req_att_ref_node,
        axiom_node_t * req_unatt_ref_node,
        axiom_node_t * sec_token_node,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_sts_client_get_id_from_str(
        trust_sts_client_t * sts_client,
        axiom_node_t * ref_node,
        const axutil_env_t * env);

#ifdef __cplusplus
}
#endif
#endif                          /*TRUST_STS_CLIENT_H */
