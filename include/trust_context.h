
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

#ifndef TRUST_CONTEXT_H
#define TRUST_CONTEXT_H

/**
  * @file trust_context.h
  * @brief Holds function declarations and data for data
  */

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <axutil_base64.h>
#include <axiom_soap.h>
#include <axiom.h>
#include <axis2_msg_ctx.h>
#include <axis2_addr.h>
#include <trust_constants.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct trust_context trust_context_t;

    AXIS2_EXTERN trust_context_t *AXIS2_CALL
    trust_context_create(
        const axutil_env_t * env,
        axis2_msg_ctx_t * in_msg_ctx);

    AXIS2_EXTERN void AXIS2_CALL
    trust_context_free(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_applies_to(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL

    trust_context_process_request_context(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_request_type(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_applies_to(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_life_time(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_claims(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_entorpy(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_token_type(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_entropy(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_key_type(
        trust_context_t * data,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_process_key_size(
        trust_context_t * data,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_context_get_token_type(
        trust_context_t * trust_context,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_set_token_type(
        trust_context_t * trust_context,
        const axutil_env_t * env,
        axis2_char_t *token_type);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_context_get_rst_node(
        trust_context_t * trust_context,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_set_rst_node(
            trust_context_t * trust_context,
            const axutil_env_t * env,
            axiom_node_t *rst_node);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_context_get_request_type(
        trust_context_t * trust_context,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_context_set_request_type(
        trust_context_t * trust_context,
        const axutil_env_t * env,
        axis2_char_t *request_type);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_context_get_soap_ns(
        trust_context_t * trust_context,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_context_get_wst_ns(
        trust_context_t * trust_context,
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_context_get_appliesto_address(
            trust_context_t *trust_context,
            const axutil_env_t *env);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_context_get_appliesto_epr_node(
            trust_context_t *trust_context,
            const axutil_env_t *env);

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_context_get_rst_context_attr(
            trust_context_t *trust_context,
            const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    trust_context_get_key_type(
            trust_context_t *trust_context,
            const axutil_env_t *env);

    AXIS2_EXTERN int AXIS2_CALL
    trust_context_get_key_size(
            trust_context_t *trust_context,
            const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_context_get_request_entropy(
            trust_context_t *trust_context,
            const axutil_env_t *env);
    
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    trust_context_get_claims_node(
            trust_context_t *trust_context,
            const axutil_env_t *env);
    
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_context_get_claims_dialect(
            trust_context_t * trust_context,
            const axutil_env_t *env);

#ifdef __cplusplus
}
#endif
#endif                          /*TRUST_CONTEXT_H */
