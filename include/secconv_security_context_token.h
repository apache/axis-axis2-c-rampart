
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

#ifndef SECCONV_SECURITY_CONTEXT_TOKEN_H
#define SECCONV_SECURITY_CONTEXT_TOKEN_H

/**
  * @file secconv_security_context_token.h
  * @brief security context token
  */

#include <stdio.h>
#include <stdlib.h>
#include <axutil_utils.h>
#include <axutil_string.h>
#include <oxs_buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct security_context_token_t security_context_token_t;

    AXIS2_EXTERN security_context_token_t *AXIS2_CALL
    security_context_token_create(
        const axutil_env_t * env);

    AXIS2_EXTERN void AXIS2_CALL
    security_context_token_free(
        security_context_token_t *sct, 
        const axutil_env_t *env);

    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
    security_context_token_get_secret(
        security_context_token_t * sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    security_context_token_get_global_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env);
    
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    security_context_token_get_local_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_secret(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        oxs_buffer_t *buffer);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_global_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        axis2_char_t *global_id);
    
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_local_identifier(
        security_context_token_t * sct, 
        const axutil_env_t * env,
        axis2_char_t *local_id);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_requested_proof_token(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_attached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_unattached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    security_context_token_get_token(
        security_context_token_t *sct, 
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_requested_proof_token(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_attached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_unattached_reference(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_set_token(
        security_context_token_t *sct, 
        const axutil_env_t * env,
        axiom_node_t *node);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_increment_ref(
        security_context_token_t *sct,
        const axutil_env_t * env);

    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    security_context_token_serialize(
        security_context_token_t *sct, 
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    security_context_token_deserialize(
        security_context_token_t *sct, 
        const axutil_env_t *env, 
        axis2_char_t *serialised_node);
   
#ifdef __cplusplus
}
#endif
#endif                          /*SECCONV_SECURITY_CONTEXT_TOKEN_H */
