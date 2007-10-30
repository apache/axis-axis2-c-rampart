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

#ifndef OXS_DERIVATION_H
#define OXS_DERIVATION_H


/**
  * @file oxs_derivation.h
  * @brief The Key derivation module for OMXMLSecurity 
  */

/**
* @defgroup oxs_derivation Derivation
* @ingroup oxs
* @{
*/
#include <axis2_defines.h>
#include <axutil_env.h>
#include <oxs_key.h>
#include <oxs_buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif


    /**
     * Derive Keys 
     * Caller must free memory
     * @param env pointer to environment struct
     * @param secret The secret is the shared secret that is exchanged (note that if two secrets were securely exchanged,\
     * possible as part of an initial exchange, they are concatenated in the order they were sent/received)
     * @param label The label is the concatenation of the client's label and the service's label
     * @param seed  The seed is the concatenation of nonce values (if multiple were exchanged) that were exchanged (initiator + receiver)
     * @param derived_key The derived key. Caller must create and free
     * @return status 
     **/
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_derivation_derive_key(const axutil_env_t *env,
                         oxs_key_t *secret,
                         oxs_buffer_t *label,
                         oxs_buffer_t *seed,
                         oxs_key_t *derived_key
                         );

    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_derivation_build_derived_key_token(const axutil_env_t *env,
    oxs_key_t *derived_key,
    axiom_node_t *parent,
    axis2_char_t *stref_uri,
    axis2_char_t *stref_val_type);

    /* If the (optional) session_key is NULL then extract it form the refered EncryptedKey. Otherwise use it
     * to Derive a new key using information available in the dk_token*/
    AXIS2_EXTERN oxs_key_t * AXIS2_CALL
    oxs_derivation_extract_derived_key_from_token(const axutil_env_t *env,
    axiom_node_t *dk_token,
    axiom_node_t *root_node,
    oxs_key_t *session_key);
    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* OXS_DERIVATION_H */
