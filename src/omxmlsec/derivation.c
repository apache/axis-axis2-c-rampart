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
#include <axis2_util.h>
#include <oxs_derivation.h>
#include <oxs_key.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_asym_ctx.h>
#include <oxs_tokens.h>


AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_derivation_build_derived_key_token(const axutil_env_t *env,
    oxs_key_t *derived_key,
    axiom_node_t *parent,
    axis2_char_t *stref_uri,
    axis2_char_t *stref_val_type)
{
    axiom_node_t *dk_token = NULL;
    axiom_node_t *str_token = NULL;
    axiom_node_t *ref_token = NULL;
    axiom_node_t *nonce_token = NULL;
    axiom_node_t *offset_token = NULL;
    axiom_node_t *length_token = NULL;
    
    axis2_char_t *dk_id = NULL;
    axis2_char_t *nonce = NULL;
    int offset = -1;
    int length = 0; 

    dk_id = oxs_key_get_name(derived_key, env);

    dk_token = oxs_token_build_derived_key_token_element(env, parent, dk_id, NULL);
    str_token = oxs_token_build_security_token_reference_element(env, dk_token); 
    ref_token = oxs_token_build_reference_element(env, dk_token, stref_uri, stref_val_type);

    /*Create offset*/
    offset = oxs_key_get_offset(derived_key, env);
    if(offset > -1){
        offset_token = oxs_token_build_offset_element(env, dk_token, offset);
    }
    /*Create length*/
    length = oxs_key_get_size(derived_key, env);
    if(length > 0){
        length_token = oxs_token_build_length_element(env, dk_token, length);
    }
    /*Create nonce*/
    nonce = oxs_key_get_nonce(derived_key, env);
    if(nonce){
        nonce_token = oxs_token_build_nonce_element(env, dk_token, nonce);
    }
   
    return dk_token; 
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_derivation_derive_key(const axutil_env_t *env,
                         oxs_key_t *secret,
                         oxs_buffer_t *label,
                         oxs_buffer_t *seed,
                         oxs_key_t *derived_key
                         )
{
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *dk_id = NULL;
    /*TODO Concatenate the seed and label*/

    /*TODO P_SHA1 (secret, label + seed)*/
    
    /*TODO Populate the derived key. What we do here is fake. We use the same key ;-)*/
    dk_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_DERIVED_ID);
    status = oxs_key_populate(derived_key, env,
        oxs_key_get_data(secret, env),
        dk_id,
        oxs_key_get_size(secret, env),
        oxs_key_get_usage(secret, env));
    
    oxs_key_set_nonce(derived_key, env, oxs_util_generate_nonce(env, 16)); /*Nonce length*/ 
    oxs_key_set_offset(derived_key, env, 0); /*Default ??*/ 

    return status;
}

