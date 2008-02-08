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

#ifndef RAMPART_SAML_TOKEN_H
#define RAMPART_SAML_TOKEN_H

#include <rampart_saml_token.h>
#include <oxs_saml_token.h>
#include <axutil_utils.h>
#include <axiom.h>
#include <axis2_msg_ctx.h>
#include <oxs_key.h>
#include <rp_property.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
/*
 * Rampart saml token subject confirmation types. Rampart support both holder 
 * of key and sender vouches methods of subject confiramtions.
 */
typedef enum 
{
    RAMPART_ST_CONFIR_TYPE_UNSPECIFIED = 0,
    RAMPART_ST_CONFIR_TYPE_SENDER_VOUCHES,
    RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY
} rampart_st_confir_type_t;

typedef struct rampart_saml_token_t rampart_saml_token_t;

AXIS2_EXTERN rampart_saml_token_t *AXIS2_CALL
rampart_saml_token_create(axutil_env_t *env, axiom_node_t *assertion, 
                          rampart_st_confir_type_t type);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_free(rampart_saml_token_t *tok, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_assertion(rampart_saml_token_t *tok, axutil_env_t *env, 
                                 axiom_node_t *assertion);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
rampart_saml_token_get_assertion(rampart_saml_token_t *tok, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_type(rampart_saml_token_t *tok, axutil_env_t *env, 
                            rampart_st_confir_type_t type);

AXIS2_EXTERN rampart_st_confir_type_t AXIS2_CALL
rampart_saml_token_get_type(rampart_saml_token_t *tok, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_key_value(rampart_saml_token_t *tok, axutil_env_t *env, 
                                 oxs_key_t *key);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
rampart_saml_token_get_str(rampart_saml_token_t *tok, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_set_str(rampart_saml_token_t *tok, axutil_env_t *env, 
                           axiom_node_t *str);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_is_added_to_header(rampart_saml_token_t *tok, 
                                      axutil_env_t *env,
                                      axis2_bool_t is_token_added);

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_saml_token_is_added_to_header(rampart_saml_token_t *tok, 
                                      axutil_env_t *env);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_set_token_type(rampart_saml_token_t *tok,
								  axutil_env_t *env,
								  rp_property_type_t token_type);

AXIS2_EXTERN rp_property_type_t AXIS2_CALL
rampart_saml_token_get_token_type(rampart_saml_token_t *tok,
								  axutil_env_t *env);
#ifdef __cplusplus
}
#endif


#endif 