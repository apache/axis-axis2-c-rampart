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
#include <oxs_constants.h>
#include <oxs_error.h>
#include <oxs_tokens.h>
#include <axiom_element.h>
#include <oxs_axiom.h>


AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_token_get_nonce_value(const axutil_env_t *env,
                           axiom_node_t *nonce_node)
{
    axis2_char_t *value = NULL;
    value = (axis2_char_t*)oxs_axiom_get_node_content(env, nonce_node);
    return value;

}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_nonce_element(const axutil_env_t *env,
                                     axiom_node_t *parent,
                                     axis2_char_t* nonce_val
                                    )
{
    axiom_node_t *nonce_node = NULL;
    axiom_element_t *nonce_ele = NULL;
    axis2_status_t ret;
    axiom_namespace_t *ns_obj = NULL;

    ns_obj = axiom_namespace_create(env, OXS_WSC_NS,
                                    OXS_WSC);

    nonce_ele = axiom_element_create(env, parent, OXS_NODE_NONCE, ns_obj, &nonce_node);
    if (!nonce_ele)
    {
        oxs_error(env, ERROR_LOCATION,
                  OXS_ERROR_ELEMENT_FAILED, "Error creating %s element", OXS_NODE_NONCE);
        return NULL;
    }

    if (nonce_val)
    {
        ret  = axiom_element_set_text(nonce_ele, env, nonce_val, nonce_node);
    }

    return nonce_node;

}

