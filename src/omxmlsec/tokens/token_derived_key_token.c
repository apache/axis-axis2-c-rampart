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

#include <oxs_constants.h>
#include <oxs_error.h>
#include <oxs_tokens.h>
#include <oxs_utility.h>
#include <axiom_attribute.h>
#include <axiom_element.h>
#include <rampart_constants.h>

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_derived_key_token_element(const axutil_env_t *env,
        axiom_node_t *parent,
        axis2_char_t* id,
        axis2_char_t* algo)
{
    axiom_node_t *derived_key_token_node = NULL;
    axiom_element_t *derived_key_token_ele = NULL;
    axiom_attribute_t *algo_att = NULL;
    axiom_attribute_t *id_attr = NULL;
    int ret;
    axiom_namespace_t *ns_obj = NULL;
    axiom_namespace_t *ns = NULL;

    ns_obj = axiom_namespace_create(env, OXS_WSC_NS,
                                    OXS_WSC);

    ns = axiom_namespace_create(env, RAMPART_WSU_XMLNS, OXS_WSU);

    derived_key_token_ele = axiom_element_create(env, parent, OXS_NODE_DERIVED_KEY_TOKEN, ns_obj, &derived_key_token_node);
    if (!derived_key_token_ele)
    {
        oxs_error(env, ERROR_LOCATION,
                  OXS_ERROR_ELEMENT_FAILED, "Error creating %s Token element", OXS_NODE_DERIVED_KEY_TOKEN);
        return NULL;
    }

    if (!id)
    {
        id = oxs_util_generate_id(env,(axis2_char_t*)OXS_DERIVED_ID);
    }


    id_attr = axiom_attribute_create(env, OXS_ATTR_ID, id,ns);
    algo_att =  axiom_attribute_create(env, OXS_ATTR_ALGORITHM, algo, NULL);

    ret = axiom_element_add_attribute(derived_key_token_ele, env, id_attr, derived_key_token_node);
    ret = axiom_element_add_attribute(derived_key_token_ele, env, algo_att, derived_key_token_node);

    return derived_key_token_node;
}


