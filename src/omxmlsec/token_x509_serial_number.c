/*
 *   Copyright 2003-2004 The Apache Software Foundation.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <oxs_constants.h>
#include <oxs_error.h>
#include <oxs_token_x509_serial_number.h>
#include <axiom_element.h>
#include <oxs_axiom.h>


AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_token_get_serial_number(const axis2_env_t *env,
        axiom_node_t *serial_number_node)
{
    axis2_char_t *val = NULL;
    /*TODO Verification*/
    val = (axis2_char_t*)oxs_axiom_get_node_content(env, serial_number_node);
    return val;

}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_token_build_serial_number_element(const axis2_env_t *env,
        axiom_node_t *parent,
        axis2_char_t* value
                                    )
{
    axiom_node_t *serial_number_node = NULL;
    axiom_element_t *serial_number_ele = NULL;
    axis2_status_t ret;
    axiom_namespace_t *ns_obj = NULL;

    ns_obj = axiom_namespace_create(env, OXS_DSIG_NS,
            OXS_DS);

    serial_number_ele = axiom_element_create(env, parent, OXS_NODE_X509_SERIAL_NUMBER, ns_obj, &serial_number_node);
    if (!serial_number_ele)
    {
        oxs_error(ERROR_LOCATION,
                OXS_ERROR_ELEMENT_FAILED, "Error creating  element");
        return NULL;
    }

    if (value)
    {
        ret  = AXIOM_ELEMENT_SET_TEXT(serial_number_ele, env, value, serial_number_node);
    }

    return serial_number_node;

}

