/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RP_SIGNED_ENCRYPTED_ELEMENTS_BUILDER_H
#define RP_SIGNED_ENCRYPTED_ELEMENTS_BUILDER_H

/** @defgroup rp_signed_encrypted_elements_builder
 * @ingroup rp_signed_encrypted_elements_builder
 * @{
 */

#include <rp_includes.h>
#include <rp_signed_encrypted_elements.h>

#ifdef __cplusplus
extern "C"
{
#endif

    AXIS2_EXTERN rp_signed_encrypted_elements_t *AXIS2_CALL
    rp_signed_encrypted_elements_builder_build(
        const axis2_env_t *env,
        axiom_node_t *elements);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rp_signed_encrypted_elements_builder_set_properties(
        axiom_node_t *node,
        axiom_element_t *element,
        axis2_char_t *local_name,
        rp_signed_encrypted_elements_t *signed_encrypted_elements,
        const axis2_env_t *env);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rp_signed_encrypted_elements_builder_set_xpath_version(
        axiom_element_t *element,
        rp_signed_encrypted_elements_t *signed_encrypted_elements,
        const axis2_env_t *env);



#ifdef __cplusplus
}
#endif
#endif
