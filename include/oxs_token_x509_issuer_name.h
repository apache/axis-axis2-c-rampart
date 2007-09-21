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

#ifndef OXS_TOKEN_X509_ISSUER_NAME_H
#define OXS_TOKEN_X509_ISSUER_NAME_H


/**
  * @file oxs_token_x509_issuer_name.h 
  * @brief Represents <X509IssuerName> element
  */

#include <axis2_defines.h>
#include <axutil_env.h>
#include <axiom_node.h>
#include <axiom_element.h>
#include <axutil_qname.h>
#ifdef __cplusplus
extern "C"
{
#endif

    /**
    * X509IssuerName element
    */

    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_token_get_issuer_name(const axutil_env_t *env,
                              axiom_node_t *issuer_name_node);

    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_issuer_name_element(const axutil_env_t *env,
                                        axiom_node_t *parent,
                                        axis2_char_t* value );

    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* OXS_TOKEN_X509_ISSUER_NAME_H */
