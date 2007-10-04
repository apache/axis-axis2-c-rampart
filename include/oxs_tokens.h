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

#ifndef OXS_TOKENS_H
#define OXS_TOKENS_H

#include <axutil_qname.h>
#include <oxs_token_binary_security_token.h>
#include <oxs_token_embedded.h>
#include <oxs_token_reference_list.h>
#include <oxs_token_transforms.h>
#include <oxs_token_c14n_method.h>
#include <oxs_token_encrypted_data.h>
#include <oxs_token_security_token_reference.h>
#include <oxs_token_x509_certificate.h>
#include <oxs_token_cipher_data.h>
#include <oxs_token_encrypted_key.h>
#include <oxs_token_x509_data.h>
#include <oxs_token_cipher_value.h>
#include <oxs_token_encryption_method.h>
#include <oxs_token_signature.h>
#include <oxs_token_x509_issuer_name.h>
#include <oxs_token_data_reference.h>
#include <oxs_token_key_identifier.h>
#include <oxs_token_signature_method.h>
#include <oxs_token_x509_issuer_serial.h>
#include <oxs_token_digest_method.h>
#include <oxs_token_key_info.h>
#include <oxs_token_signature_value.h>
#include <oxs_token_x509_serial_number.h>
#include <oxs_token_digest_value.h>
#include <oxs_token_key_name.h>
#include <oxs_token_signed_info.h>
#include <oxs_token_ds_reference.h>
#include <oxs_token_reference.h>
#include <oxs_token_transform.h>




/**
* @file oxs_tokens.h
* @brief includes all tokens of OMXMLSecurity.
*/
#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @defgroup oxs_token OMXMLSecurity Tokens
     * @ingroup oxs
     * @{
     */
    
    /*TODO : We need to import functions in other oxs_token_* headers too here */
    
    /*<wsse11:SignatureConfirmation> element ************************************************/
  
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    oxs_token_get_signature_confirmation_value(const axutil_env_t *env, axiom_node_t *signature_confirmation_node);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    oxs_token_get_signature_confirmation_id(const axutil_env_t *env, axiom_node_t *signature_confirmation_node);

    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_signature_confirmation_element(const axutil_env_t *env,
                                        axiom_node_t *parent,
                                        axis2_char_t *id,
                                        axis2_char_t *val); 
    /** @} */

#ifdef __cplusplus
}
#endif

#endif /*OXS_TOKENS_H */
