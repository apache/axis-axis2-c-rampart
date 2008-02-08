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

#include <axutil_utils_defines.h>
#include <axis2_defines.h>
#include <axutil_env.h>
#include <axiom_soap.h>
#include <axis2_msg_ctx.h>
#include <oxs_asym_ctx.h>
#include <oxs_xml_encryption.h>
#include <rampart_context.h>
#include <axutil_utils.h>
#include <axiom.h>

/**
  * @file rampart_saml.h
  * @brief build saml tokens and validate saml tokens 
  */


#ifndef RAMPART_SAML_H
#define RAMPART_SAML_H

#ifdef __cplusplus
extern "C" {
#endif

#define RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_STR   "A referenced SAML assertion could not be retrieved."
#define RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_STR   "An assertion contains a <saml:condition> element that the receive does not understand."
#define RAMPART_ST_FAULT_FAILEDCHECK_STR                "A signature withing an assertion or referencing an assertion is invalid."
#define RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_STR       "The issuer of an assertion is not acceptable to the receiver."                

#define RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_CODE  "wsse:SecurityTokenUnavailable"
#define RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_CODE  "wsse:UnsupportedSecurityToken"
#define RAMPART_ST_FAULT_FAILEDCHECK_CODE               "wsse:FailedCheck"
#define RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_CODE      "wsse:InvalidSecurityToken"                

#define RAMPART_SAML_FAULT_CODE                         "env:Sender"

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_supporting_token_build(const axutil_env_t *env, 
                         rampart_context_t *rampart_context,                         
                         axiom_node_t *sec_node);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_validate(axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            axiom_node_t *assertion);

AXIS2_EXTERN char * AXIS2_CALL
rampart_saml_token_get_subject_confirmation(const axutil_env_t *env, 
                                            axiom_node_t *assertion);

/* SAML token proccessing faults */
AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_securitytokenunavailable(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_unsupportedsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_failedcheck(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx);

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_invalidsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx);


#ifdef __cplusplus
}
#endif

#endif    