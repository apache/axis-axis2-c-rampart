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

#include <rampart_saml.h>
#include <oxs_constants.h>
#include <rp_property.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_supporting_token_build(axutil_env_t *env, 
                         rampart_context_t *rampart_context,                         
                         axiom_node_t *sec_node)
{
    axiom_node_t *strn = NULL, *assertion = NULL;
    rampart_saml_token_t *saml = rampart_context_get_saml_token(rampart_context, env, RP_PROPERTY_SIGNED_SUPPORTING_TOKEN);
    if (!saml)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] SAML token not set in the rampart context. ERROR");			
        return AXIS2_FAILURE;
    }
    assertion = rampart_saml_token_get_assertion(saml, env);
    if (!assertion)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] SAML assertion not set in the rampart_saml_token. ERROR");			
        return AXIS2_FAILURE;
    }
    axiom_node_add_child(sec_node, env, assertion);
    strn = rampart_saml_token_get_str(saml, env);
    if (!strn)
    {
        strn = oxs_saml_token_build_key_identifier_reference_local(env, NULL, assertion);
        rampart_saml_token_set_str(saml, env, strn);
    }
    axiom_node_add_child(sec_node, env, strn);    
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_validate(axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            axiom_node_t *assertion)
{
	/* At the moment SAML validation is not done. But we need to validate the signature of SAML tokens.
	We can look at this after the PKS12 integration*/
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN char * AXIS2_CALL
rampart_saml_token_get_subject_confirmation(axutil_env_t *env, axiom_node_t *assertion)
{
    axiom_node_t *node = oxs_axiom_get_node_by_local_name(env, assertion, OXS_NODE_SAML_SUBJECT_CONFIRMATION_METHOD);
    if (node) 
    {
        return oxs_axiom_get_node_content(env, node);
    }
    return NULL;
}

/** Faults Defined by the specification **/
AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_securitytokenunavailable(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_unsupportedsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}


AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_failedcheck(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_FAILEDCHECK_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_FAILEDCHECK_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_invalidsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}

