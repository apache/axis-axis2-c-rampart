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

#ifndef SAML_REQ_H
#define SAML_REQ_H

#include <saml.h>
#include <oxs_xml_signature.h>
#include <oxs_sign_ctx.h>
#include <oxs_xml_key_processor.h>
#include <oxs_utility.h>
#include <oxs_transforms_factory.h>
#include <oxs_xml_key_info_builder.h>
#include <oxs_key_mgr.h>
#include <oxs_transform.h>
#include <oxs_x509_cert.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SAML_REQUEST_ID        "RequestID"
#define SAML_SIGNATURE        "Signature"
#define SAML_SUBJECT_QUERY    "SubjectQuery"
#define SAML_ATTRIBUTE_QUERY  "AttributeQuery"
#define SAML_AUTHENTICATION_QUERY    "AuthenticationQuery"
#define SAML_AUTHORIZATION_DECISION_QUERY    "AuthorizationDecisionQuery"
#define SAML_ASSERTION_ID_REF        "AssertionIDReference"
#define SAML_ASSERTION_ARTIFACT    "AssertionArtifact"
#define SAML_RESPOND_WITH            "RespondWith"
#define SAML_ATTRIBUTE_DESIGNATOR        "AttributeDesignator"
#define SAML_RESPONSE_ID            "ResponceID"
#define SAML_IN_RESPONSE_TO        "InResponseTo"
#define SAML_RECEPIENT            "Recipient"
#define SAML_STATUS_CODE            "StatusCode"
#define SAML_STATUS_MESSAGE            "StatusMessage"
#define SAML_STATUS_DETAIL        "StatusDetail"
#define SAML_STATUS_VALUE        "Value"
#define SAML_STATUS                "Status"
#define SAML_PROTOCOL_NMSP			"urn:oasis:names:tc:SAML:1.0:protocol"
#define SAML_PROTOCOL_PREFIX		"samlp"
#define SAML_REQUEST				"Request"
#define SAML_RESPONSE				"Response"

/*A code representing the status of the corresponding request*/

typedef struct saml_artifact
{
	axis2_char_t *artifact;
}saml_artifact_t;

typedef struct saml_status
{
    axutil_qname_t *status_value;
    axis2_char_t *status_code;
    axis2_char_t *status_msg;
    axiom_node_t *status_detail;

}saml_status_t;


typedef struct saml_query
{
	axis2_char_t *type;
	void *query;
}saml_query_t;

typedef struct saml_subject_query
{
    saml_subject_t *subject;
}saml_subject_query_t;

typedef struct saml_authentication_query
{
    saml_subject_t *subject;
    /* A URI reference that specifies the type of authentication that took place */
    axis2_char_t *auth_method;

}saml_authentication_query_t;

typedef struct saml_attr_query
{
    saml_subject_t *subject;
    axis2_char_t *resource;
    axutil_array_list_t *attr_desigs;
}saml_attr_query_t;

typedef struct saml_autho_decision_query
{
    saml_subject_t *subject;
    axis2_char_t *resource;
    /* One or more saml actions*/
    axutil_array_list_t *saml_actions;
    saml_evidence_t *evidence;

}saml_autho_decision_query_t;

typedef struct saml_request
{
    axis2_char_t *request_id;

    /* majod version */
    axis2_char_t *major_version;

    /* minor version */
    axis2_char_t *minor_version;

    /* time instant of the issue */
    axutil_date_time_t *issue_instant;

    /*optional*/
    oxs_sign_ctx_t *sig_ctx;

    /* An array for QNames	
	 * specifies the type of statement the SAML relying party wants from the
	 * SAML authority*
	 */
    axutil_array_list_t *saml_responds;

    /*To request assrtions by means of ID one or more*/
    axutil_array_list_t *saml_asserion_id_ref;
    
    axutil_array_list_t *saml_artifacts;
	
	saml_query_t *query;

	axiom_node_t *original_xml;

	axiom_node_t *signature;
}saml_request_t;

typedef struct saml_response
{
    axis2_char_t *response_id;

    axis2_char_t *major_version;

    axis2_char_t *minor_version;
    
    axis2_char_t *recepient;

    axis2_char_t  *request_response_id;

    axutil_date_time_t *issue_instant;

    oxs_sign_ctx_t *sig_ctx;
    saml_status_t *status;

    axutil_array_list_t *saml_assertions;

	axiom_node_t *original_xml;
	axiom_node_t *signature;
}saml_response_t;

AXIS2_EXTERN saml_request_t* AXIS2_CALL 
saml_request_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_request_free(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_build(saml_request_t *request, axiom_node_t *node, 
				   axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_request_to_om(saml_request_t *request, axiom_node_t *parent, 
				   axutil_env_t *env); 

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_request_get_id(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_signature(saml_request_t *request, axutil_env_t *env, 
						   oxs_sign_ctx_t *sig_ctx);

AXIS2_EXTERN void AXIS2_CALL 
saml_request_set_default_signature(saml_request_t *request, axutil_env_t *env, 
								   oxs_sign_ctx_t *sig_ctx);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_unset_signature(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_sign(saml_request_t *request, axiom_node_t **node, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_minor_version(saml_request_t *request, int version, 
							   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_major_version(saml_request_t *request, 
							   int version, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_issue_instant(saml_request_t *request, 
							   axutil_date_time_t *date_time, axutil_env_t *ev);

AXIS2_EXTERN axutil_date_time_t* AXIS2_CALL 
saml_request_get_issue_instant(saml_request_t *request, axutil_env_t *ev);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_respond_withs(saml_request_t *request, 
							   axutil_array_list_t *responds, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_request_get_respond_withs(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_respond_with(saml_request_t *request, axutil_qname_t *respond, 
							  axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_respond_with(saml_request_t *request, int index, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_query(saml_request_t *request, saml_query_t *query, axutil_env_t *env);

AXIS2_EXTERN saml_query_t* AXIS2_CALL 
saml_request_get_query(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_id_refs(saml_request_t *request, axutil_array_list_t *id_refs, 
						 axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_request_get_id_refs(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_id_refs(saml_request_t *request, axis2_char_t *id_reference, 
						 axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_id_refs(saml_request_t *request, 
							int index, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_set_artifacts(saml_request_t *request, 
						   axutil_array_list_t *artifacts, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t*  AXIS2_CALL 
saml_request_get_artifacts(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_add_artifact(saml_request_t *request, saml_artifact_t *artifact, 
						  axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_request_remove_artifact(saml_request_t *request, int index, 
							 axutil_env_t *env);

AXIS2_EXTERN axis2_bool_t AXIS2_CALL 
saml_request_check_validity(saml_request_t *request, axutil_env_t *env);

AXIS2_EXTERN saml_response_t* saml_response_create(axutil_env_t *env);

AXIS2_EXTERN void saml_response_free(saml_response_t *response, 
									 axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_build(saml_response_t *response, axiom_node_t *node, 
					axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_response_to_om(saml_response_t *response, axiom_node_t *parent, 
					axutil_env_t *env);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_response_get_id(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_signature(saml_response_t *response, 
							axutil_env_t *env, oxs_sign_ctx_t *sig_ctx);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_unset_signature(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_sign(saml_response_t *response, axiom_node_t *node, 
				   axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_response_set_default_signature(saml_response_t *response, 
									axutil_env_t *env, oxs_sign_ctx_t *sig_ctx);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_minor_version(saml_response_t *response, 
								int version, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_major_version(saml_response_t *response, 
								int version, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_issue_instant(saml_response_t *response, 
								axutil_date_time_t *date_time, axutil_env_t *ev);

AXIS2_EXTERN  axutil_date_time_t* AXIS2_CALL 
saml_response_get_issue_instant(saml_response_t *response, axutil_env_t *ev);


AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_recepient(saml_response_t *response, axis2_char_t *recepient, 
							axutil_env_t *env);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_response_get_recepient(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_status(saml_response_t *response, saml_status_t *status, 
						 axutil_env_t *env);

AXIS2_EXTERN saml_status_t* AXIS2_CALL 
saml_response_get_status(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_assertions(saml_response_t *response, 
							 axutil_array_list_t *assertions, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_response_get_assertions(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_add_assertion(saml_response_t *response, saml_assertion_t *assertion, 
							axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_remove_assertion(saml_response_t *response, int index, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_response_set_in_reponses_to(saml_response_t *response, 
								 axis2_char_t *request_response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_query_build(saml_query_t *query, axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN saml_query_t* AXIS2_CALL 
saml_query_create(axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_query_to_om(saml_query_t *query, axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_query_free(saml_query_t *query, axutil_env_t *env);

AXIS2_EXTERN saml_subject_query_t* AXIS2_CALL 
saml_subject_query_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_query_free(saml_subject_query_t* subject_query, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_query_build(saml_subject_query_t* subject_query, 
						 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_subject_query_to_om(saml_subject_query_t *subject_query, 
						 axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_authentication_query_t* AXIS2_CALL 
saml_authentication_query_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_authentication_query_free(saml_authentication_query_t *authentication_query, 
							   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_authentication_query_build(saml_authentication_query_t* authentication_query, 
								axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_authentication_query_to_om(saml_authentication_query_t *authentication_query, 
								axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_query_set_authentication_method(
	saml_authentication_query_t *authentication_query,
	axis2_char_t *authentication_mtd,
	axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_query_get_authentication_method(
	saml_authentication_query_t *authentication_query,
	axutil_env_t *env);

AXIS2_EXTERN saml_attr_query_t* AXIS2_CALL 
saml_attr_query_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL
saml_attr_query_free(saml_attr_query_t* attribute_query, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_build(saml_attr_query_t* attribute_query, 
					  axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_attr_query_to_om(saml_attr_query_t *attribute_query, 
					  axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_subject_t* AXIS2_CALL 
saml_query_get_subject(saml_query_t* query,
						axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_subject(saml_query_t *query, saml_subject_t *subject,
					   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_type(saml_query_t *query, axis2_char_t *type,
					axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_query_set_query(saml_query_t *query, void *spec_query, 
					 axis2_char_t *type, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_set_resource(saml_attr_query_t *attr_query, 
							 axutil_env_t *env, axis2_char_t *resource);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_attr_query_get_resource(saml_attr_query_t *attr_query, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_set_designators(saml_attr_query_t *attr_query, 
								axutil_array_list_t *saml_designators, 
								axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_attr_query_get_designators(saml_attr_query_t *attr_query, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_add_designators(saml_attr_query_t *attr_query, 
								saml_attr_desig_t *desig, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_query_remove_designator(saml_attr_query_t *attr_query, 
								  int index, axutil_env_t *env);


AXIS2_EXTERN saml_autho_decision_query_t* AXIS2_CALL 
saml_autho_decision_query_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_autho_decision_query_free(saml_autho_decision_query_t* autho_decision_query, 
							   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_build(saml_autho_decision_query_t* autho_decision_query, 
								axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_autho_decision_query_to_om(saml_autho_decision_query_t *autho_decision_query, 
								axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_resource(
			saml_autho_decision_query_t *autho_dec_query,
			axis2_char_t *resource,
			axutil_env_t *env);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_autho_decision_query_get_resource(saml_autho_decision_query_t *autho_dec_query,
														 axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_actions(
			saml_autho_decision_query_t *autho_dec_query,
			axutil_array_list_t *actions,
			axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL 
saml_autho_decision_query_get_actions(
			saml_autho_decision_query_t *autho_dec_query,
			axutil_env_t *env);
														

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_add_action(
			saml_autho_decision_query_t *autho_dec_query,
			saml_action_t *action,
			axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_remove_action(saml_autho_decision_query_t *autho_dec_query,
													int index,
													axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_autho_decision_query_set_evidence(
			saml_autho_decision_query_t *autho_dec_query,
			saml_evidence_t *evidence,
			axutil_env_t *env);

AXIS2_EXTERN saml_evidence_t* AXIS2_CALL 
saml_autho_decision_query_get_evidence(
			saml_autho_decision_query_t *autho_dec_query,
			axutil_env_t *env);
														
AXIS2_EXTERN int AXIS2_CALL 
saml_status_build(saml_status_t *status, axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN saml_status_t* AXIS2_CALL 
saml_status_create(axutil_env_t *env);

AXIS2_EXTERN void 
saml_status_free(saml_status_t *status, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_value(saml_status_t *status, 
							 axutil_qname_t *qname, axutil_env_t *env);

AXIS2_EXTERN axutil_qname_t* AXIS2_CALL 
saml_status_get_status_value(saml_status_t *status, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_msg(saml_status_t *status, axis2_char_t *msg, 
						   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_code(saml_status_t *status, axis2_char_t *code, 
							axutil_env_t *env);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_status_get_status_msg(saml_status_t *status, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_status_set_status_detail(saml_status_t *status, axiom_node_t *det, 
							  axutil_env_t *env);

AXIS2_EXTERN axiom_node_t* AXIS2_CALL 
saml_status_get_status_detail(saml_status_t *status, axutil_env_t *env);

AXIS2_EXTERN saml_artifact_t* AXIS2_CALL 
saml_artifact_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_artifact_free(saml_artifact_t *artifact, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL 
saml_artifact_get_data(saml_artifact_t *artifact, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_artifact_set_data(saml_artifact_t *artifact, axutil_env_t *env, 
					   axis2_char_t *data);

AXIS2_EXTERN int AXIS2_CALL
saml_response_signature_verify(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_response_is_sign_set(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_response_is_signed(saml_response_t *response, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_request_signature_verify(saml_request_t *request, axutil_env_t *env);
AXIS2_EXTERN int AXIS2_CALL
saml_request_is_sign_set(saml_request_t *request, axutil_env_t *env);
AXIS2_EXTERN int AXIS2_CALL
saml_request_is_signed(saml_request_t *request, axutil_env_t *env);

#ifdef __cplusplus
}
#endif

#endif 

