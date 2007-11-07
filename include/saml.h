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
#ifndef SAML_H
#define SAML_H

#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <axutil_hash.h>
#include <axutil_date_time.h>
#include <axiom.h>
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


#define SAML_VERSION_MAX    16
#define SAML_URI_LEN_MAX    2048
#define SAML_ARRAY_LIST_DEF    4

#define SAML_PREFIX							"saml"
#define SAML_NMSP_URI						"urn:oasis:names:tc:SAML:1.0:assertion"
#define SAML_XML_TYPE						"type"
#define SAML_XSI_NS							"http://www.w3.org/2001/XMLSchema-instance"
#define SAML_XSI							"xsi"

#define SAML_MAJORVERSION					"MajorVersion"
#define SAML_MINORVERSION					"MinorVersion"
#define SAML_ASSERTION_ID					"AssertionID"
#define SAML_ISSUER							"Issuer"
#define SAML_ISSUE_INSTANT					"IssueInstant"
#define SAML_STATEMENT						"Statement"
#define SAML_SUBJECT_STATEMENT				"SubjectStatement"
#define SAML_AUTHENTICATION_STATEMENT		"AuthenticationStatement"
#define SAML_AUTHORIZATION_DECISION_STATEMENT "AuthorizationDecisionStatement"
#define SAML_ATTRIBUTE_STATEMENT			"AttributeStatement"
#define SAML_CONDITIONS						"Conditions"
#define SAML_ADVICE							"Advice"
#define SAML_NOT_BEFORE						"NotBefore"
#define SAML_NOT_ON_OR_AFTER                "NotOnOrAfter"
#define SAML_SIGNATURE						"Signature"

#define SAML_EMAIL_ADDRESS					"#emailAddress"
#define SAML_X509_SUBJECT_NAME				"#X509SubjectName"
#define SAML_WINDOWS_DOMAIN_QUALIFIED_NAME  "#WindowsDomainQualifiedName"

#define SAML_NAME_QUALIFIER					"NameQualifier"
#define SAML_FORMAT							"Format"
#define SAML_NAME_IDENTIFIER                "NameIdentifier"
#define SAML_SUBJECT_CONFIRMATION			"SubjectConfirmation"
#define SAML_CONFIRMATION_METHOD            "ConfirmationMethod"
#define SAML_SUBJECT_CONFIRMATION_DATA		"SubjectConfirmationData"
#define SAML_KEY_INFO						"KeyInfo"
#define SAML_SUBJECT						"Subject"

#define SAML_AUDIENCE						"Audience"
#define SAML_AUDIENCE_RESTRICTION_CONDITION_TYPE "AudienceRestrictionConditionType" 
#define SAML_AUDIENCE_RESTRICTION_CONDITION "AudienceRestrictionCondition"

#define SAML_AUTHENTICATION_METHOD			"AuthenticationMethod"
#define SAML_AUTHENTICATION_INSTANT			"AuthenticationInstant"
#define SAML_IP_ADDRESS						"IPAddress" 
#define SAML_DNS_ADDRESS                    "DNSAddress"
#define SAML_SUBJECT_LOCALITY                "SubjectLocality"
#define SAML_AUTHORITY_BINDING				"AuthorityBinding"
#define SAML_AUTHORITY_KIND					"AuthorityKind"
#define SAML_LOCATION						"Location"
#define SAML_BINDING						"Binding"

#define SAML_RESOURCE						"Resource"
#define SAML_DECISION						"Decision"    
#define SAML_ACTION							"Action"
#define SAML_NAMESPACE						"Namespace"
#define SAML_ASSERTION_ID_REFERENCE			"AssertionIDReference" 
#define SAML_ASSERTION						"Assertion"    
#define SAML_ACTION							"Action"
#define SAML_EVIDENCE						"Evidence"

#define SAML_ATTRIBUTE_NAME					"AttributeName"
#define SAML_ATTRIBUTE_NAMESPACE            "AttributeNamespace"
#define SAML_ATTRIBUTE_VALUE                "AttributeValue"
#define SAML_ATTRIBUTE						"Attribute"
#define SAML_ATTRIBUTE_DESIGNATOR			"AttributeDesignator"

#define SAML_SUB_CONFIRMATION_HOLDER_OF_KEY	"urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
#define SAML_SUB_CONFIRMATION_SENDER_VOUCHES	"urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"
#define SAML_SUB_CONFIRMATION_ARTIFACT		"urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
#define SAML_SUB_CONFIRMATION_BEARER		"urn:oasis:names:tc:SAML:1.0:cm:bearer"

#define SAML_AUTH_METHOD_URI_PASSWORD		"urn:oasis:names:tc:SAML:1.0:am:password"
#define SAML_AUTH_METHOD_URI_KERBEROS		"urn:ietf:rfc:1510"
#define SAML_AUTH_METHOD_URI_SRP			"urn:ietf:rfc:2945"
#define SAML_AUTH_METHOD_URI_HARDWARE_TOKEN	"urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define SAML_AUTH_METHOD_URI_SSL_TLS		"urn:ietf:rfc:2246"
#define SAML_AUTH_METHOD_URI_X509			"urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define SAML_AUTH_METHOD_URI_PGP			"urn:oasis:names:tc:SAML:1.0:am:PGP"
#define SAML_AUTH_METHOD_URI_SPKI			"urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define SAML_AUTH_METHOD_URI_XKMS			"urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define SAML_AUTH_METHOD_URI_XML_DS			"urn:ietf:rfc:3075"
#define SAML_AUTH_METHOD_URI_UNSPECIFIED	"urn:oasis:names:tc:SAML:1.0:am:unspecified"

#define SAML_ACTION_URI_RWEDC_N				"urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"
#define SAML_ACTION_URI_RWEDC				"urn:oasis:names:tc:SAML:1.0:action:rwedc"

#define SAML_ACTION_READ					"Read"
#define SAML_ACTION_WRITE					"Write"
#define SAML_ACTION_EXECUTE					"Execute"
#define SAML_ACTION_DELETE					"Delete"
#define SAML_ACTION_CONTROL					"Control"
#define SAML_ACTION_READ_N					"~Read"
#define SAML_ACTION_WRITE_N					"~Write"
#define SAML_ACTION_EXECUTE_N				"~Execute"
#define SAML_ACTION_DELETE_N				"~Delete"
#define SAML_ACTION_CONTROL_N				"~Control"

#define SAML_MAJOR_VERSION					"1"

typedef struct saml_assertion_s saml_assertion_t;

#ifndef SAML_DECLARE
#define SAML_DECLARE(type)	AXIS2_EXTERN type AXIS2_CALL
#endif

typedef enum deciosion_type
{
    PERMIT = 0,
    DENY,
    INDETERMINATE
} deciosion_type_t;

typedef enum
{
    SAML_COND_UNSPECFIED = 0,
    SAML_COND_AUDI_RESTRICTION 
} saml_cond_type_t; 

typedef struct condition_s 
{
    saml_cond_type_t type;
    void *cond;
} saml_condition_t;

typedef struct saml_audi_restriction_cond_s
{
    axutil_array_list_t *audiences;	
} saml_audi_restriction_cond_t;

typedef struct saml_advise_s
{
    int a;
} saml_advise_t;

typedef enum
{
    SAML_STMT_UNSPECIFED = 0,
    SAML_STMT_SUBJECTSTATEMENT,
    SAML_STMT_AUTHENTICATIONSTATEMENT,
    SAML_STMT_AUTHORIZATIONDECISIONSTATEMENT,
    SAML_STMT_ATTRIBUTESTATEMENT
} saml_stmt_type_t;

typedef struct
{
    saml_stmt_type_t type;
    void *stmt;
} saml_stmt_t;

typedef struct saml_named_id_s
{
    /* The security or administrative domain that qualifies the name of 
     * the subject 
     */
    axis2_char_t *name_qualifier;

    /* The syntax used to describe the name of the subject */
    axis2_char_t *format;

    axis2_char_t *name;
} saml_named_id_t;


typedef struct saml_subject_s
{
    saml_named_id_t *named_id;
    
    /* URI reference that identifies a protocol to be used to authenticate 
     * the subject 
     */
    axutil_array_list_t *confirmation_methods;

    /* An XML Signature element that specifies a cryptographic key held by 
     * the subject 
     */
    axiom_node_t *key_info;

    /* Additional authentication information to be used by a specific 
     * authentication protocol 
     */
    axiom_node_t *confirmation_data;    
} saml_subject_t;

typedef struct saml_subject_stmt_s
{
    saml_subject_t *subject;
} saml_subject_stmt_t;

typedef struct saml_action
{
    /* URI for the specified action to be performed */
    char *name_space;

    /* An action to be performed on the data */
    char *data;
} saml_action_t;


typedef struct saml_evidence_s
{
    /* Specifies an assertion by reference to the value of the assertion’s 
     * AssertionID attribute 
     */
    axutil_array_list_t *assertion_ids;

    /* Specifies an assertion by value */
    axutil_array_list_t *assertions;
} saml_evidence_t;


typedef struct saml_subject_locality
{
    /* The IP address of the system entity that was authenticated */
    axis2_char_t *ip;

    /* The DNS address of the system entity that was authenticated */
    axis2_char_t *dns;
} saml_subject_locality_t;


typedef struct saml_auth_binding
{
    /* The type of SAML Protocol queries to which the authority described 
     * by this element will respond 
     */
    axis2_char_t *auth_kind;

    /* A URI reference describing how to locate and communicate with the 
     * authority 
     */
    axis2_char_t *location;

    /* A URI reference identifying the SAML protocol binding to use 
     * in communicating with the authority 
     */
    axis2_char_t *binding;
} saml_auth_binding_t;

typedef struct saml_auth_stmt
{
	saml_subject_t *subject;

    /* A URI reference that specifies the type of authentication that took place */
    axis2_char_t *auth_method;
    
    /* Specifies the time at which the authentication took place */
    axutil_date_time_t *auth_instanse;

    /* 
     * Specifies the DNS domain name and IP address for the system entity from which the Subject was
     * apparently authenticated 
     */
    /*saml_subject_locality_t *sub_locality;*/
	axis2_char_t *ip;
	
	axis2_char_t *dns;

    /* Indicates that additional information about the subject of the statement may be available */
    axutil_array_list_t *auth_binding;

} saml_auth_stmt_t;

typedef struct saml_auth_desicion_stmt
{
    saml_subject_t *subject;
    /* A URI reference identifying the resource to which access authorization */
    char *resource;

    /* The decision rendered by the issuer with respect to the specified resource */
    char *decision;

    /* The set of actions authorized to be performed on the specified resource */
    axutil_array_list_t *action;

    /* A set of assertions that the issuer relied on in making the decision */
    saml_evidence_t *evidence;
} saml_auth_desicion_stmt_t;

typedef struct saml_attr_s 
{
    /* The name of the attribute */
    char *attr_name;

    /* The namespace in which the AttributeName elements are interpreted */
    char *attr_nmsp;

    axutil_array_list_t *attr_value;
} saml_attr_t;


typedef struct saml_attr_stmt_s 
{
    saml_subject_t *subject;
    /* An attribute */
    axutil_array_list_t *attribute;
} saml_attr_stmt_t;

typedef struct saml_attr_desig_s
{
    axis2_char_t *attr_name;
    axis2_char_t *attr_nmsp;
} saml_attr_desig_t;

struct saml_assertion_s
{
    /* majod version */
    axis2_char_t *major_version;

    /* minor version */
    axis2_char_t *minor_version;

    /* id */
    axis2_char_t *assertion_id;

    /* uri representing the issuer */
    axis2_char_t *issuer;

    /* time instant of the issue */
    axutil_date_time_t *issue_instant;

    axutil_date_time_t *not_before;    

    axutil_date_time_t *not_on_or_after;

    /* SAML condition */
    axutil_array_list_t *conditions;

    /* An XML Signature that authenticates the assertion */
    axiom_node_t *signature;

	axutil_array_list_t *statements;

	oxs_sign_ctx_t *sign_ctx;

	axiom_node_t *ori_xml;	
};

/* assertion */
AXIS2_EXTERN saml_assertion_t *AXIS2_CALL 
saml_assertion_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_assertion_free(saml_assertion_t *assertion, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_build(saml_assertion_t *assertion, 
					 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_assertion_to_om(saml_assertion_t *assertion, 
					 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assetion_get_conditions(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_assertion_get_statements(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_conditions(saml_assertion_t *a, 
							  axutil_env_t *env, axutil_array_list_t *list);
AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_condition(saml_assertion_t *a, 
							 axutil_env_t *env, saml_condition_t *cond);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_condition(saml_assertion_t *a, 
								axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_statements(saml_assertion_t *a, 
							  axutil_env_t *env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_add_statement(saml_assertion_t *a, 
							 axutil_env_t *env, saml_stmt_t *stmt);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_remove_statement(saml_assertion_t *a, 
								axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_minor_version(saml_assertion_t *a, 
								 axutil_env_t *env, int version);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issuer(saml_assertion_t *a, 
						  axutil_env_t *env, axis2_char_t *issuer);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_issue_instant(saml_assertion_t *a, 
								 axutil_env_t *env, axutil_date_time_t *instant);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_before(saml_assertion_t *a, 
							  axutil_env_t *env, axutil_date_time_t *time);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_not_on_or_after(saml_assertion_t *a, 
								   axutil_env_t *env, axutil_date_time_t *time);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_assertion_get_issuer(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_issue_instant(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_before(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_assertion_get_not_on_or_after(saml_assertion_t *a, axutil_env_t *env);

/* sign methods */
AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_signed(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_is_sign_set(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_signature_verify(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL
saml_assertion_sign(saml_assertion_t *a, axutil_env_t *env, 
					oxs_sign_ctx_t *sign_ctx, axiom_node_t **node);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_unsign(saml_assertion_t *a, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_assertion_set_default_signature(saml_assertion_t *a, 
					axutil_env_t *env, oxs_sign_ctx_t *sign_ctx);


/* statement */
AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_stmt_free(saml_stmt_t *stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_build(saml_stmt_t *stmt, axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_stmt_to_om(saml_stmt_t *stmt, axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_stmt_type_t AXIS2_CALL 
saml_stmt_get_type(saml_stmt_t *stmt, axutil_env_t *env);

AXIS2_EXTERN saml_stmt_t * AXIS2_CALL 
saml_stmt_get_stmt(saml_stmt_t *stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_type(saml_stmt_t *stmt, axutil_env_t *env, saml_stmt_type_t type);

AXIS2_EXTERN int AXIS2_CALL 
saml_stmt_set_stmt(saml_stmt_t *stmt, axutil_env_t *env, 
				   void *st, saml_stmt_type_t type);



/*AXIS2_EXTERN int AXIS2_CALL saml_id_init(saml_id_t *id, axutil_env_t *env);*/
AXIS2_EXTERN axis2_char_t * AXIS2_CALL saml_id_generate_random_bytes(axutil_env_t *env);
/*AXIS2_EXTERN void AXIS2_CALL saml_id_uninit(saml_id_t *id, axutil_env_t *env);*/

/* auth binding */
AXIS2_EXTERN saml_auth_binding_t * AXIS2_CALL 
saml_auth_binding_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_auth_binding_free(saml_auth_binding_t *auth_bind, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_build(saml_auth_binding_t *auth_bind, 
						axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_auth_binding_to_om(saml_auth_binding_t *auth_binding, 
						axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_authoity_kind(saml_auth_binding_t *auth_binding, 
									axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_binding(saml_auth_binding_t *auth_binding, 
							  axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_binding_get_location(saml_auth_binding_t *auth_binding, 
							   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_authority_kind(saml_auth_binding_t *auth_binding, 
									 axutil_env_t *env, axis2_char_t *auth_kind);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_binding(saml_auth_binding_t *auth_binding, 
							  axutil_env_t *env, axis2_char_t *binding);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_binding_set_location(saml_auth_binding_t *auth_binding, 
							   axutil_env_t *env, axis2_char_t *location);


/* subject locality */
AXIS2_EXTERN saml_subject_locality_t * AXIS2_CALL 
saml_subject_locality_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_locality_free(saml_subject_locality_t *sub_locality, 
						   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_build(saml_subject_locality_t *sub_locality, 
							axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_subject_locality_to_om(saml_subject_locality_t *sub_locality, 
							axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_subject_locality_get_ip(saml_subject_locality_t *sub_locality, 
							 axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_subject_locality_get_dns(saml_subject_locality_t *sub_locality, 
							  axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_set_ip(saml_subject_locality_t *sub_locality, 
							 axutil_env_t *env, axis2_char_t *ip);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_locality_set_dns(saml_subject_locality_t *sub_locality, 
							  axutil_env_t *env, axis2_char_t *dns);


/* subject */
AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_free(saml_subject_t *subject, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_build(saml_subject_t *subject, 
				   axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_to_om(saml_subject_t *subject, 
				   axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_subject_get_named_id(saml_subject_t *subject, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_subject_get_confirmation_methods(saml_subject_t *subject, 
									  axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_confirmation_data(saml_subject_t *subject, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_get_key_info(saml_subject_t *subject, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_named_id(saml_subject_t *subject, 
						  axutil_env_t *env, saml_named_id_t *named_id);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_confirmation_methods(saml_subject_t *subject, 
									  axutil_env_t *env, 
									  axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_add_confirmation(saml_subject_t *subject, 
							  axutil_env_t *env, 
							  axis2_char_t *sub_confirmation);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_remove_subject_confiirmation(saml_subject_t *subject, 
										  axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_set_key_info(saml_subject_t *subject, 
						  axutil_env_t *env, axiom_node_t *node);

/* subject statement */
AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_build(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_subject_stmt_free(saml_subject_stmt_t *subject_stmt, 
					   axutil_env_t *env);

AXIS2_EXTERN saml_subject_stmt_t * AXIS2_CALL 
saml_subject_stmt_create(axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_subject_stmt_to_om(saml_subject_stmt_t *subject_stmt, 
						axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_subject_stmt_set_subject(saml_subject_stmt_t *subject_stmt, 
							  axutil_env_t *env, saml_subject_t *subject);

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_subject_stmt_get_subject(saml_subject_stmt_t *subject_stmt, 
							  axutil_env_t *env);

/* auth desicin statement */
AXIS2_EXTERN saml_auth_desicion_stmt_t * AXIS2_CALL 
saml_auth_desicion_stmt_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_auth_desicion_stmt_free(saml_auth_desicion_stmt_t *auth_des_stmt, 
							 axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_build(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_auth_desicion_stmt_to_om(saml_auth_desicion_stmt_t *auth_des_stmt, 
							  axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_subject(saml_auth_desicion_stmt_t *auth_des_stmt, 
									axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									axutil_env_t *env);

AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_auth_desicion_stmt_get_evidence(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_resource(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 axutil_env_t *env, axis2_char_t *resource);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_desicion(saml_auth_desicion_stmt_t *auth_des_stmt, 
									 axutil_env_t *env, axis2_char_t *desicion);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_actions(saml_auth_desicion_stmt_t *auth_des_stmt, 
									axutil_env_t * env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_remove_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
									  axutil_env_t * env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_add_action(saml_auth_desicion_stmt_t *auth_des_stmt, 
								   axutil_env_t * env, saml_action_t *action);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_desicion_stmt_set_subject(saml_auth_desicion_stmt_t *auth_des_stmt, 
									axutil_env_t * env, saml_subject_t *subject);

/* auth statement */
AXIS2_EXTERN saml_auth_stmt_t * AXIS2_CALL 
saml_auth_stmt_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_auth_stmt_free(saml_auth_stmt_t *auth_stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_build(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_auth_stmt_to_om(saml_auth_stmt_t *auth_stmt, 
					 axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_auth_method(saml_auth_stmt_t *auth_stmt, 
							   axutil_env_t *env);

AXIS2_EXTERN axutil_date_time_t * AXIS2_CALL 
saml_auth_stmt_get_auth_instant(saml_auth_stmt_t *auth_stmt, 
								axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_auth_stmt_get_auth_bindings(saml_auth_stmt_t *auth_stmt, 
								 axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_ip(saml_auth_stmt_t *auth_stmt, 
							  axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_auth_stmt_get_subject_dns(saml_auth_stmt_t *auth_stmt, 
							   axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject(saml_auth_stmt_t *auth_stmt, 
						   axutil_env_t *env, saml_subject_t *subject);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_method(saml_auth_stmt_t *auth_stmt, 
							   axutil_env_t *env, axis2_char_t *method);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_instant(saml_auth_stmt_t *auth_stmt, 
								axutil_env_t *env, axutil_date_time_t *dt);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_auth_bindings(saml_auth_stmt_t *auth_stmt, 
								 axutil_env_t *env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_add_auth_binding(saml_auth_stmt_t *auth_stmt, 
								axutil_env_t *env, saml_auth_binding_t *bind);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_remove_auth_binding(saml_auth_stmt_t *auth_stmt, 
								   axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_dns(saml_auth_stmt_t *auth_stmt, 
							   axutil_env_t *env, axis2_char_t *dns);

AXIS2_EXTERN int AXIS2_CALL 
saml_auth_stmt_set_subject_ip(saml_auth_stmt_t *auth_stmt, 
							  axutil_env_t *env, axis2_char_t *ip);

/* attribute statement */
AXIS2_EXTERN saml_attr_stmt_t * AXIS2_CALL 
saml_attr_stmt_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_stmt_free(saml_attr_stmt_t *attr_stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_build(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_stmt_to_om(saml_attr_stmt_t *attr_stmt, 
					 axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN saml_subject_t * AXIS2_CALL 
saml_attr_stmt_get_subject(saml_attr_stmt_t *attr_stmt, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_attr_stmt_get_attributes(saml_attr_stmt_t *attr_stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_subject(saml_attr_stmt_t *attr_stmt, 
						   axutil_env_t *env, saml_subject_t *subject);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_set_attributes(saml_attr_stmt_t *attr_stmt, 
							  axutil_env_t *env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_add_attribute(saml_attr_stmt_t *attr_stmt, 
							 axutil_env_t *env, saml_attr_t *attribute);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_stmt_remove_attribute(saml_attr_stmt_t *attr_stmt, 
								axutil_env_t *env, int index);

/* condition */
AXIS2_EXTERN saml_condition_t * AXIS2_CALL 
saml_condition_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_condition_free(saml_condition_t *cond, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_build(saml_condition_t *cond, 
					 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_condition_to_om(saml_condition_t *cond, 
					 axiom_node_t *parent, axutil_env_t * env);

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_condition(saml_condition_t *cond, 
							 axutil_env_t *env, void * condition, 
							 saml_cond_type_t type);

AXIS2_EXTERN int AXIS2_CALL 
saml_condition_set_type(saml_condition_t *cond, 
						axutil_env_t *env, saml_cond_type_t type);

AXIS2_EXTERN void * AXIS2_CALL 
saml_condition_get_condition(saml_condition_t *cond, axutil_env_t *env);

AXIS2_EXTERN saml_cond_type_t AXIS2_CALL 
saml_condition_get_type(saml_condition_t *cond, axutil_env_t *env);

/* audio restriction */
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_build(saml_audi_restriction_cond_t *arc, 
								 axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t *AXIS2_CALL 
saml_audi_restriction_cond_to_om(saml_audi_restriction_cond_t *cond, 
								 axiom_node_t *parent, axutil_env_t * env);

AXIS2_EXTERN void AXIS2_CALL 
saml_audi_restriction_cond_free(saml_audi_restriction_cond_t *arc, 
								axutil_env_t * env);

AXIS2_EXTERN saml_audi_restriction_cond_t * AXIS2_CALL 
saml_audi_restriction_cond_create(axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_audi_restriction_cond_get_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_set_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_remove_audiences(saml_audi_restriction_cond_t *cond, 
											axutil_env_t * env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_add_audience(saml_audi_restriction_cond_t *cond, 
										axutil_env_t * env, axis2_char_t *audience);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_audi_restriction_cond_get_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_set_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_remove_audiences(saml_audi_restriction_cond_t *cond, 
											axutil_env_t * env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_add_audience(saml_audi_restriction_cond_t *cond, 
										axutil_env_t * env, axis2_char_t *audience);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_audi_restriction_cond_get_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_set_audiences(saml_audi_restriction_cond_t *cond, 
										 axutil_env_t * env, 
										 axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_remove_audiences(saml_audi_restriction_cond_t *cond, 
											axutil_env_t * env, int index);
AXIS2_EXTERN int AXIS2_CALL 
saml_audi_restriction_cond_add_audience(saml_audi_restriction_cond_t *cond, 
										axutil_env_t * env, axis2_char_t *audience);

/* action */
AXIS2_EXTERN saml_action_t * AXIS2_CALL 
saml_action_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_action_free(saml_action_t *action, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_action_build(saml_action_t *action, axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_action_to_om(saml_action_t *action, 
				  axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_data(saml_action_t *action, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_action_get_namespace(saml_action_t *action, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_data(saml_action_t *action, axutil_env_t *env, 
					 axis2_char_t *data);

AXIS2_EXTERN int AXIS2_CALL 
saml_action_set_namespace(saml_action_t *action, axutil_env_t *env, 
						  axis2_char_t *name_space);

/* evidence */
AXIS2_EXTERN saml_evidence_t * AXIS2_CALL 
saml_evidence_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_evidence_free(saml_evidence_t *evidence, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_build(saml_evidence_t *evidence, 
					axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_evidence_to_om(saml_evidence_t *evidence, axiom_node_t *parent, 
					axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertions(saml_evidence_t *evidence, axutil_env_t *env);

AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL 
saml_evidence_get_assertion_ids(saml_evidence_t *evidence, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertions(saml_evidence_t *evidence, 
							 axutil_env_t * env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion(saml_evidence_t *evidence, 
							   axutil_env_t * env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion(saml_evidence_t *evidence, 
							axutil_env_t * env, saml_assertion_t *assertion);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_set_assertion_ids(saml_evidence_t *evidence, 
								axutil_env_t * env, axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_remove_assertion_id(saml_evidence_t *evidence, 
								  axutil_env_t * env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_evidence_add_assertion_id(saml_evidence_t *evidence, 
							   axutil_env_t * env, axis2_char_t *assertion_id);

/* atrribute designature */
AXIS2_EXTERN saml_attr_desig_t * AXIS2_CALL 
saml_attr_desig_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_desig_free(saml_attr_desig_t *attr_desig, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_build(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_desig_to_om(saml_attr_desig_t *attr_desig, 
					  axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_name(saml_attr_desig_t *attr_desig, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_desig_get_namespace(saml_attr_desig_t *attr_desig, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_name(saml_attr_desig_t *attr_desig, 
						 axutil_env_t *env, axis2_char_t *name);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_desig_set_namespace(saml_attr_desig_t *attr_desig, 
							  axutil_env_t *env, axis2_char_t *name_space);

/* attribute */
AXIS2_EXTERN saml_attr_t * AXIS2_CALL 
saml_attr_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_attr_free(saml_attr_t *attr, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_build(saml_attr_t *attr, axiom_node_t *node, axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_attr_to_om(saml_attr_t *sattr, axiom_node_t *parent, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_name(saml_attr_t *attr_stmt, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_attr_get_namespace(saml_attr_t *attr_stmt, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_name(saml_attr_t *attr, axutil_env_t *env, axis2_char_t *name);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_namespace(saml_attr_t *attr, axutil_env_t *env, 
						axis2_char_t *name_space);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_set_values(saml_attr_t *attr, axutil_env_t *env, 
					 axutil_array_list_t *list);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_remove_value(saml_attr_t *attr, axutil_env_t *env, int index);

AXIS2_EXTERN int AXIS2_CALL 
saml_attr_add_value(saml_attr_t *attr, axutil_env_t *env, axiom_node_t *value);


/*named id*/
AXIS2_EXTERN saml_named_id_t * AXIS2_CALL 
saml_named_id_create(axutil_env_t *env);

AXIS2_EXTERN void AXIS2_CALL 
saml_named_id_free(saml_named_id_t *named_id, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_build(saml_named_id_t *named_id, axiom_node_t *node, 
					axutil_env_t *env);

AXIS2_EXTERN axiom_node_t * AXIS2_CALL 
saml_named_id_to_om(saml_named_id_t *id, axiom_node_t *parent, 
					axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name(saml_named_id_t *id, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_format(saml_named_id_t *id, axutil_env_t *env);

AXIS2_EXTERN axis2_char_t * AXIS2_CALL 
saml_named_id_get_name_qualifier(saml_named_id_t *id, axutil_env_t *env);

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name(saml_named_id_t *id, 
					   axutil_env_t *env, axis2_char_t *name);

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_format(saml_named_id_t *id, 
						 axutil_env_t *env, axis2_char_t *format);

AXIS2_EXTERN int AXIS2_CALL 
saml_named_id_set_name_qualifier(saml_named_id_t *id, 
								 axutil_env_t *env, axis2_char_t *qualifier);


/* private method */
AXIS2_EXTERN int AXIS2_CALL saml_util_set_sig_ctx_defaults(oxs_sign_ctx_t *sig_ctx, axutil_env_t *env, axis2_char_t *id);

#ifdef __cplusplus
}
#endif


#endif 
