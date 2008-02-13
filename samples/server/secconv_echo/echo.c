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
#include "echo.h"
#include <axiom_xml_writer.h>
#include <axiom_util.h>
#include <stdio.h>
#include <secconv_security_context_token.h>
#include <trust_rstr.h>
#include <trust_rst.h>
#include <openssl_util.h>
#include <oxs_utility.h>
#include <axutil_hash.h>
#include <axis2_conf_ctx.h>
#include <axis2_ctx.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_sct_provider.h>

axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text);

static axutil_hash_t *
secconv_echo_get_sct_db(const axutil_env_t *env, axis2_msg_ctx_t* msg_ctx);

axiom_node_t *
axis2_echo_echo(const axutil_env_t *env, axiom_node_t *node, axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *ret_node = NULL;
    axis2_char_t *name = NULL;
    AXIS2_ENV_CHECK(env, NULL);
    
    name = axiom_util_get_localname(node, env);
    AXIS2_LOG_INFO(env->log, "[rampart][sec_echo_service] Recieved node %s", name);     
/*
 * This shows how to acces the security processed results from the message context
    {
    axis2_char_t *username = NULL;
    
    username = (axis2_char_t*)rampart_get_security_processed_result(env, msg_ctx, "SPR_UT_username");
    printf("Username of the Token is = %s ", username);
    }
*/    
    ret_node = build_om_programatically(env, name);
    return ret_node;
}

/* Builds the response content */
axiom_node_t *
build_om_programatically(const axutil_env_t *env, axis2_char_t *text)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 = axiom_namespace_create(env, "http://ws.apache.org/axis2/rampart/samples", "ns1");
    echo_om_ele = axiom_element_create(env, NULL, "RecievedNode", ns1, &echo_om_node);

    text_om_ele = axiom_element_create(env, echo_om_node, "LocalName", NULL, &text_om_node);

    axiom_element_set_text(text_om_ele, env, text, text_om_node);
 
    return echo_om_node;
}

axiom_node_t *
secconv_echo_sts_request_security_token(
    const axutil_env_t *env, 
    axiom_node_t *node, 
    axis2_msg_ctx_t *msg_ctx)
{
    trust_rst_t* rst = NULL;
    trust_rstr_t* rstr = NULL;
    axis2_status_t status;
    axis2_char_t *token_type = NULL;
    axis2_char_t *request_type = NULL;
    axis2_char_t *global_id = NULL;
    axis2_char_t *local_id = NULL;
    oxs_buffer_t *shared_secret = NULL;
    security_context_token_t *sct = NULL;
    axiom_node_t* rstr_node = NULL;
    int size = 32;
    axutil_hash_t* db = NULL;

    /*create and populate rst using node given*/
    rst = trust_rst_create(env);
    trust_rst_set_wst_ns_uri(rst, env, TRUST_WST_XMLNS_05_02);
    status = trust_rst_populate_rst(rst, env, node);
    if(status == AXIS2_FAILURE)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] cannot populate rst");
        return NULL;
    }

    /*check whether rst is valid and can be processed*/
    token_type = trust_rst_get_token_type(rst, env);
    if((!token_type) || (0 != axutil_strcmp(token_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN)))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] token type is not valid");
        return NULL;
    }
    request_type = trust_rst_get_request_type(rst, env);
    if(!request_type) /*|| (0 != axutil_strcmp(request_type, TRUST_REQ_TYPE_ISSUE)))*/
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] request type is not valid");
        return NULL;
    }

    /*create global id, local id, and shared secret*/
    global_id = oxs_util_generate_id(env,"urn:uuid:");
    local_id = axutil_stracat(env, "#", oxs_util_generate_id(env, "sctId"));
    shared_secret = oxs_buffer_create(env);
    openssl_generate_random_data(env, shared_secret, size);

    /*create security context token and populate it*/
    sct = security_context_token_create(env);
    security_context_token_set_secret(sct, env, shared_secret);
    security_context_token_set_global_identifier(sct, env, global_id);
    security_context_token_set_local_identifier(sct, env, local_id);

    /*store SCT so that when server needs it, can be extracted*/
    db = sct_provider_get_sct_db(env, msg_ctx);
    if(!db)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][secconv_service] Cannot get sct datastore");
        security_context_token_free(sct, env);
        return NULL;
    }

    axutil_hash_set(db, global_id, AXIS2_HASH_KEY_STRING, sct);

    /*create rstr and populate*/
    rstr = trust_rstr_create(env);
    trust_rstr_set_token_type(rstr, env, token_type);
    trust_rstr_set_request_type(rstr, env, request_type);
    trust_rstr_set_wst_ns_uri(rstr, env, TRUST_WST_XMLNS_05_02);
    trust_rstr_set_requested_proof_token(rstr, env, 
                    security_context_token_get_requested_proof_token(sct, env));
    trust_rstr_set_requested_unattached_reference(rstr, env, 
                    security_context_token_get_unattached_reference(sct, env));
    trust_rstr_set_requested_attached_reference(rstr, env, 
                    security_context_token_get_attached_reference(sct, env));
    trust_rstr_set_requested_security_token(rstr, env, 
                    security_context_token_get_token(sct, env));

    /*build the rstr node*/
    rstr_node = trust_rstr_build_rstr(rstr, env, NULL);

    /*clear stuff*/
    trust_rstr_free(rstr, env);

    /*set the action*/
    axis2_msg_ctx_set_wsa_action(msg_ctx, env, "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT");

    /*return the node*/
    return rstr_node;
}

static axutil_hash_t *
secconv_echo_get_sct_db(const axutil_env_t *env,
                                  axis2_msg_ctx_t* msg_ctx)
{
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_ctx_t *ctx = NULL;
    axutil_property_t *property = NULL;
    axutil_hash_t *db = NULL;
    
    /*Get the conf ctx*/
    conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    if(!conf_ctx)
    {
        AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, "[rampart][secconv_service] Conf context is NULL ");
        return NULL;
    }
    ctx = axis2_conf_ctx_get_base(conf_ctx,env);
    if(!ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][secconv_service] axis2 context is NULL ");
        return NULL;
    }

    /*Get the DB property*/
    property = axis2_ctx_get_property(ctx, env, RAMPART_SCT_PROVIDER_DB_PROB);
    if(property)
    {
        /*Get the DB*/
        db = (axutil_hash_t*)axutil_property_get_value(property, env);
    }
    else
    {
        axutil_property_t *db_prop = NULL;

        db = axutil_hash_make(env);
        db_prop = axutil_property_create(env);
        axutil_property_set_value(db_prop, env, db);
        axis2_ctx_set_property(ctx, env, RAMPART_SCT_PROVIDER_DB_PROB, db_prop);
    }

    return db;
}

