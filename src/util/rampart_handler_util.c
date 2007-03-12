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

#include <rampart_handler_util.h>
#include <axis2_handler_desc.h>
#include <axis2_qname.h>
#include <axis2_svc.h>
#include <axiom_soap_header.h>
#include <axiom_soap_body.h>
#include <axiom_soap_header_block.h>
#include <axis2_endpoint_ref.h>
#include <axis2_property.h>
#include <rampart_constants.h>
#include <axis2_dll_desc.h>
#include <axis2_class_loader.h>
#include <axis2_conf_ctx.h>
#include <oxs_axiom.h>

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_callback_encuser_password(const axis2_env_t *env,
            rampart_actions_t *actions,
            axis2_msg_ctx_t *msg_ctx);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_get_property_from_ctx(const axis2_env_t *env,
        axis2_ctx_t *ctx,
        const axis2_char_t *key);

AXIS2_EXTERN axis2_param_t* AXIS2_CALL
rampart_get_security_param(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_char_t *parameter);

AXIS2_EXTERN axis2_array_list_t* AXIS2_CALL
rampart_get_actions(const axis2_env_t *env,
        axis2_ctx_t *ctx,
        axis2_param_t *param_x_flow_security);

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_get_action_params(const axis2_env_t *env,
        axis2_param_t *param_action,
        const axis2_char_t *key);

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
rampart_get_security_token(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_soap_header_t *soap_header);

AXIS2_EXTERN void AXIS2_CALL
rampart_create_fault_envelope(const axis2_env_t *env,
        const axis2_char_t *sub_code,
        const axis2_char_t *reason_text,
        const axis2_char_t *detail_node_text,
        axis2_msg_ctx_t *msg_ctx);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_validate_security_token(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_node_t *sec_node);

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_get_policy_location(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_char_t *param_name);

/**********************end of header functions ****************************/

axis2_char_t* AXIS2_CALL
rampart_callback_encuser_password(const axis2_env_t *env,
            rampart_actions_t *actions,
            axis2_msg_ctx_t *msg_ctx)
{
    axis2_char_t *enc_user = NULL;
    axis2_char_t *pw_callback_module = NULL;
    axis2_char_t *password = NULL;
    axis2_ctx_t *ctx = NULL;

    /*Check if encUserPassword is in the context. This is designed specially for PHP
    i.e.In any context in the context hierarchy starting from msg, op, svc, etc.*/
    ctx = AXIS2_MSG_CTX_GET_BASE(msg_ctx, env);
    password = rampart_get_property_from_ctx(env, ctx,  RAMPART_ACTION_ENC_USER_PASSWORD);
    if (password)
    {
        return password;
    }
    /*If not found then callback the password*/ 

    enc_user = RAMPART_ACTIONS_GET_ENC_USER(actions, env);
    pw_callback_module = RAMPART_ACTIONS_GET_PW_CB_CLASS(actions, env);
    if(!pw_callback_module){
        return NULL;
    }
    if(!enc_user){
        /*If a special enc_user hasn't specified try to get the user.
         * But it is advisable to use enc_user instead of user.*/
        enc_user = RAMPART_ACTIONS_GET_USER(actions, env);
        if(!enc_user){
            return NULL;
        }
    }
    /*Get axis2_ctx_t. This is designed specially for PHP*/

/*  password = rampart_callback_password(env, pw_callback_module, enc_user, ctx);*/
/*  password = rampart_callback_password(env, pw_callback_module, enc_user);*/

    return password;
}

axis2_char_t* AXIS2_CALL
rampart_get_property_from_ctx(const axis2_env_t *env,
        axis2_ctx_t *ctx,
        const axis2_char_t *key)
{
    axis2_property_t* property = NULL;
    axis2_char_t* str_property = NULL;

    /*Get value from the dynamic settings*/

    property = AXIS2_CTX_GET_PROPERTY(ctx, env, key, AXIS2_FALSE);
    if (property)
    {
        str_property = AXIS2_PROPERTY_GET_VALUE(property, env);
        property = NULL;
    }

    return str_property;
}


axis2_param_t* AXIS2_CALL
rampart_get_security_param(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_char_t *parameter)
{
    /*parameter can be either RAMPART_OUTFLOW_SECURITY or RAMPART_INFLOW_SECURITY*/
    axis2_param_t *param = NULL;
    param = AXIS2_MSG_CTX_GET_PARAMETER(msg_ctx, env, parameter);
    return param;
}


axis2_array_list_t *AXIS2_CALL
rampart_get_actions(const axis2_env_t *env,
        axis2_ctx_t *ctx,
        axis2_param_t *param_x_flow_security)
{
    axis2_array_list_t *action_list = NULL;
    int param_type;
    if (!param_x_flow_security)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu]param_in_flow_security is NULL");
        return action_list;
    }

    /*ERROR HERE param returns TEXT even for DOM*/
    param_type = AXIS2_PARAM_GET_PARAM_TYPE(param_x_flow_security, env);

    action_list = AXIS2_PARAM_GET_VALUE_LIST(param_x_flow_security, env);
    if (!action_list)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] action_list is NULL ... ERROR ");
    }
    return action_list;
}


axis2_char_t* AXIS2_CALL
rampart_get_action_params(const axis2_env_t *env,
        axis2_param_t *param_action,
        const axis2_char_t *key)
{
    axis2_char_t *value = NULL;
    axis2_char_t *tmp_key = NULL;
    axis2_char_t * param_name = NULL;
    axis2_array_list_t *param_list = NULL;
    axis2_param_t *param = NULL;
    int param_type;
    int i, size = 0;

    if (!param_action)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] param_action is NULL");
    }

    param_type = AXIS2_PARAM_GET_PARAM_TYPE(param_action, env);
    param_name = AXIS2_PARAM_GET_NAME(param_action, env);

    param_list = AXIS2_PARAM_GET_VALUE_LIST(param_action, env);
    if (!param_list)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] param list is NULL");
    }

    size = axis2_array_list_size(param_list, env);
    for (i = 0; i < size; i = i + 1)
    {
        param = (axis2_param_t*) axis2_array_list_get(param_list, env, i);
        if (param)
        {
            tmp_key = AXIS2_PARAM_GET_NAME(param, env);

            if (0 == AXIS2_STRCMP(tmp_key , key))
            {
                value = AXIS2_PARAM_GET_VALUE(param, env);
                return value;
            }
        }
    }

    return value;
}

axiom_node_t *AXIS2_CALL
rampart_get_security_token(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_soap_header_t *soap_header
                          )
{
    axis2_array_list_t *sec_headers = NULL;
    axis2_char_t *sec_ns_str = NULL;
    axis2_hash_index_t *hash_index =  NULL;
    axis2_hash_t *header_block_ht = NULL;
    axiom_element_t *header_block_ele = NULL;
    axiom_node_t *header_block_node = NULL;

    sec_headers = AXIOM_SOAP_HEADER_GET_HEADER_BLOCKS_WITH_NAMESPACE_URI(soap_header, env, RAMPART_WSSE_XMLNS);
    if (sec_headers)
    {
        sec_ns_str = AXIS2_STRDUP(RAMPART_WSSE_XMLNS, env);

        header_block_ht = AXIOM_SOAP_HEADER_GET_ALL_HEADER_BLOCKS(soap_header, env);
        if (!header_block_ht)
            return AXIS2_FAILURE;

        /*BETTER IF : If there are multiple security header elements, get the one with @role=rampart*/
        for (hash_index = axis2_hash_first(header_block_ht, env); hash_index;
                hash_index = axis2_hash_next(env, hash_index))
        {

            void *hb = NULL;
            axiom_soap_header_block_t *header_block =    NULL;
            axis2_char_t *ele_localname = NULL;

            axis2_hash_this(hash_index, NULL, NULL, &hb);
            header_block = (axiom_soap_header_block_t *)hb;
            header_block_node = AXIOM_SOAP_HEADER_BLOCK_GET_BASE_NODE(header_block, env);
            header_block_ele  = (axiom_element_t*)AXIOM_NODE_GET_DATA_ELEMENT(header_block_node, env);
            ele_localname = AXIOM_ELEMENT_GET_LOCALNAME(header_block_ele, env);

            if (AXIS2_STRCMP(ele_localname, RAMPART_SECURITY) == 0)
            {
                /*Set mustUnderstand = 0*/
                AXIOM_SOAP_HEADER_BLOCK_SET_MUST_UNDERSTAND_WITH_BOOL(header_block, env, AXIS2_FALSE);
                return header_block_node;
            }

        }/*End of for*/
    }
    return header_block_node;

}

AXIS2_EXTERN void AXIS2_CALL
rampart_create_fault_envelope(const axis2_env_t *env,
        const axis2_char_t *sub_code,
        const axis2_char_t *reason_text,
        const axis2_char_t *detail_node_text,
        axis2_msg_ctx_t *msg_ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    axis2_array_list_t *sub_codes = NULL;

    sub_codes = axis2_array_list_create(env, 1);
    axis2_array_list_add(sub_codes, env, sub_code);

    ns1 = axiom_namespace_create(env, RAMPART_WSSE_XMLNS, RAMPART_WSSE);
    text_om_ele = axiom_element_create(env, NULL, "ProblemSecurityHeader", ns1, &text_om_node);
    AXIOM_ELEMENT_SET_TEXT(text_om_ele, env, detail_node_text, text_om_node);

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
            "soapenv:Sender",
            reason_text,
            soap_version, sub_codes, text_om_node);

    AXIS2_MSG_CTX_SET_FAULT_SOAP_ENVELOPE(msg_ctx, env, envelope);
    /*free sub codes*/
    return;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_validate_security_token(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axiom_node_t *sec_node)
{
    int num = 0;
    /*Check if there are multiple timestamp tokens*/
    num = oxs_axiom_get_number_of_children_with_qname(env, sec_node, RAMPART_SECURITY_TIMESTAMP, NULL, NULL);
    if (num > 1)
    {
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN void *AXIS2_CALL
rampart_get_rampart_configuration(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_char_t *param_name)
        
{
    axis2_param_t *param_x_flow_security = NULL;
    void *value = NULL;

    param_x_flow_security = rampart_get_security_param(env, msg_ctx,
                                    param_name);
    
    if (!param_x_flow_security)
    {
        AXIS2_LOG_INFO(env->log,
            "[rampart][rampart_handler_utils] %s parameter is not set.",param_x_flow_security);
        return NULL;
    }
    value = AXIS2_PARAM_GET_VALUE(param_x_flow_security, env);
    return value;
}

/*This method will check whether rampart should process the message*/

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_is_rampart_engaged(const axis2_env_t *env,
        axis2_msg_ctx_t *msg_ctx)
{
    struct axis2_svc *svc = NULL;
    axis2_array_list_t *engaged_modules = NULL;
    int size = 0;
    int i = 0;
    const axis2_qname_t *qname = NULL;
    axis2_char_t *local_name = NULL;
    axis2_conf_t *conf = NULL;
    struct axis2_conf_ctx *conf_ctx = NULL;

    conf_ctx = AXIS2_MSG_CTX_GET_CONF_CTX(msg_ctx,env);
    if(!conf_ctx)
    {
         AXIS2_LOG_INFO(env->log, "[rampart][rhu] Conf context is NULL ");
         return AXIS2_FALSE;
    }    
    conf =  axis2_conf_ctx_get_conf(conf_ctx, env);
    if(!conf)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] Cannot get the axis2 conf from conf context. ");
        return AXIS2_FALSE;
    }
    
    engaged_modules = AXIS2_CONF_GET_ALL_ENGAGED_MODULES(conf, env);
    if(engaged_modules)
    {
        size = axis2_array_list_size(engaged_modules,env);
        for(i=0; i<size; i++)
        {
            qname = (axis2_qname_t *) axis2_array_list_get(engaged_modules,env,i);
            local_name = AXIS2_QNAME_GET_LOCALPART(qname,env);
            if(AXIS2_STRCMP(local_name,RAMPART_RAMPART)==0)
                return AXIS2_TRUE;
        }
    }            
/*If not engaed gloabally check whether it is engaged at service level.
 *And If service is not there check whether the rampart is enabled by 
 a previous invocation of a handler.*/

    svc = AXIS2_MSG_CTX_GET_SVC(msg_ctx,env);
    if(!svc)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] Service is NULL.");
        return axis2_conf_get_enable_security(conf,env);
    }    
            
    engaged_modules = AXIS2_SVC_GET_ALL_MODULE_QNAMES(svc,env);
    if(engaged_modules)
    {
        size = axis2_array_list_size(engaged_modules,env);
        for(i=0; i<size; i++)
        {
            qname = (axis2_qname_t *) axis2_array_list_get(engaged_modules,env,i);
            local_name = AXIS2_QNAME_GET_LOCALPART(qname,env);
            if(AXIS2_STRCMP(local_name,RAMPART_RAMPART)==0)
            {                
                axis2_conf_set_enable_security(conf,env,AXIS2_TRUE);
                return AXIS2_TRUE;
            }                
        }
    }
    return AXIS2_FALSE;
}

