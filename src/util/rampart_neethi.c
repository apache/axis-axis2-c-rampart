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

/*
 *
 */

#include <rampart_neethi.h>
#include <axis2_ctx.h>
#include <axis2_svc.h>
#include <axis2_desc.h>
#include <axis2_policy_include.h>
#include <rp_secpolicy_builder.h>
#include <neethi_policy.h>
#include <rampart_authn_provider.h>
#include <rampart_util.h>
#include <rampart_constants.h>
#include <rampart_callback.h>
#include <axis2_msg.h>
#include <axis2_conf_ctx.h>

/*This method sets all the configurations
 loads required modules and start rampart.*/


AXIS2_EXTERN rampart_context_t *AXIS2_CALL 
rampart_neethi_build_configuration(
        const axutil_env_t *env,
        axis2_msg_ctx_t *msg_ctx,
        axis2_bool_t is_inflow)
{

    axis2_svc_t *svc = NULL;
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    neethi_policy_t *service_policy = NULL;
    rp_secpolicy_t *secpolicy = NULL;
    rampart_context_t *rampart_context = NULL;
    rampart_callback_t* password_callback_module = NULL;
    rampart_authn_provider_t *authn_provider = NULL;
    axis2_char_t *pwcb_module_name = NULL;
    axis2_char_t *authn_provider_name = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axis2_op_t *op = NULL;
    axis2_msg_t *msg = NULL;
    axis2_conf_t *conf = NULL;
    struct axis2_conf_ctx *conf_ctx = NULL;


    conf_ctx =  axis2_msg_ctx_get_conf_ctx(msg_ctx,env);
    if(!conf_ctx)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] Conf context is NULL ");
        return NULL;
    }
    conf =  axis2_conf_ctx_get_conf(conf_ctx, env);
    if(!conf)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rhu] Cannot get the axis2 conf from conf context. ");
        return NULL;
    }
    
    svc =  axis2_msg_ctx_get_svc(msg_ctx,env);
    if(!svc)
    {
        rampart_context = (rampart_context_t *)axis2_conf_get_security_context(conf, env);
        if(rampart_context)
            return rampart_context;
        
        else
        {
            AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] Service is NULL.");
            return NULL;
        }
    }
                        
    op = axis2_msg_ctx_get_op(msg_ctx, env);
    if(!op)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] Operation is NULL.");
        return NULL;
    }        
    
    if(is_inflow)
    {
        msg = axis2_op_get_msg(op, env, "in");
    }
    else
    {
        msg = axis2_op_get_msg(op, env, "out");
    }        

    if(!msg)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] Message is NULL.");
        return NULL;
    }
    
    /*desc = axis2_svc_get_base(svc, env);*/
    desc = axis2_msg_get_base(msg, env);
    if(!desc)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] axis2 description is NULL.");
        return NULL;
    }
    policy_include = axis2_desc_get_policy_include(desc, env);        
    
    if(!policy_include)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] Policy include is NULL.");
        return NULL;
    }
    /*service_policy = axis2_policy_include_get_policy(policy_include, env);*/
    service_policy = axis2_policy_include_get_effective_policy(policy_include, env);
    
    if(!service_policy)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] Policy is NULL.");
        return NULL;
    }    
    secpolicy = rp_secpolicy_builder_build(env, service_policy);

    if(!service_policy)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][rampart_neethi] security policy is NULL.");
        return NULL;
    }
    rampart_context = rampart_context_create(env);
    
    rampart_context_set_secpolicy(rampart_context, env, secpolicy);

    status = rampart_context_set_user_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
        return NULL;

    status = rampart_context_set_ttl_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
        return NULL;

    status = rampart_context_set_password_type_from_file(rampart_context,env);
    if(status!=AXIS2_SUCCESS)
        return NULL;

    pwcb_module_name = rampart_context_get_password_callback_class(rampart_context,env);

    if(pwcb_module_name)
    {
        password_callback_module = rampart_load_pwcb_module(env,pwcb_module_name);
        if(password_callback_module)
            rampart_context_set_password_callback(rampart_context,env,password_callback_module);
    }
    authn_provider_name = rampart_context_get_authn_module_name(rampart_context,env);

    if(authn_provider_name)
    {
        authn_provider = rampart_load_auth_module(env,authn_provider_name);
        if(authn_provider)
            rampart_context_set_authn_provider(rampart_context,env,authn_provider);
    }
    
    if(!axis2_msg_ctx_get_server_side(msg_ctx, env))
    {
        axis2_conf_set_security_context(conf, env, rampart_context);        
    }        

    return rampart_context;
}

