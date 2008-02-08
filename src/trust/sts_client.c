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

#include <trust_sts_client.h>
#include <axis2_op_client.h>

#ifndef TRUST_COMPUTED_KEY_PSHA1
#define TRUST_COMPUTED_KEY_PSHA1	"P-SHA1"
#endif

struct trust_sts_client
{

    /* Algorithm Suite for Entropy */
    rp_algorithmsuite_t *algo_suite;

    /* Trust 1.0 Assertions */
    rp_trust10_t *trust10;

    /* Issuer Address */
    axis2_char_t *issuer_address;

    /* STS Client Home Directory */
    axis2_char_t *home_dir;

    /* Location of the issuer's policy file */
    axis2_char_t *issuer_policy_location;

    /* Location of the service's (relying party's) policy file */
    axis2_char_t *service_policy_location;

	/*SVC Client Reference*/
	axis2_svc_client_t *svc_client;

	/*SENT RST - Most Recent*/
	axiom_node_t *sent_rst_node;

	/*RECEIVED RSTR - Most Recent*/
	axiom_node_t *received_rstr_node;

	/*RECEIVED In_msg_ctx*/
	axis2_msg_ctx_t *received_in_msg_ctx;


};

AXIS2_EXTERN trust_sts_client_t *AXIS2_CALL
trust_sts_client_create(
    const axutil_env_t * env)
{
    trust_sts_client_t *sts_client = NULL;

    sts_client = (trust_sts_client_t *) AXIS2_MALLOC(env->allocator, sizeof(trust_sts_client_t));

    sts_client->algo_suite = NULL;
    sts_client->trust10 = NULL;
    sts_client->home_dir = NULL;
    sts_client->issuer_address = NULL;
    sts_client->issuer_policy_location = NULL;
    sts_client->service_policy_location = NULL;
	sts_client->svc_client = NULL;

    return sts_client;
}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_free(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

	if(sts_client->svc_client)
	{
		axis2_svc_client_free(sts_client->svc_client, env);
		sts_client->svc_client = NULL;
	}

    if (sts_client)
    {
        AXIS2_FREE(env->allocator, sts_client);
    }

}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_request_security_token(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    trust_context_t *trust_context)
{
    neethi_policy_t *issuer_policy = NULL;
    neethi_policy_t *service_policy = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *return_node = NULL;

	axis2_op_client_t* op_client = NULL;
	axis2_msg_ctx_t *in_msg_ctx = NULL;

    
    /*Action Logic*/
    trust_rst_t *rst = NULL;
    axis2_char_t *request_type = NULL;
    
    if(sts_client->issuer_policy_location && sts_client->service_policy_location)
    {
        issuer_policy = neethi_util_create_policy_from_file(env, sts_client->issuer_policy_location);
        service_policy = neethi_util_create_policy_from_file(env, sts_client->service_policy_location);
    }
    
    if (!issuer_policy || !service_policy)
    {
        status = AXIS2_FAILURE;
    }
    else
    {
        trust_sts_client_process_policies(sts_client, env, issuer_policy, service_policy);
    }

 
    /*Action Logic - RequestType - used for specify the requesting action*/
    rst = trust_context_get_rst(trust_context, env);
    if(NULL == rst)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST is NULL: Created RST_CTX may not set to TrustContext");
            return;
    }

    request_type = trust_rst_get_request_type(rst, env);

    if(NULL == request_type)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-RequestType is NOT set. RST MUST have a RequestType");
            return;
    }

    sts_client->svc_client =
    trust_sts_client_get_svc_client(sts_client, env, request_type);
														  

    if (status == AXIS2_SUCCESS)
    {
        status = axis2_svc_client_set_policy(sts_client->svc_client, env, issuer_policy);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
        }
		/*Building the RST */
        rst_node = trust_context_build_rst_node(trust_context, env);
        if(rst_node)
        {
            return_node = axis2_svc_client_send_receive(sts_client->svc_client, env, rst_node);
			sts_client->sent_rst_node = return_node;

			/*Processing Response*/
			if(!return_node)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Return axiom node NULL");
			}
			else
			{
				/*Processing IN_MSG_CONTEXT*/
				op_client = axis2_svc_client_get_op_client(sts_client->svc_client, env);
				if(op_client)
				{
					in_msg_ctx = (axis2_msg_ctx_t *)axis2_op_client_get_msg_ctx (op_client, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
					
					if(in_msg_ctx)
					{
						trust_context_process_rstr(trust_context, env, in_msg_ctx);
						sts_client->received_in_msg_ctx = in_msg_ctx;	/*Store the in_msg_context for sec_header extentions in trust*/
					}
				}

			}
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-Not send -> RST Node building failed");
            return;
        }
    }

    return;
}

AXIS2_EXTERN axis2_svc_client_t *AXIS2_CALL
trust_sts_client_get_svc_client(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * action)
{
    axis2_endpoint_ref_t *endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t *svc_client = NULL;

    endpoint_ref = axis2_endpoint_ref_create(env, sts_client->issuer_address);

    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env, action);

    svc_client = axis2_svc_client_create(env, sts_client->home_dir);
    if (!svc_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:" " %d :: %s",
                        env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /* Engage addressing module */
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);

    return svc_client;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_process_policies(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    neethi_policy_t * issuer_policy,
    neethi_policy_t * service_policy)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (issuer_policy)
    {
        sts_client->algo_suite = trust_policy_util_get_algorithmsuite(env, issuer_policy);
    }

    if (service_policy)
    {
        sts_client->trust10 = trust_policy_util_get_trust10(env, service_policy);
    }

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * address)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, address, AXIS2_FAILURE);

    sts_client->issuer_address = address;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_address;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * directory)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, directory, AXIS2_FAILURE);

    sts_client->home_dir = directory;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->home_dir;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->issuer_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_policy_location;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->service_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->service_policy_location;
}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_request_security_token_using_policy(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    trust_context_t *trust_context,
    neethi_policy_t *issuer_policy)
{
    axis2_svc_client_t *svc_client = NULL;

    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *return_node = NULL;
    axis2_op_client_t* op_client = NULL;
	axis2_msg_ctx_t *in_msg_ctx = NULL;

    
    /*Action Logic*/
    trust_rst_t *rst = NULL;
    axis2_char_t *request_type = NULL;
    
    trust_sts_client_process_policies(sts_client, env, issuer_policy, issuer_policy);
 
    /*Action Logic - RequestType - used for specify the requesting action*/
    rst = trust_context_get_rst(trust_context, env);
    if(NULL == rst)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST is NULL: Created RST_CTX may not set to TrustContest");
            return;
    }

    request_type = trust_rst_get_request_type(rst, env);

    if(NULL == request_type)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-RequestType is NOT set. RST MUST have a RequestType");
            return;
    }

    svc_client =
    trust_sts_client_get_svc_client(sts_client, env, request_type);
														  

    if (svc_client)
    {
        status = axis2_svc_client_set_policy(svc_client, env, issuer_policy);

        if (status == AXIS2_FAILURE)
        {
            axis2_svc_client_free(svc_client, env);
            svc_client = NULL;
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
        }

		/*Building the RST */
        rst_node = trust_context_build_rst_node(trust_context, env);
        if(rst_node)
        {
            return_node = axis2_svc_client_send_receive(svc_client, env, rst_node);
			sts_client->sent_rst_node = return_node;

			/*Processing Response*/
			if(!return_node)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Return axiom node NULL");
			}
			else
			{
				/*Processing IN_MSG_CONTEXT*/
				op_client = axis2_svc_client_get_op_client(svc_client, env);
				if(op_client)
				{
					in_msg_ctx = (axis2_msg_ctx_t *)axis2_op_client_get_msg_ctx (op_client, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
					
					if(in_msg_ctx)
					{
						trust_context_process_rstr(trust_context, env, in_msg_ctx);
						sts_client->received_in_msg_ctx = in_msg_ctx;	/*Store the in_msg_context for sec_header extentions in trust*/
					}
				}

			}
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-Not send -> RST Node building failed");
            return;
        }
    }

    return;
}