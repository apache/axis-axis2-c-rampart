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

#ifndef RAMPART_SCT_PROVIDER_H
#define RAMPART_SCT_PROVIDER_H

/**
  * @file rampart_sct_provider.h
  * @brief Security context token provider module for rampart 
  */

/**
* @defgroup sct_provider Security Context Token provider
* @ingroup rampart_utils
* @{
*/

#include <axis2_defines.h>
#include <axutil_env.h>
#include <axis2_msg_ctx.h>
#include <axis2_conf_ctx.h>
#include <rampart_context.h>
#include <secconv_security_context_token.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Type name for struct rampart_sct_provider_ops 
     */
    typedef struct rampart_sct_provider_ops rampart_sct_provider_ops_t;

    /**
     * Type name for struct rampart_sct_provider
     */

    typedef struct rampart_sct_provider rampart_sct_provider_t;

    /**
     * get_sct_secret gives the shared secret of security context token
     */
    struct rampart_sct_provider_ops
    {
        security_context_token_t* (AXIS2_CALL*
            get_token)(rampart_sct_provider_t *sct_provider,
            const axutil_env_t* env, 
            rp_property_t *token, 
            axis2_bool_t server_side, 
            axis2_bool_t is_encryption, 
            axis2_char_t* identifier,
            rampart_context_t* rampart_context, 
            axis2_msg_ctx_t* msg_ctx);

        axis2_status_t (AXIS2_CALL*
            free)(rampart_sct_provider_t *sct_provider,
            const axutil_env_t* env);
    };

    struct rampart_sct_provider
    {
        rampart_sct_provider_ops_t *ops;
		axutil_param_t *param;
    };

    /*returned buffer should NOT be cleared by the caller*/
    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
    sct_provider_get_secret(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t server_side, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /*returned buffer should NOT be cleared by the caller*/
    AXIS2_EXTERN oxs_buffer_t *AXIS2_CALL
        sct_provider_get_secret_using_id(
        const axutil_env_t* env, 
        axis2_char_t* sct_id, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    sct_provider_get_token(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t server_side, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    sct_provider_get_attached_reference(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t server_side, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    sct_provider_get_unattached_reference(
        const axutil_env_t* env, 
        rp_property_t *token, 
        axis2_bool_t server_side, 
        axis2_bool_t is_encryption, 
        rampart_context_t* rampart_context, 
        axis2_msg_ctx_t* msg_ctx);

    /*************************** Function macros **********************************/
#define RAMPART_SCT_PROVIDER_GET_TOKEN(sct_provider, env, token, server_side, is_enc, sct_id, rampart_ctx, msg_ctx) \
        ((sct_provider)->ops->get_token(sct_provider, env, token, server_side, is_enc, sct_id, rampart_ctx, msg_ctx))

#define RAMPART_SCT_PROVIDER_FREE(sct_provider, env) \
        ((sct_provider)->ops->free(sct_provider, env))

    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* RAMPART_SCT_PROVIDER_H */

