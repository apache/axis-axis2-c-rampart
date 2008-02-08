/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RAMPART_CONFIG_H
#define RAMPART_CONFIG_H

/**
  * @file rampart_config.h
  * @brief The Rampart Config, in which user configurations are stored
  */

/**
 * @defgroup rampart_config Rampart Config
 * @ingroup rampart_utils
 * @{
 */

#include <rp_includes.h>
#include <rp_secpolicy.h>
#include <rampart_authn_provider.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_callback.h>
#include <rampart_authn_provider.h>
#include <axis2_key_type.h>
#include <axis2_msg_ctx.h>
#include <oxs_key.h>
#include <axutil_array_list.h>
#include <rampart_saml_token.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_config_t rampart_config_t;


    /**
    * Create a rampart_config.rampart_config is the wrapper
    * @env pointer to environment struct
    * @return ramaprt_config_t* on successful creation. Else NULL; 
    */

    AXIS2_EXTERN rampart_config_t *AXIS2_CALL
    rampart_config_create(const axutil_env_t *env);


    /**
    * Frees a rampart_config.
    * @rampart_config the rampart_config
    * @env pointer to environment struct
    */

    AXIS2_EXTERN void AXIS2_CALL
    rampart_config_free(rampart_config_t *rampart_config,
                         const axutil_env_t *env);


    /****************************************************************/


    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_username(rampart_config_t *rampart_config,
                             const axutil_env_t *env,
                             axis2_char_t *user);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_password(rampart_config_t *rampart_config,
                                 const axutil_env_t *env,
                                 axis2_char_t *password);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_password_type(rampart_config_t *rampart_config,
                                      const axutil_env_t *env,
                                      axis2_char_t *password_type);

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_config_set_ttl(rampart_config_t *rampart_config,
                            const axutil_env_t *env,
                            int ttl);

	AXIS2_EXTERN int AXIS2_CALL
	rampart_config_add_saml_token(rampart_config_t *rampart_config, 
								  const axutil_env_t *env, 
								  rampart_saml_token_t *saml);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_username(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_password(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_config_get_password_type(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);
    
    AXIS2_EXTERN int AXIS2_CALL
    rampart_config_get_ttl(
        rampart_config_t *rampart_config,
        const axutil_env_t *env);

	AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
	rampart_config_get_saml_tokens(rampart_config_t *rampart_config, 
								  const axutil_env_t *env);    
    /*End of Getters */


#ifdef __cplusplus
}
#endif
#endif
