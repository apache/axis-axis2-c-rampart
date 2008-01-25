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

#include <rampart_config.h>
#include <rampart_constants.h>

struct rampart_config_t
{
    /*****************************/
    axis2_char_t *username;
    axis2_char_t *password;
    axis2_char_t *password_type;
    int ttl;
};



AXIS2_EXTERN rampart_config_t *AXIS2_CALL
rampart_config_create(const axutil_env_t *env)
{
    rampart_config_t *rampart_config = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    rampart_config =  (rampart_config_t *) AXIS2_MALLOC (env->allocator,
                       sizeof (rampart_config_t));

    if(rampart_config == NULL)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }
    rampart_config->username = NULL;
    rampart_config->password = NULL;
    rampart_config->password_type = NULL;

    return rampart_config;
}

AXIS2_EXTERN void AXIS2_CALL
rampart_config_free(rampart_config_t *rampart_config,
                     const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);


        /*TODO Free*/
        AXIS2_FREE(env->allocator,rampart_config);
        rampart_config = NULL;
    return;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_username(rampart_config_t *rampart_config,
                         const axutil_env_t *env,
                         axis2_char_t *username)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, username, AXIS2_FAILURE);

    rampart_config->username = username;
    return AXIS2_SUCCESS;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_password(rampart_config_t *rampart_config,
                             const axutil_env_t *env,
                             axis2_char_t *password)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error,password,AXIS2_FAILURE);

    rampart_config->password = password;
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_password_type(rampart_config_t *rampart_config,
                                  const axutil_env_t *env,
                                  axis2_char_t *password_type)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error,password_type,AXIS2_FAILURE);

    rampart_config->password_type = password_type;
    return AXIS2_SUCCESS;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_config_set_ttl(rampart_config_t *rampart_config,
                        const axutil_env_t *env,
                        int ttl)
{

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error,ttl,AXIS2_FAILURE);

    rampart_config->ttl = ttl;
    return AXIS2_SUCCESS;
}




AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_username(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return rampart_config->username;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_password(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, NULL);

    return rampart_config->password;
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_config_get_password_type(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env,NULL);

    return rampart_config->password_type;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_config_get_ttl(
    rampart_config_t *rampart_config,
    const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env,NULL);

    return rampart_config->ttl;
}

