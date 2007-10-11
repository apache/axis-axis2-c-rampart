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

#include <stdio.h>
#include <axis2_util.h>
#include <oxs_derivation.h>
#include <oxs_key.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_asym_ctx.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_derivation_derive_key(const axutil_env_t *env,
                         oxs_key_t *secret,
                         oxs_buffer_t *label,
                         oxs_buffer_t *seed,
                         oxs_key_t *derived_key
                         )
{
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *dk_id = NULL;
    /*TODO Concatenate the seed and label*/

    /*TODO P_SHA1 (secret, label + seed)*/
    
    /*TODO Populate the derived key. What we do here is fake. We use the same key ;-)*/
    dk_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_DERIVED_ID);
    status = oxs_key_populate(derived_key, env,
        oxs_key_get_data(secret, env),
        dk_id,
        oxs_key_get_size(secret, env),
        oxs_key_get_usage(secret, env));
        /*status = oxs_key_populate_with_buf(derived_key, env, 
            oxs_key_get_buffer(secret, env), 
            1,
            2);
            oxs_key_get_size(secret, env), 
            oxs_key_get_usage(secret, env));
    oxs_key_set_name(derived_key, env, dk_id);    */
 

    return status;
}

