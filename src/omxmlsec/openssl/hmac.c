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
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl_hmac.h>
#include <axutil_base64.h>
#include <axis2_util.h>

/**

*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
openssl_hmac_sha1(const axutil_env_t *env,
             oxs_key_t *secret,
             oxs_buffer_t *input,
             oxs_buffer_t *output)
{
    HMAC_CTX ctx;
    unsigned char hmac[MD5_DIGEST_LENGTH];
    unsigned int hashed_len;

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, oxs_key_get_data(secret, env), oxs_key_get_size(secret, env), EVP_sha1(), NULL);
    HMAC_Update(&ctx, oxs_buffer_get_data(input, env), oxs_buffer_get_size(input, env));
    HMAC_Final(&ctx, hmac, &hashed_len);
    HMAC_cleanup(&ctx); 
    
    HMAC_CTX_cleanup(&ctx);
    return AXIS2_SUCCESS;
}


