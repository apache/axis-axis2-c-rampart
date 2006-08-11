/*
 *   Copyright 2003-2004 The Apache Software Foundation.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <axis2_util.h>
#include <oxs_error.h>
#include <oxs_cipher.h>
#include <openssl_constants.h>

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_get_cipher(const axis2_env_t *env,
                     axis2_char_t *url)
{
    if(AXIS2_STRCMP(url, (axis2_char_t*)OXS_HrefDes3Cbc)){
        return OPENSSL_EVP_des_ede3_cbc;
    }else if(AXIS2_STRCMP(url, (axis2_char_t*)OXS_HrefAes128Cbc)){
        return OPENSSL_EVP_aes_128_cbc;
    }else if(AXIS2_STRCMP(url, (axis2_char_t*)OXS_HrefAes192Cbc)){
        return OPENSSL_EVP_aes_192_cbc;
    }else if(AXIS2_STRCMP(url, (axis2_char_t*)OXS_HrefAes256Cbc)){
        return OPENSSL_EVP_aes_256_cbc;
    }else{
        oxs_error(ERROR_LOCATION,
                    OXS_ERROR_UNSUPPORTED_ALGO, "Algorithm not supported");
        return NULL;
    }

    return NULL; 
}

AXIS2_EXTERN int AXIS2_CALL
oxs_get_cipher_key_size(const axis2_env_t *env,
                     axis2_char_t *url)
{
    int size = 16;
    axis2_char_t* cipher_name = NULL;

    cipher_name = oxs_get_cipher(env, url);
    /*TODO*/
    return size;    
}


AXIS2_EXTERN int AXIS2_CALL
oxs_get_cipher_iv_size(const axis2_env_t *env,
                     axis2_char_t *url)
{
    int size = 8;
    axis2_char_t* cipher_name = NULL;

    cipher_name = oxs_get_cipher(env, url);
    /*TODO*/
    
    return size;

}
