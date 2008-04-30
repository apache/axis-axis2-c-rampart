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

#include <openssl_pkcs12_keystore.h>
#include <axutil_array_list.h>

struct pkcs12_keystore{
    char *keystore_file;
    char *keystore_password;
    PKCS12 *keystore;
    oxs_x509_cert_t *cert;
    axutil_array_list_t *other_certs; 
    openssl_pkey_t *pvt_key;
};

AXIS2_EXTERN pkcs12_keystore_t * AXIS2_CALL pkcs12_keystore_create(
    const axutil_env_t *env, 
    axis2_char_t *filename, 
    axis2_char_t *password)
{
    pkcs12_keystore_t *keystore = NULL;
    X509 *own_cert = NULL;
    STACK_OF(X509) *other_certs = NULL;
    EVP_PKEY *pvt_key = NULL;
        
    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    
    keystore = (pkcs12_keystore_t*)AXIS2_MALLOC(env->allocator, sizeof(pkcs12_keystore_t));
    if(!keystore)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_CREATION_FAILED, "Memory allocation error!");
        return NULL;
    }
    
    keystore->keystore_file = filename;
    keystore->keystore_password = password;
    keystore->other_certs = NULL;
    keystore->keystore = NULL;
    keystore->cert = NULL;
    keystore->pvt_key = NULL;
        
    if(!openssl_pkcs12_load(env, keystore->keystore_file, &keystore->keystore))
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_DEFAULT,
                          "Error loading pkcs12 keystore from file");
        return NULL;
    }
    
    if(!openssl_pkcs12_parse(
            env, 
            keystore->keystore_password, 
            keystore->keystore, 
            &pvt_key,
            &own_cert,
            &other_certs))
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_CREATION_FAILED, "PKCS12 Key Store Parsing failed.");
        AXIS2_FREE(env->allocator, keystore);
        return NULL;        
    }
    
    if(pvt_key)
    {
        keystore->pvt_key = openssl_pkey_create(env);
        openssl_pkey_populate(keystore->pvt_key, env, pvt_key, (axis2_char_t*)keystore->keystore_file, OPENSSL_PKEY_TYPE_PRIVATE_KEY);
    }
    
    if(own_cert)
    {
        pkcs12_keystore_populate_oxs_cert(env, own_cert);
    }
    
    if(other_certs)
    {
        keystore->other_certs = pkcs12_keystore_populate_cert_array(env, other_certs);
    }
    
    
    return keystore;    
}

axutil_array_list_t * AXIS2_CALL pkcs12_keystore_populate_cert_array(
    const axutil_env_t *env,
    STACK_OF(X509) *other_certs)
{
    int num = 0, i;
    axutil_array_list_t *cert_list = NULL;
    oxs_x509_cert_t *oxs_cert = NULL;
    X509 *cert = NULL;
    
    num = sk_X509_num(other_certs);    
    cert_list = axutil_array_list_create(env, num);
    
    for(i = 0; i < num; i++){
        cert = sk_X509_value(other_certs, i);
        oxs_cert = pkcs12_keystore_populate_oxs_cert(env, cert);
        if(oxs_cert)
        {
            if(!axutil_array_list_add(cert_list, env, (void *)oxs_cert))
                return NULL;
        }
    }
    
    return cert_list;
}

oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_populate_oxs_cert(
    const axutil_env_t *env, 
    X509 *cert_in)
{
    axis2_char_t *x509_cert_data = NULL;
    axis2_char_t *x509_cert_date = NULL;
    axis2_char_t *x509_cert_issuer = NULL;
    axis2_char_t *x509_cert_subject = NULL;
    axis2_char_t *x509_cert_finger = NULL;
    axis2_char_t *x509_cert_key_id = NULL;
    EVP_PKEY *pub_key = NULL;
    openssl_pkey_t *open_pubkey = NULL;
    oxs_x509_cert_t *cert_out = NULL;

    x509_cert_data = openssl_x509_get_cert_data(env, cert_in);
    x509_cert_date = openssl_x509_get_info(env, OPENSSL_X509_INFO_VALID_TO ,cert_in);
    x509_cert_issuer = openssl_x509_get_info(env, OPENSSL_X509_INFO_ISSUER ,cert_in);
    x509_cert_subject = openssl_x509_get_info(env, OPENSSL_X509_INFO_SUBJECT ,cert_in);
    x509_cert_finger = openssl_x509_get_info(env, OPENSSL_X509_INFO_FINGER, cert_in);
    x509_cert_key_id = openssl_x509_get_subject_key_identifier(env, cert_in);
    
    cert_out = oxs_x509_cert_create(env);
    if(!cert_out)
    {
        return NULL;
    }
    
    oxs_x509_cert_set_data(cert_out, env, x509_cert_data);
    oxs_x509_cert_set_date(cert_out, env, x509_cert_date);
    oxs_x509_cert_set_issuer(cert_out, env, x509_cert_issuer);
    oxs_x509_cert_set_subject(cert_out, env, x509_cert_subject);
    oxs_x509_cert_set_fingerprint(cert_out, env, x509_cert_finger);
    oxs_x509_cert_set_serial_number(cert_out, env, openssl_x509_get_serial(env, cert_in));
    oxs_x509_cert_set_key_identifier(cert_out, env, x509_cert_key_id);
    
    openssl_x509_get_pubkey(env, cert_in, &pub_key);
    open_pubkey = openssl_pkey_create(env);
    openssl_pkey_populate(open_pubkey, env, pub_key, x509_cert_finger, OPENSSL_PKEY_TYPE_PUBLIC_KEY);
    /*Set the public key to the x509 certificate*/
    oxs_x509_cert_set_public_key(cert_out, env, open_pubkey);
    
    return cert_out;
}

AXIS2_EXTERN openssl_pkey_t * AXIS2_CALL pkcs12_keystore_get_owner_private_key(
    pkcs12_keystore_t *keystore,
    const axutil_env_t *env)
{
    return keystore->pvt_key;
}

AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_owner_certificate(
    pkcs12_keystore_t *keystore, 
    const axutil_env_t *env)
{
    return keystore->cert;
}

AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_issuer_serial(
    pkcs12_keystore_t *keystore,
    const axutil_env_t *env,
    axis2_char_t *issuer,
    int serial_number)
{
    int i = 0;
    oxs_x509_cert_t *cert = NULL;
    
    if(!issuer || !(serial_number > 0))
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, 
                "Invalid arguments to get_certificate_for_issuer_serial.");
        return NULL;
    }
    
    if(keystore->other_certs){
        for(i = 0; i < axutil_array_list_size(keystore->other_certs, env); i++)
        {
            cert = (oxs_x509_cert_t *)axutil_array_list_get(keystore->other_certs, env, i);
            if(axutil_strcmp(oxs_x509_cert_get_issuer(cert, env), issuer) == 0 &&
                    (serial_number == oxs_x509_cert_get_serial_number(cert, env))){
                return cert;
            }
            
        }
    }
    
    return NULL;
    
}

AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_thumbprint(
    pkcs12_keystore_t *keystore, 
    const axutil_env_t *env, 
    axis2_char_t *thumbprint)
{
    int i = 0;
    oxs_x509_cert_t *cert = NULL;
    
    if(!thumbprint)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, 
                "Invalid arguments to get_certificate_for_issuer_serial.");
        return NULL;
    }
    
    if(keystore->other_certs){
        for(i = 0; i < axutil_array_list_size(keystore->other_certs, env); i++)
        {
            cert = (oxs_x509_cert_t *)axutil_array_list_get(keystore->other_certs, env, i);
            if(axutil_strcmp(oxs_x509_cert_get_fingerprint(cert, env), thumbprint) == 0){
                return cert;
            }
            
        }
    }
    
    return NULL;    
}

AXIS2_EXTERN oxs_x509_cert_t * AXIS2_CALL pkcs12_keystore_get_certificate_for_subject_key_id(
        pkcs12_keystore_t *keystore,
        const axutil_env_t *env,
        axis2_char_t *ski)
{
    int i = 0;
    oxs_x509_cert_t *cert = NULL;
    
    if(!ski)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, 
                "Invalid arguments to get_certificate_for_issuer_serial.");
        return NULL;
    }
    
    if(keystore->other_certs){
        for(i = 0; i < axutil_array_list_size(keystore->other_certs, env); i++)
        {
            cert = (oxs_x509_cert_t *)axutil_array_list_get(keystore->other_certs, env, i);
            if(axutil_strcmp(oxs_x509_cert_get_key_identifier(cert, env), ski) == 0){
                return cert;
            }
            
        }
    }
    
    return NULL; 
}
