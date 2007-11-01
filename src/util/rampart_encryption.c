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
#include <axutil_utils.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <rampart_encryption.h>
#include <oxs_key.h>
#include <rampart_constants.h>
#include <rampart_handler_util.h>
#include <oxs_tokens.h>
#include <axutil_array_list.h>
#include <oxs_axiom.h>
#include <oxs_asym_ctx.h>
#include <oxs_xml_encryption.h>
#include <oxs_derivation.h>
#include <axis2_key_type.h>
#include <oxs_derivation.h>

/*Private functions*/

axis2_status_t AXIS2_CALL
rampart_enc_get_nodes_to_encrypt(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt)
{

    axis2_status_t status1 = AXIS2_SUCCESS;
    axis2_status_t status2 = AXIS2_SUCCESS;

    status1 = rampart_context_get_nodes_to_encrypt(
                  rampart_context, env, soap_envelope, nodes_to_encrypt);

    status2 = rampart_context_get_elements_to_encrypt(
                  rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status1 == AXIS2_SUCCESS || status2 == AXIS2_SUCCESS)
    {
        return AXIS2_SUCCESS;
    }
    else
    {
        return AXIS2_FAILURE;
    }
}


/*Public functions*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_session_key(const axutil_env_t *env,
    oxs_key_t *session_key,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axutil_array_list_t *id_list)
{
    oxs_asym_ctx_t *asym_ctx = NULL;	
    axis2_char_t *enc_asym_algo = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    rp_property_type_t token_type;
    rampart_callback_t *password_callback = NULL;
    password_callback_fn password_function = NULL;
    axis2_char_t *eki = NULL;
    void *key_buf = NULL;
    void *param = NULL;
    axis2_char_t *certificate_file = NULL;
    axis2_char_t *password = NULL;
    axis2_char_t *enc_user = NULL;
    token = rampart_context_get_token(rampart_context, env,
                                      AXIS2_TRUE, server_side, AXIS2_FALSE);
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Specified token type not supported.");
        return AXIS2_FAILURE;
    }
    

    /*Get the asymmetric key encryption algorithm*/
    enc_asym_algo = rampart_context_get_enc_asym_algo(rampart_context, env);

    /*Get encryption key identifier*/
    /*First we should check whether we include the token in the
     *message.*/

    if(rampart_context_is_token_include(rampart_context,
                                        token, token_type, server_side, AXIS2_FALSE, env))
    {
        eki = RAMPART_STR_DIRECT_REFERENCE;
    }
    else
    {
        eki = rampart_context_get_key_identifier(rampart_context, token, env);
    }
    if(!eki)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] No mechanism for attaching the certificate info.");
        return AXIS2_FAILURE;
    }

    /*Create asymmetric encryption context*/
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, enc_asym_algo);

    /*First check whether the public key is set*/
    key_buf = rampart_context_get_receiver_certificate(rampart_context, env);
    if(key_buf)
    {
        axis2_key_type_t type = 0;
        type = rampart_context_get_receiver_certificate_type(rampart_context, env);
        if(type == AXIS2_KEY_TYPE_PEM)
        {
            oxs_asym_ctx_set_format(asym_ctx, env, OXS_ASYM_CTX_FORMAT_PEM);
            oxs_asym_ctx_set_pem_buf(asym_ctx, env, (axis2_char_t *)key_buf);
        }
    }

    /*Buffer is null load from the file*/
    else
    {
        certificate_file = rampart_context_get_receiver_certificate_file(
                               rampart_context, env);
        oxs_asym_ctx_set_file_name(asym_ctx, env, certificate_file);
        oxs_asym_ctx_set_format(asym_ctx, env,
                                oxs_util_get_format_by_file_extension(env, certificate_file));

        /*Get the password to retrieve the key from key store*/
        password = rampart_context_get_prv_key_password(rampart_context, env);

        if(!password)
        {
            enc_user = rampart_context_get_encryption_user(rampart_context, env);

            if(!enc_user)
            {
                enc_user = rampart_context_get_user(rampart_context, env);
            }

            if(enc_user)
            {
                password_function = rampart_context_get_pwcb_function(rampart_context, env);
                if(password_function)
                {
                    password = (*password_function)(env, enc_user, param);
                }

                else
                {
                    password_callback = rampart_context_get_password_callback
                                        (rampart_context, env);
                    if(!password_callback)
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[rampart][rampart_encryption] Password call back module is not loaded.");
                        return AXIS2_FAILURE;
                    }
                    password = rampart_callback_password(env, password_callback, enc_user);
                    if(password)
                    {
                        oxs_asym_ctx_set_password(asym_ctx, env, password);
                    }
                }
            }
        }
    }
    oxs_asym_ctx_set_operation(asym_ctx, env,
                               OXS_ASYM_CTX_OPERATION_PUB_ENCRYPT);
    oxs_asym_ctx_set_st_ref_pattern(asym_ctx, env, eki);

    /*Encrypt the session key*/
    status = oxs_xml_enc_encrypt_key(env, asym_ctx,
                                     sec_node, session_key, id_list);
    oxs_asym_ctx_free(asym_ctx, env);
    asym_ctx = NULL;
    
    if(AXIS2_FAILURE == status)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Session key encryption failed.");
        return AXIS2_FAILURE;
    }else{
	    return AXIS2_SUCCESS;
    }

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_dk_encrypt_message(const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{
    axis2_status_t status = AXIS2_FAILURE;
    oxs_key_t *session_key = NULL;
    axutil_array_list_t *nodes_to_encrypt = NULL;
    axutil_array_list_t *id_list = NULL;
    axutil_array_list_t *dk_list = NULL;
    axis2_char_t *enc_sym_algo = NULL;
    axis2_char_t *asym_key_id = NULL;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *sig_node = NULL;
    axis2_bool_t use_derived_keys = AXIS2_TRUE;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    axis2_bool_t signature_protection = AXIS2_FALSE;
    int i = 0;
    int j = 0;

    /*Get nodes to be encrypted*/
    nodes_to_encrypt = axutil_array_list_create(env, 0);
    status = rampart_enc_get_nodes_to_encrypt(
                 rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature] Error occured in Adding Encrypted parts..");
        axutil_array_list_free(nodes_to_encrypt, env);
        nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }
    
    /*If the sp:EncryptSignature is ON  &&  We sign before the encryption, we need to add signature node too. */
    signature_protection = rampart_context_is_encrypt_signature(
                               rampart_context, env);
    if(signature_protection)
    {
        if(!(rampart_context_is_encrypt_before_sign(rampart_context, env)))
        {
            /*Sign->Encrypt. Easy. just add the signature node to the list*/
            sig_node = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_SIGNATURE);
            if(!sig_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Sigature Not found");
                return AXIS2_FAILURE;
            }
            axutil_array_list_add(nodes_to_encrypt, env, sig_node);
        }
    }

    
    /*Get the symmetric encryption algorithm*/
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);

    /*If not specified set the default*/
    if(!enc_sym_algo ||  (0 == axutil_strcmp(enc_sym_algo, "")))
    {
        AXIS2_LOG_INFO(env->log,
                       "[rampart][rampart_encryption] No symmetric algorithm is specified for encryption. Using the default");
        enc_sym_algo = OXS_DEFAULT_SYM_ALGO;
    }

    session_key = rampart_context_get_session_key(rampart_context, env);
    if(!session_key){
        /*Generate the  session key*/
        session_key = oxs_key_create(env);
        rampart_context_set_session_key(rampart_context, env, session_key);
        status = oxs_key_for_algo(session_key, env, enc_sym_algo);
    }
 
    id_list = axutil_array_list_create(env, 5);
    dk_list = axutil_array_list_create(env, 5);
    /* For each and every encryption part.
        1. Derive a new key if key derivation is enabled. Or else use the same session key
        2. Encrypt using that key       
     */
   
    /*We need to take the decision whether to use derived keys or not*/
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_TRUE, server_side, AXIS2_FALSE);
    use_derived_keys = rampart_context_check_is_derived_keys (env, token);

    /*Repeat until all encryption parts are encrypted*/
    for(i=0 ; i < axutil_array_list_size(nodes_to_encrypt, env); i++)
    {
        axiom_node_t *node_to_enc = NULL;
        oxs_ctx_t *enc_ctx = NULL;
        oxs_key_t *derived_key = NULL;
        axis2_char_t *enc_data_id = NULL;
        axiom_node_t *parent_of_node_to_enc = NULL;
        axiom_node_t *enc_data_node = NULL;

        /*Get the node to be encrypted*/
        node_to_enc = (axiom_node_t *)axutil_array_list_get
                      (nodes_to_encrypt, env, i);
    
        /*Create the encryption context for OMXMLSEC*/
        enc_ctx = oxs_ctx_create(env);

        if(AXIS2_TRUE == use_derived_keys){
            /*Derive a new key*/
            derived_key = oxs_key_create(env);
            status = oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE); 
            
            /*Set the derived key for the encryption*/
            oxs_ctx_set_key(enc_ctx, env, derived_key);

            /*Set the ref key name to build KeyInfo element. Here the key name is the derived key id*/
            oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(derived_key, env));
            
            /*Add derived key to the list. We will create tokens*/
            axutil_array_list_add(dk_list, env, derived_key);
        }else{
            /*No key derivation. We use the same session key*/
            oxs_ctx_set_key(enc_ctx, env, session_key);
            oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(session_key, env));
        }
        /*Set the algorithm*/
        oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);  

        /*Generate ID for the encrypted data ielement*/       
        parent_of_node_to_enc = axiom_node_get_parent(node_to_enc, env);
        enc_data_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);
 
        if(parent_of_node_to_enc || enc_data_id)
        {
            enc_data_node = oxs_token_build_encrypted_data_element(env,
                            parent_of_node_to_enc, OXS_TYPE_ENC_ELEMENT, enc_data_id );
            status = oxs_xml_enc_encrypt_node(env, enc_ctx,
                                                  node_to_enc, &enc_data_node);
            /*Add Ids to the list. We will create reference list*/
            axutil_array_list_add(id_list, env, enc_data_id);

            if(AXIS2_FAILURE == status)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot encrypt the node " );
                return AXIS2_FAILURE;
            }

        }
        oxs_ctx_free(enc_ctx, env);
        enc_ctx = NULL;
        
    }/*End of for loop. Iterating nodes_to_encrypt list*/
    
    /*Free node list*/
    axutil_array_list_free(nodes_to_encrypt, env);
    nodes_to_encrypt = NULL;

    /* If not done already, Encrypt the session key using the Public Key of the recipient*/
    /* Note: Here we do not send the id_list to create a ReferenceList inside the encrypted key. Instead we create the 
     *       ReferenceList as a child of Security element */
            
    encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
    if(!encrypted_key_node){
        /*Create EncryptedKey element*/
        status = rampart_enc_encrypt_session_key(env, session_key, msg_ctx, rampart_context, soap_envelope, sec_node, NULL );
        if(AXIS2_FAILURE == status){
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot encrypt the session key " );
            return AXIS2_FAILURE;
        }
        /*Now we have en EncryptedKey Node*/
        encrypted_key_node = oxs_axiom_get_node_by_local_name(env, sec_node,  OXS_NODE_ENCRYPTED_KEY);

        /*Get the asym key Id*/
        if(!encrypted_key_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
            return AXIS2_FAILURE;
        }
        asym_key_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCKEY_ID);
        if(asym_key_id)
        {
            oxs_axiom_add_attribute(env, encrypted_key_node, NULL,
                                NULL, OXS_ATTR_ID, asym_key_id);
        }
    }else{
        /*OK Buddy we have already created EncryptedKey node. Get the Id */
        asym_key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
    }
    /*Add used <wsc:DerivedKeyToken> elements to the header*/
    for(j=0 ; j < axutil_array_list_size(dk_list, env); j++){
        oxs_key_t *dk = NULL;
        
        dk = (oxs_key_t *)axutil_array_list_get(dk_list, env, j);
        
        /*Build the <wsc:DerivedKeyToken> element*/
        if(dk){
            oxs_derivation_build_derived_key_token(env, dk, sec_node, asym_key_id, OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY);
        }
        /*Do we need derived keys? Can we free 'em here?*/
        oxs_key_free(dk, env);
        dk = NULL;
    
    }/*End of For loop of dk_list iteration*/
    
    /*Free derrived key list*/
    axutil_array_list_free(dk_list, env);
    dk_list = NULL;
 
    /*Add ReferenceList element to the Security header*/
    status = oxs_token_build_data_reference_list(env, sec_node, id_list);

    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_message(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    axutil_array_list_t *nodes_to_encrypt = NULL;
    axutil_array_list_t *id_list = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *enc_sym_algo = NULL;
    oxs_key_t *session_key = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_type_t token_type;
    rp_property_t *token = NULL;
    int i = 0;
    axis2_bool_t signature_protection = AXIS2_FALSE;
    axiom_node_t *sig_node = NULL;


    /*Get nodes to be encrypted*/

    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    nodes_to_encrypt = axutil_array_list_create(env, 0);

    signature_protection = rampart_context_is_encrypt_signature(
                               rampart_context, env);

    status = rampart_enc_get_nodes_to_encrypt(
                 rampart_context, env, soap_envelope, nodes_to_encrypt);

    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_signature]Error occured in Adding Encrypted parts..");
        axutil_array_list_free(nodes_to_encrypt, env);
        nodes_to_encrypt = NULL;
        return AXIS2_FAILURE;
    }

    if((axutil_array_list_size(nodes_to_encrypt, env)==0))
    {
        if(!signature_protection)
        {
            AXIS2_LOG_INFO(env->log,
                           "[rampart][rampart_encryption] No parts specified or specified parts can't be found for encryprion.");
            return AXIS2_SUCCESS;
        }
    }

    if(signature_protection)
    {
        if(!(rampart_context_is_encrypt_before_sign(rampart_context, env)))
        {
            sig_node = oxs_axiom_get_node_by_local_name(env, sec_node, OXS_NODE_SIGNATURE);
            if(!sig_node)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Sigature Not found");
                return AXIS2_FAILURE;
            }
            axutil_array_list_add(nodes_to_encrypt, env, sig_node);
        }
    }

    /*Now we have to check whether a token is specified.*/
    token = rampart_context_get_token(rampart_context, env,
                                      AXIS2_TRUE, server_side, AXIS2_FALSE);
    if(!token)
    {
        AXIS2_LOG_INFO(env->log,
                       "[rampart][rampart_encryption]Encryption Token is not specified");
        return AXIS2_SUCCESS;
    }
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Specified token type not supported.");
        return AXIS2_FAILURE;
    }
    if(rampart_context_check_is_derived_keys(env,token))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]We still do not support derived keys");
        return AXIS2_FAILURE;
    }

    /*Get the symmetric encryption algorithm*/
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);

    /*If not specified set the default*/
    if(!enc_sym_algo ||  (0 == axutil_strcmp(enc_sym_algo, "")))
    {
        AXIS2_LOG_INFO(env->log,
                       "[rampart][rampart_encryption]No symmetric algorithm is specified for encryption. Using the default");
        enc_sym_algo = OXS_DEFAULT_SYM_ALGO;
    }

    session_key = rampart_context_get_session_key(rampart_context, env);
    if(!session_key){
        /*Generate the  session key*/
         session_key = oxs_key_create(env);
         status = oxs_key_for_algo(session_key, env, enc_sym_algo);
         rampart_context_set_session_key(rampart_context, env, session_key);
    }
    if(AXIS2_FAILURE == status)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Cannot generate the key for the algorithm %s, ", enc_sym_algo);
        return AXIS2_FAILURE;
    }

    /*Key will be duplicated inside the function. So no worries freeing it here*/
    if(rampart_context_is_encrypt_before_sign(rampart_context, env)
            && signature_protection)
    {
        rampart_context_set_session_key(rampart_context, env, session_key);
    }

    /*Create a list to store EncDataIds. This will be used in building the ReferenceList*/

    id_list = axutil_array_list_create(env, 5);

    /*Repeat until all encryption parts are encrypted*/
    for(i=0 ; i < axutil_array_list_size(nodes_to_encrypt, env); i++)
    {
        axiom_node_t *node_to_enc = NULL;
        axiom_node_t *parent_of_node_to_enc = NULL;
        axiom_node_t *enc_data_node = NULL;
        oxs_ctx_t *enc_ctx = NULL;
        axis2_char_t *id = NULL;
        axis2_status_t enc_status = AXIS2_FAILURE;

        /*Get the node to be encrypted*/
        node_to_enc = (axiom_node_t *)axutil_array_list_get
                      (nodes_to_encrypt, env, i);
        if(!node_to_enc)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] Cannot get the node from the list to encrypt");
            return AXIS2_FAILURE;
        }
        /*Create the encryption context for OMXMLSEC*/
        enc_ctx = oxs_ctx_create(env);
        /*Set the key*/
        oxs_ctx_set_key(enc_ctx, env, session_key);
        /*Set the algorithm*/
        oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);
        /*Create an empty EncryptedDataNode*/
        parent_of_node_to_enc = axiom_node_get_parent(node_to_enc, env);
        id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);

        if(parent_of_node_to_enc || id)
        {
            enc_data_node = oxs_token_build_encrypted_data_element(env,
                            parent_of_node_to_enc, OXS_TYPE_ENC_ELEMENT, id );
            enc_status = oxs_xml_enc_encrypt_node(env, enc_ctx,
                                                  node_to_enc, &enc_data_node);
            axutil_array_list_add(id_list, env, id);
            if(AXIS2_FAILURE == enc_status)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption] Cannot encrypt the node " );
                return AXIS2_FAILURE;
            }
        }
        oxs_ctx_free(enc_ctx, env);
        enc_ctx = NULL;

    }/*Eof For loop*/

    /*TODO free list*/
    axutil_array_list_free(nodes_to_encrypt, env);
    nodes_to_encrypt = NULL;

    /*We need to encrypt the session key.*/
    status = rampart_enc_encrypt_session_key(env, session_key, msg_ctx, rampart_context, soap_envelope, sec_node, id_list);
    if(AXIS2_FAILURE == status){
        return AXIS2_FAILURE;
    }
    /*Free id_list*/
    if(id_list)
    {
        int size = 0;
        int j = 0;
        size = axutil_array_list_size(id_list, env);
        for (j = 0; j < size; j++)
        {
            axis2_char_t *id = NULL;

            id = axutil_array_list_get(id_list, env, j);
            AXIS2_FREE(env->allocator, id);
            id = NULL;
        }
        axutil_array_list_free(id_list, env);
        id_list = NULL;
    }



    /*oxs_key_free(session_key, env);
    session_key = NULL;*/

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_add_key_info(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    axis2_char_t *key_id = NULL;
    axiom_node_t *key_info_node = NULL;
    axiom_node_t *str_node = NULL;
    axiom_node_t *reference_node = NULL;

    axiom_node_t *encrypted_data_node = NULL;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *body_node = NULL;
    axiom_soap_body_t *body = NULL;

    axiom_element_t *body_ele = NULL;
    axiom_element_t *encrypted_data_ele = NULL;

    encrypted_key_node = oxs_axiom_get_node_by_local_name(
                             env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
    if(!encrypted_key_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
        return AXIS2_FAILURE;
    }

    key_id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCKEY_ID);

    if(key_id)
    {
        oxs_axiom_add_attribute(env, encrypted_key_node, NULL/*OXS_WSU*/,
                                NULL/*RAMPART_WSU_XMLNS*/, OXS_ATTR_ID, key_id);
    }

    body = axiom_soap_envelope_get_body(soap_envelope, env);
    body_node = axiom_soap_body_get_base_node(body, env);

    body_ele = (axiom_element_t *)
               axiom_node_get_data_element(body_node, env);

    encrypted_data_ele = axiom_util_get_first_child_element_with_localname(
                             body_ele, env, body_node, OXS_NODE_ENCRYPTED_DATA, &encrypted_data_node);

    if(encrypted_data_ele)
    {
        key_info_node = oxs_token_build_key_info_element(
                            env, encrypted_data_node);
        if(key_info_node)
        {
            str_node = oxs_token_build_security_token_reference_element(
                           env, key_info_node);
            if(str_node)
            {
                axis2_char_t *key_id_ref = NULL;
                key_id_ref = axutil_stracat(env, "#",key_id);
                reference_node = oxs_token_build_reference_element(
                                     env, str_node, key_id_ref, NULL);
                AXIS2_FREE(env->allocator, key_id_ref);
                key_id_ref = NULL;
				AXIS2_FREE(env->allocator, key_id);
				key_id = NULL;

                if(!reference_node)
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][rampart_encryption]Encrypting signature, Reference Node build failed");
                    return AXIS2_FAILURE;
                }
                else
                {
                    return AXIS2_SUCCESS;
                }
            }
            else{
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Cannot build the STR node");
				AXIS2_FREE(env->allocator, key_id);
				key_id = NULL;
                return AXIS2_FAILURE;
            }
        }
        else{
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][rampart_encryption] Encrypting signature, cannot build the key indfo node");
			AXIS2_FREE(env->allocator, key_id);
			key_id = NULL;
            return AXIS2_FAILURE;
        }
    }
    else{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, Cannot get the encryption data element");
		AXIS2_FREE(env->allocator, key_id);
		key_id = NULL;
        return AXIS2_FAILURE;
    }
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_enc_encrypt_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node)
{

    oxs_key_t *session_key = NULL;
    oxs_key_t *derived_key = NULL;
    axiom_node_t *node_to_enc = NULL;
    axiom_node_t *enc_data_node = NULL;
    oxs_ctx_t *enc_ctx = NULL;
    axis2_char_t *id = NULL;
    axis2_status_t enc_status = AXIS2_FAILURE;
    axis2_char_t *enc_sym_algo = NULL;
    axutil_array_list_t *id_list = NULL;
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *temp_node = NULL;
    axiom_node_t *node_to_move = NULL;
    axis2_bool_t use_derived_keys = AXIS2_TRUE;
    axis2_bool_t server_side = AXIS2_FALSE;
    rp_property_t *token = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    session_key = rampart_context_get_session_key(rampart_context, env);

    if(!session_key)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting Signature.Session key not found");
        return AXIS2_FAILURE;
    }
    /*Get <ds:Signature> node*/
    node_to_enc = oxs_axiom_get_node_by_local_name(
                      env, sec_node, OXS_NODE_SIGNATURE);

    if(!node_to_enc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting Signature. Signature node not found");
        return AXIS2_FAILURE;
    }

    encrypted_key_node = oxs_axiom_get_node_by_local_name(
                             env, sec_node,  OXS_NODE_ENCRYPTED_KEY);
    if(!encrypted_key_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature, EncryptedKey Not found");
        return AXIS2_FAILURE;
    }

    enc_ctx = oxs_ctx_create(env);

    /*We need to take the decision whether to use derived keys or not*/
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    token = rampart_context_get_token(rampart_context, env, AXIS2_TRUE, server_side, AXIS2_FALSE);
    use_derived_keys = rampart_context_check_is_derived_keys (env, token);
    if(AXIS2_TRUE == use_derived_keys){
            /*Derive a new key*/
            derived_key = oxs_key_create(env);
            status = oxs_derivation_derive_key(env, session_key, derived_key, AXIS2_TRUE);

            /*Set the derived key for the encryption*/
            oxs_ctx_set_key(enc_ctx, env, derived_key);

            /*Set the ref key name to build KeyInfo element. Here the key name is the derived key id*/
            oxs_ctx_set_ref_key_name(enc_ctx, env, oxs_key_get_name(derived_key, env));
    }else{
        /*No Key derivation is needed we will proceed with the same session key*/
        oxs_ctx_set_key(enc_ctx, env, session_key);
    }
    enc_sym_algo = rampart_context_get_enc_sym_algo(rampart_context, env);
    oxs_ctx_set_enc_mtd_algorithm(enc_ctx, env, enc_sym_algo);
    id = oxs_util_generate_id(env, (axis2_char_t*)OXS_ENCDATA_ID);
    enc_data_node = oxs_token_build_encrypted_data_element(
                        env, sec_node, OXS_TYPE_ENC_ELEMENT, id );
    enc_status = oxs_xml_enc_encrypt_node(
                     env, enc_ctx, node_to_enc, &enc_data_node);

    /*FREE*/
    oxs_ctx_free(enc_ctx, env);
    enc_ctx = NULL;

    if(enc_status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption] Encrypting node failed");
        return AXIS2_FAILURE;
    }
    /*If we have used a derrived key, we need to attach it to the Securuty Header*/
    if(AXIS2_TRUE == use_derived_keys){
        axis2_char_t *asym_key_id = NULL;
 
        asym_key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
        oxs_derivation_build_derived_key_token(env, derived_key, sec_node, asym_key_id, OXS_WSS_11_VALUE_TYPE_ENCRYPTED_KEY);  
    }

    node_to_move = oxs_axiom_get_node_by_local_name(
                       env, sec_node,  OXS_NODE_REFERENCE_LIST);

    if(node_to_move)
    {
        temp_node = axiom_node_detach(node_to_move, env);
        if(temp_node)
        {
            enc_status = axiom_node_insert_sibling_after(
                             enc_data_node, env, temp_node);
            if(enc_status != AXIS2_SUCCESS)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][rampart_encryption]Encrypting signature, Node moving failed.");
                return AXIS2_FAILURE;
            }
        }
    }

    id_list = axutil_array_list_create(env, 0);

    axutil_array_list_add(id_list, env, id);

    enc_status = oxs_token_build_data_reference_list(
                     env, encrypted_key_node, id_list);
    if(enc_status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rampart_encryption]Encrypting signature,Building reference list failed");
        return AXIS2_FAILURE;
    }

    if(id_list){
        /*TODO need to free data of the list*/
        int size = 0;
        int j = 0;
        size = axutil_array_list_size(id_list, env);
        for (j = 0; j < size; j++)
        {
            axis2_char_t *id_temp = NULL;

            id_temp = axutil_array_list_get(id_list, env, j);
            AXIS2_FREE(env->allocator, id_temp);
            id_temp = NULL;
        }

        axutil_array_list_free(id_list, env);
        id_list = NULL;
    }
    return AXIS2_SUCCESS;
}
