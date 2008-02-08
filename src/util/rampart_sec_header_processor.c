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
#include <rampart_encryption.h>
#include <rampart_constants.h>
#include <rampart_sec_header_processor.h>
#include <rampart_username_token.h>
#include <rampart_timestamp_token.h>
#include <rampart_util.h>
#include <rampart_sec_processed_result.h>
#include <rampart_handler_util.h>
#include <rampart_token_processor.h>
#include <rampart_policy_validator.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_key.h>
#include <oxs_axiom.h>
#include <oxs_asym_ctx.h>
#include <oxs_tokens.h>
#include <oxs_derivation.h>
#include <axutil_utils.h>
#include <axutil_array_list.h>
#include <axis2_key_type.h>
#include <oxs_sign_ctx.h>
#include <oxs_xml_signature.h>
#include <oxs_key_mgr.h>
#include <rampart_replay_detector.h>
#include <saml.h>
#include <rampart_saml.h>
#include <rampart_saml_token.h>
/*Private functions*/

/*Process a KeyInfo and return the reference value*/
static axis2_char_t *
rampart_shp_process_key_info_for_ref_val(const axutil_env_t *env,
                            axiom_node_t *key_info_node)
{
    axiom_node_t *str_node = NULL;
    axiom_node_t *ref_node = NULL;
    axis2_char_t *ref_val = NULL;
    axis2_char_t *id = NULL;

    /*Get the STR*/
    str_node = oxs_axiom_get_first_child_node_by_name(env, key_info_node, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);

    /*Get Reference element*/
    if(str_node){
        ref_node = oxs_axiom_get_first_child_node_by_name(env, str_node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);

        /*Get the reference value in the @URI*/
        if(ref_node){
            ref_val = oxs_token_get_reference(env, ref_node);
            /*Need to remove # sign from the ID*/
            id = axutil_string_substring_starting_at(ref_val, 1);
        }
    }
    return id;
}

static axis2_bool_t
rampart_shp_validate_qnames(const axutil_env_t *env,
                            axiom_node_t *node)

{
    axiom_element_t *node_ele = NULL;
    axutil_qname_t *qname = NULL;
    axutil_qname_t *node_qname = NULL;
    axis2_char_t *local_name = NULL;

    AXIS2_ENV_CHECK(env,AXIS2_FALSE);

    node_ele = axiom_node_get_data_element(node, env);
    if(!node_ele)
        return AXIS2_FALSE;

    local_name = axiom_element_get_localname(node_ele,env);
    if(!local_name){
        return AXIS2_FALSE;
    }
    if(axutil_strcmp(local_name, RAMPART_SECURITY_TIMESTAMP) == 0)
    {
        qname = axutil_qname_create(env, local_name, RAMPART_WSU_XMLNS, NULL/*RAMPART_WSU*/);
    }
    else if(axutil_strcmp(local_name, RAMPART_SECURITY_USERNAMETOKEN) ==0)
    {
        qname = axutil_qname_create(env, local_name, RAMPART_WSSE_XMLNS, NULL/*RAMPART_WSSE*/);
    }
    else if(axutil_strcmp(local_name,OXS_NODE_ENCRYPTED_KEY)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_ENC_NS, NULL/*OXS_XENC*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_ENCRYPTED_DATA)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_ENC_NS, NULL/*OXS_XENC*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_SIGNATURE)==0)
    {
        qname = axutil_qname_create(env, local_name, OXS_DSIG_NS, NULL/*OXS_DS*/);
    }
    else if(axutil_strcmp(local_name, OXS_NODE_BINARY_SECURITY_TOKEN) == 0)
    {
        return AXIS2_FALSE;
    }
    else if(axutil_strcmp(local_name, OXS_NODE_REFERENCE_LIST)==0)
    {
        return AXIS2_FALSE;
    }
    else
    {
        return AXIS2_FALSE;
    }

    if(!qname)
    {
        return AXIS2_FALSE;
    }
    node_qname = axiom_element_get_qname(node_ele, env, node);

    if(!node_qname)
    {
        axutil_qname_free(qname, env);
        qname = NULL;
        return AXIS2_FALSE;
    }

    if(axutil_qname_equals(qname, env, node_qname))
    {
        axutil_qname_free(qname, env);
        qname = NULL;
        return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}

static oxs_x509_cert_t *get_receiver_x509_cert(
    const axutil_env_t *env,
    rampart_context_t *rampart_context)
{

    axis2_char_t *file_name = NULL;
    axis2_char_t *pem_buf = NULL;

    pem_buf = (axis2_char_t *)rampart_context_get_receiver_certificate(
                  rampart_context, env);
    if(pem_buf)
    {
        return oxs_key_mgr_load_x509_cert_from_string(env, pem_buf);
    }
    else
    {
        file_name = rampart_context_get_receiver_certificate_file(rampart_context, env);
        if(!file_name)
        {
            return NULL;
        }
        else
        {
            return oxs_key_mgr_load_x509_cert_from_pem_file(env, file_name);
        }
    }
}

static axis2_status_t
rampart_shp_process_signature_confirmation(const axutil_env_t *env,
                                   axis2_msg_ctx_t *msg_ctx,
                                   rampart_context_t *rampart_context,
                                   axiom_node_t *cur_node)
{
    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_CONFIRM_FOUND, RAMPART_YES);
    return AXIS2_SUCCESS;
}

static axis2_status_t
rampart_shp_process_timestamptoken(const axutil_env_t *env,
                                   axis2_msg_ctx_t *msg_ctx,
                                   rampart_context_t *rampart_context,
                                   axiom_node_t *sec_node)
{
    axis2_status_t valid_ts = AXIS2_FAILURE;
    axiom_node_t *ts_node = NULL;
    ts_node = oxs_axiom_get_first_child_node_by_name(env, sec_node, RAMPART_SECURITY_TIMESTAMP, OXS_WSU_XMLNS, NULL);
    if(!ts_node)
    {
        if(rampart_context_is_include_timestamp(rampart_context, env))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Timestamp is not in the message");
            rampart_create_fault_envelope(env, RAMPART_FAULT_SECURITY_TOKEN_UNAVAILABLE,
                                          "Timestamp is not in the message ", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
            return AXIS2_FAILURE;
        }

        else
        {
            return AXIS2_SUCCESS;
        }
    }
    else if(!rampart_context_is_include_timestamp(rampart_context, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Timestamp should not be in the message.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                      "Timestamp should not be in the message ", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
        return AXIS2_FAILURE;
    }
    else
    {
        if(!rampart_shp_validate_qnames(env, ts_node))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Error in the Timestamp element.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                          "Error in the Timestamp Element. ", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
            return AXIS2_FAILURE;
        }


        valid_ts = rampart_timestamp_token_validate(env, msg_ctx, ts_node);

        if (valid_ts)
        {
            AXIS2_LOG_INFO(env->log, "[rampart][scp] Succesfully validated the timestamp ");
            return AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][scp] Timestamp is not valid");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Timestamp is not valid", RAMPART_FAULT_IN_TIMESTAMP, msg_ctx);
            return AXIS2_FAILURE;
        }
    }
}

static axis2_status_t
rampart_shp_process_usernametoken(const axutil_env_t *env,
                                  axis2_msg_ctx_t *msg_ctx,
                                  rampart_context_t *rampart_context,
                                  axiom_node_t *sec_node)
{
    axis2_status_t valid_user = AXIS2_FAILURE;
    axiom_node_t *ut_node = NULL;
    ut_node = oxs_axiom_get_first_child_node_by_name(env, sec_node, RAMPART_SECURITY_USERNAMETOKEN, OXS_WSSE_XMLNS, NULL);
    if(!ut_node)
    {
        if(rampart_context_is_include_username_token(rampart_context, env))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Username token is not in the message");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION,
                                          "Username Token not found", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
            return AXIS2_FAILURE;
        }
        else
        {
            return AXIS2_SUCCESS;
        }
    }
    else if(!rampart_context_is_include_username_token(rampart_context, env))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Username token should not be in the message.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                      "Username Token not expected", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);

        return AXIS2_FAILURE;
    }
    else
    {
        if(!rampart_shp_validate_qnames(env, ut_node))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Error in validating qnames for the username token");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                          "Error in the Username token.", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);

            return AXIS2_FAILURE;
        }

        AXIS2_LOG_INFO(env->log, "[rampart][shp] Validating UsernameToken");
        valid_user = rampart_username_token_validate(env,
                     msg_ctx, ut_node, rampart_context);
    }
    if (valid_user)
    {
        AXIS2_LOG_INFO(env->log, "[rampart][shp] Validating UsernameToken SUCCESS");
        return AXIS2_SUCCESS;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Validating UsernameToken FAILED");

        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION,
                                          "UsernameToken validation failed.", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
        }
        return AXIS2_FAILURE;
    }
}

static axis2_status_t
rampart_shp_process_encrypted_key(const axutil_env_t *env,
                                  axis2_msg_ctx_t *msg_ctx,
                                  rampart_context_t *rampart_context,
                                  axiom_soap_envelope_t *soap_envelope,
                                  axiom_node_t *sec_node,
                                  axiom_node_t *encrypted_key_node)
{
    axiom_node_t *ref_list_node = NULL;
    axiom_node_t *enc_mtd_node = NULL;
    axutil_array_list_t *reference_list = NULL;
    axis2_char_t *enc_asym_algo = NULL;
    axis2_char_t *prv_key_file = NULL;
    axis2_char_t *password = NULL;
    axis2_char_t *enc_user = NULL;
    rampart_callback_t *password_callback = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    oxs_asym_ctx_t *asym_ctx = NULL;
    oxs_key_t *decrypted_sym_key = NULL;
    axis2_char_t *enc_asym_algo_in_pol = NULL;
    axis2_char_t *enc_sym_algo_in_pol = NULL;
    password_callback_fn password_function = NULL;
    void *param = NULL;
    int i = 0;
    void *key_buf = NULL;

    /*Get EncryptedData references */
    ref_list_node = oxs_axiom_get_first_child_node_by_name(
                        env, encrypted_key_node, OXS_NODE_REFERENCE_LIST, OXS_ENC_NS, NULL);
    reference_list = oxs_token_get_reference_list_data(env, ref_list_node);

    /*Get the algorithm to decrypt the sesison key*/
    enc_mtd_node = oxs_axiom_get_first_child_node_by_name(
                       env, encrypted_key_node, OXS_NODE_ENCRYPTION_METHOD, OXS_ENC_NS, NULL);
    enc_asym_algo = oxs_token_get_encryption_method(env, enc_mtd_node);

    /*If the reference list > 0 then We have nodes to decrypt. Next step is to get the encrypted key*/
    /*Obtain the session key which is encrypted*/
    /*Create an asym_ctx*/
    /*We should verify the algorithm with policy*/

    enc_asym_algo_in_pol = rampart_context_get_enc_asym_algo(rampart_context, env);
    if(!enc_asym_algo_in_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Error in the policy. No asym algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Assymetric enc algorithm not specified in policy.");
        return AXIS2_FAILURE;
    }

    /*If the algo tally with the policy?*/
    if(axutil_strcmp(enc_asym_algo_in_pol, enc_asym_algo) != 0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "The key is encrypted with the wrong algorithm");
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "The key is encrypted with the wrong algorithm", RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
        return AXIS2_FAILURE;
    }
    
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, enc_asym_algo);

    key_buf = rampart_context_get_prv_key(rampart_context, env);
    if(key_buf)
    {
        axis2_key_type_t type = 0;
        type = rampart_context_get_prv_key_type(rampart_context, env);
        if(type == AXIS2_KEY_TYPE_PEM)
        {
            oxs_asym_ctx_set_pem_buf(asym_ctx, env, (axis2_char_t *)key_buf);
            oxs_asym_ctx_set_format(asym_ctx, env, OXS_ASYM_CTX_FORMAT_PEM);
        }
    }
    else
    {
        prv_key_file = rampart_context_get_private_key_file(rampart_context, env);
        if(!prv_key_file)
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Error in the policy. No private key", RAMPART_FAULT_IN_POLICY, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Private Key is not specified.");
            return AXIS2_FAILURE;
        }
        oxs_asym_ctx_set_file_name(asym_ctx, env, prv_key_file);
        oxs_asym_ctx_set_format(asym_ctx, env,
                                oxs_util_get_format_by_file_extension(env, prv_key_file));

        /*Get the password to retrieve the key from key store*/
        /*  password = rampart_callback_encuser_password(env, actions, msg_ctx);*/

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
                    password_callback = rampart_context_get_password_callback(rampart_context, env);
                    if(!password_callback)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                                      "Error in the policy. No password callback", RAMPART_FAULT_IN_POLICY, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[rampart][shp] Password call back module is not specified.");

                        return AXIS2_FAILURE;
                    }
                    password = rampart_callback_password(env, password_callback, enc_user);
                }
            }
        }
        oxs_asym_ctx_set_password(asym_ctx, env, password);
    }
    oxs_asym_ctx_set_operation(asym_ctx, env, OXS_ASYM_CTX_OPERATION_PRV_DECRYPT);

    /*Create an empty key*/
    decrypted_sym_key = oxs_key_create(env);

    /*Call decrypt for the EncryptedKey*/
    status = oxs_xml_enc_decrypt_key(env, asym_ctx,
                                     sec_node, encrypted_key_node,  decrypted_sym_key);


    if(AXIS2_FAILURE == status)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Cannot decrypt the EncryptedKey");
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Key decryption failed", RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
        return AXIS2_FAILURE;
    }
    /*We need to set the session key name= EncryptedKey@Id*/
    if(decrypted_sym_key){
        axis2_char_t *key_id = NULL;

        key_id = oxs_axiom_get_attribute_value_of_node_by_name(env, encrypted_key_node, OXS_ATTR_ID, NULL);
        if(!key_id){
            key_id = "SESSION_KEY";
        }
        
        oxs_key_set_name(decrypted_sym_key, env, key_id);
    }
    /*Now we need to set this to the rampart context for future use*/
    rampart_context_set_session_key(rampart_context, env, decrypted_sym_key);

    /*Alright now we have the key used to encrypt the elements in the reference_list*/
    /*Go thru each and every node in the list and decrypt them*/

    /*Before decrypt we should get the symmetric algo from policy.
      So for each encrypted element we can compare the algo. */
    enc_sym_algo_in_pol = rampart_context_get_enc_sym_algo(rampart_context, env);
    if(!enc_sym_algo_in_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                      "Error in the policy. No summetric algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Symetric enc algorithm not specified in policy.");
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
        return AXIS2_FAILURE;
    }
    
    /* In some cases there might not be any references in the list. For example when the derived keys are in use. 
     * If there are references, that means those references are encrypted using the session key. So we need to decrypt 'em*/
    if(reference_list){
      for(i=0 ; i < axutil_array_list_size(reference_list, env); i++ )
      {
        axis2_char_t *id = NULL;
        axis2_char_t *id2 = NULL;
        axiom_node_t *enc_data_node = NULL;
        axiom_node_t *envelope_node = NULL;
        oxs_ctx_t *ctx = NULL;
        axiom_node_t *decrypted_node = NULL;
        axiom_node_t *mtd_node = NULL;
        axis2_char_t *sym_algo = NULL;
        axiom_soap_body_t *soap_body = NULL;

        /*This need to be done in order to build the soap body.Do not remove.*/
        soap_body = axiom_soap_envelope_get_body(soap_envelope, env);

        /*Get the i-th element and decrypt it */
        id = (axis2_char_t*)axutil_array_list_get(reference_list, env, i);
        AXIS2_LOG_INFO(env->log, "[rampart][shp] Decrypting node, ID=%s", id);

        /*Need to remove # sign from the ID*/
        id2 = axutil_string_substring_starting_at(id, 1);
        envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);

        /*Search for the node by its ID*/
        enc_data_node = oxs_axiom_get_node_by_id(env, envelope_node, OXS_ATTR_ID, id2, NULL);
        if(!enc_data_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Node with ID=%s cannot be found", id);

            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptedData element", 
                                        RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }
        /*Create an enc_ctx*/
        mtd_node = oxs_axiom_get_first_child_node_by_name(
                       env, enc_data_node, OXS_NODE_ENCRYPTION_METHOD, OXS_ENC_NS, NULL);

        if(!mtd_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot find EncryptionMethod Element");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptionMethod Element", 
                                    RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }

        sym_algo = oxs_token_get_encryption_method(env, mtd_node);
        if(!sym_algo)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the Symmetric Algorithm from Soap message.");
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Cannot find EncryptionMethod Element", 
                            RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;

            return AXIS2_FAILURE;
        }
        /*Would the encryption method tally with the policy?*/
        if(axutil_strcmp(sym_algo, enc_sym_algo_in_pol)!=0)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "The content is encrypted with the wrong algorithm");
            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                          "The content is encrypted with the wrong algorithm",
                                          RAMPART_FAULT_IN_ENCRYPTED_KEY, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;

        }
        /*Get ready for the decryption. Create an encryption ctx*/
        ctx = oxs_ctx_create(env);
        oxs_ctx_set_key(ctx, env, decrypted_sym_key);
        status = oxs_xml_enc_decrypt_node(env, ctx, enc_data_node, &decrypted_node);

        if(AXIS2_FAILURE == status)
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Data decryption failed", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            oxs_asym_ctx_free(asym_ctx, env);
            asym_ctx = NULL;
            return AXIS2_FAILURE;
        }
        /*Check if the signture is encrypted*/
        if(0 == axutil_strcmp( OXS_NODE_SIGNATURE , axiom_util_get_localname(decrypted_node, env))){
            rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_ENCRYPTED, RAMPART_YES);
        }
        /*Check if the body is encrypted*/
        if(0 == axutil_strcmp(OXS_NODE_BODY , axiom_util_get_localname(axiom_node_get_parent(decrypted_node, env), env))){
             rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_BODY_ENCRYPTED, RAMPART_YES);
        }

        /*Free*/
        oxs_ctx_free(ctx, env);
        ctx = NULL;

        AXIS2_LOG_INFO(env->log, "[rampart][shp] Node ID=%s decrypted successfuly", id);
      }/*end of For loop*/
    }

    /*Set the security processed result*/
    rampart_set_security_processed_result(
        env, msg_ctx, RAMPART_SPR_ENC_CHECKED, RAMPART_YES);

    /*Free*/
    if(asym_ctx){
        oxs_asym_ctx_free(asym_ctx, env);
        asym_ctx = NULL;
    }

    if(decrypted_sym_key)
    {
        oxs_key_free(decrypted_sym_key, env);
        decrypted_sym_key = NULL;
    }

    if(reference_list){
        axutil_array_list_free(reference_list, env);
        reference_list = NULL;
    }
    return AXIS2_SUCCESS;
}


static axis2_status_t
rampart_shp_process_reference_list(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *ref_list_node)
{

    axutil_array_list_t *reference_list = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    int i = 0;

    reference_list = oxs_token_get_reference_list_data(env,
                     ref_list_node);

    if((!reference_list) || (0 == axutil_array_list_size(reference_list, env)))
    {
        if (reference_list)
        {
            axutil_array_list_free(reference_list, env);
            reference_list = NULL;
        }

        AXIS2_LOG_INFO(env->log,
                       "[rampart][shp] Nothing Encrypted Outside security header");
        return AXIS2_SUCCESS;
    }
    /*Go thru each and every element in the ReferenceList*/
    for(i=0 ; i < axutil_array_list_size(reference_list, env); i++ )
    {
        axis2_char_t *id = NULL;
        axis2_char_t *id2 = NULL;
        axiom_node_t *enc_data_node = NULL;
        axiom_node_t *envelope_node = NULL;
        axiom_soap_body_t *soap_body = NULL;
        axiom_node_t *key_info_node = NULL;

        soap_body = axiom_soap_envelope_get_body(soap_envelope, env);

        id = (axis2_char_t*)axutil_array_list_get(reference_list, env, i);

        id2 = axutil_string_substring_starting_at(axutil_strdup(env, id), 1);

        envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);

        /*Search for the node by its ID*/
        enc_data_node = oxs_axiom_get_node_by_id(env, envelope_node, OXS_ATTR_ID, id2, NULL);
        if(!enc_data_node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][shp] Node with ID=%s cannot be found", id2);
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Cannot find EncryptedData element", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
            axutil_array_list_free(reference_list, env);
            reference_list = NULL;
            AXIS2_FREE(env->allocator, id2);
            id2 = NULL;
            return AXIS2_FAILURE;
        }

        AXIS2_FREE(env->allocator, id2);
        id2 = NULL;

        key_info_node = oxs_axiom_get_first_child_node_by_name(env, enc_data_node,
                        OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL);

       if(key_info_node){
            axis2_char_t *key_name = NULL;
            oxs_key_t *session_key = NULL;
            oxs_key_t *key_to_decrypt = NULL;

            key_name = rampart_shp_process_key_info_for_ref_val(env, key_info_node);
            /*Get the sesison key*/
            session_key = rampart_context_get_session_key(rampart_context, env);
            /*Search for the key using key_name. It can be either the session or a derived key*/
            if(0 == axutil_strcmp(key_name, oxs_key_get_name(session_key, env))){
                /*OK the key used to encrypt is the session key*/
                key_to_decrypt = session_key;
            }else{
                /*The key used to decrypt can be a derived key*/
                key_to_decrypt = rampart_context_get_derived_key(rampart_context, env, key_name);
            }
            
            if(key_to_decrypt){
                /*Now if everything is fine we need to decrypt*/
                oxs_ctx_t *ctx = NULL;
                axiom_node_t *decrypted_node = NULL;

                ctx = oxs_ctx_create(env);
                oxs_ctx_set_key(ctx, env, key_to_decrypt);
                status = oxs_xml_enc_decrypt_node(env, ctx, enc_data_node, &decrypted_node);

                if(AXIS2_FAILURE == status)
                {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Data decryption failed", RAMPART_FAULT_IN_ENCRYPTED_DATA, msg_ctx);
                        return AXIS2_FAILURE;
                }
                /*Check if the signture is encrypted*/
                if(0 == axutil_strcmp( OXS_NODE_SIGNATURE , axiom_util_get_localname(decrypted_node, env))){
                    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_ENCRYPTED, RAMPART_YES);
                }
                /*Check if the body is encrypted*/
                if(0 == axutil_strcmp(OXS_NODE_BODY , axiom_util_get_localname(axiom_node_get_parent(decrypted_node, env), env))){
                    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_BODY_ENCRYPTED, RAMPART_YES);
                }

                /*Free*/
                oxs_ctx_free(ctx, env);
                ctx = NULL;

            }else{
                /*Can't help. Error retrieving the key to decrypt the reference. */
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,  "[rampart][shp] On processing ReferenceList, failed to get the key to decrypt");
                return AXIS2_FAILURE;
            }
       }

    }

    axutil_array_list_free(reference_list, env);
    reference_list = NULL;
    return status;
}


static axis2_status_t
rampart_shp_process_sym_binding_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{
    axis2_status_t status = AXIS2_FAILURE;
    oxs_sign_ctx_t *sign_ctx = NULL;
    axiom_node_t *envelope_node = NULL;
    axiom_node_t *key_info_node = NULL;
    oxs_key_t *key_to_verify = NULL;
    oxs_key_t *session_key = NULL;

    /*Get the session key*/
    session_key = rampart_context_get_session_key(rampart_context, env);
    
    /*Get the envelope node*/
    envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
   
    /*Get the KeyInfo node*/
    key_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                            OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL);
    if(key_info_node){
       /* axiom_node_t *reffed_node = NULL;
        axis2_char_t *reffed_node_name = NULL;*/
        
        /*Now we need to decrypt the EncryptedKey if not done already*/
        if(!session_key){
            axiom_node_t *encrypted_key_node = NULL;

            encrypted_key_node = oxs_axiom_get_first_child_node_by_name(env, sec_node, OXS_NODE_ENCRYPTED_KEY, OXS_ENC_NS, NULL);
            status = rampart_shp_process_encrypted_key(env, msg_ctx, rampart_context, soap_envelope, sec_node, encrypted_key_node);                     
            session_key = rampart_context_get_session_key(rampart_context, env);
        }
    }
    if(session_key){
        axis2_char_t *key_name = NULL;

        key_name = rampart_shp_process_key_info_for_ref_val(env, key_info_node);
            /*Search for the key using key_name. It can be either the session or a derived key*/
            if(0 == axutil_strcmp(key_name, oxs_key_get_name(session_key, env))){
                /*OK the key used to sign is the session key*/
                key_to_verify = session_key;
            }else{
                /*The key used to sign can be a derived key*/
                key_to_verify = rampart_context_get_derived_key(rampart_context, env, key_name);
            }
    }
    if(!key_to_verify){
        /*It's an error*/
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                          "Signature Verification failed. Cannot get the key to verify", 
                                RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp] Signature Verification failed. Cannot get the key to verify");

        return AXIS2_FAILURE;
    } 
    /*Create sign context*/
    sign_ctx = oxs_sign_ctx_create(env);
    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_VERIFY);
    oxs_sign_ctx_set_secret(sign_ctx, env, key_to_verify);
    status = oxs_xml_sig_verify(env, sign_ctx, sig_node, envelope_node);
    if(status != AXIS2_SUCCESS)
    {
        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope( env, RAMPART_FAULT_INVALID_SECURITY,
                "Signature Verification failed.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        }

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[Rampart][shp]Signature Verification failed.");

        return AXIS2_FAILURE;
    }
    /*Free Sign Ctx*/ 
    oxs_sign_ctx_free(sign_ctx, env);
    sign_ctx = NULL;

    return status;
}

static axis2_status_t
rampart_shp_process_asym_binding_signature(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{

    oxs_sign_ctx_t *sign_ctx = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *digest_mtd_pol = NULL;
    axis2_char_t *sig_mtd_pol = NULL;
    axiom_node_t *sign_info_node = NULL;
    axiom_node_t *cur_node = NULL;
    rp_property_t *token = NULL;
    axis2_bool_t server_side = AXIS2_FALSE;
    axis2_char_t *eki = NULL;
    rp_property_type_t token_type;
    axiom_node_t *key_info_node = NULL;
    axiom_node_t *str_node = NULL;
    axiom_node_t *str_child_node = NULL;
    axis2_char_t *str_child_name = NULL;
    oxs_x509_cert_t *cert = NULL;
    axiom_node_t *key_info_child_node = NULL;
    axiom_node_t *envelope_node = NULL;
    axis2_bool_t is_include_token = AXIS2_FALSE;

    server_side = axis2_msg_ctx_get_server_side(msg_ctx,env);
    sig_mtd_pol = rampart_context_get_asym_sig_algo(rampart_context,env);
    digest_mtd_pol = rampart_context_get_digest_mtd(rampart_context,env);

    if(!sig_mtd_pol || !digest_mtd_pol)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK,
                                      "Error in the policy. No signature algo", RAMPART_FAULT_IN_POLICY, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Error in policy, Specifying signature algorithms.");
        return AXIS2_FAILURE;
    }

    sign_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                     OXS_NODE_SIGNEDINFO, OXS_DSIG_NS, NULL);

    if(!sign_info_node)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "Sign info node not found.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] Sign info cannot be found.Verifycation failed");
        return AXIS2_FAILURE;
    }

    cur_node = axiom_node_get_first_element(sign_info_node, env);
    while(cur_node)
    {
        axis2_char_t *localname =  NULL;
        localname  = axiom_util_get_localname(cur_node, env);
        if(axutil_strcmp(localname, OXS_NODE_SIGNATURE_METHOD)==0)
        {
            /*Verify the signature method with policy*/
            axis2_char_t *sig_mtd = NULL;
            sig_mtd = oxs_token_get_signature_method(env, cur_node);
            if(sig_mtd)
            {
                if(axutil_strcmp(sig_mtd_pol, sig_mtd)!=0)
                {
                    rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                  "Signed with Invalid algorithm", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[rampart][shp] Signed with Invalid algorithm");

                    return AXIS2_FAILURE;
                }
            }

            else
            {
                rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                              "Signature method element not found .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[rampart][shp] Signature method element not found");
                return AXIS2_FAILURE;
            }
        }
        else if(axutil_strcmp(localname, OXS_NODE_REFERENCE) == 0)
        {
            /*Verify each digest method with policy*/
            axiom_node_t *digest_mtd_node = NULL;
            axis2_char_t *digest_mtd = NULL;
            digest_mtd_node  = oxs_axiom_get_first_child_node_by_name(env, cur_node,
                               OXS_NODE_DIGEST_METHOD, OXS_DSIG_NS, NULL);
            if(digest_mtd_node)
            {
                digest_mtd = oxs_token_get_digest_method(env, digest_mtd_node);
                if(digest_mtd)
                {
                    if(axutil_strcmp(digest_mtd_pol, digest_mtd)!=0)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Digest created with Invalid algorithm", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Digest Created with Invalid algorithm");

                        return AXIS2_FAILURE;
                    }
                }
                else
                {
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                return AXIS2_FAILURE;
            }
        }
        else
        {
            /*we do not need to process at this moment*/
        }
        cur_node = axiom_node_get_next_sibling(cur_node, env);
    }/*Eof While*/
    /*Get the key identifiers and build the certificate*/
    /*First we should verify with policy*/

    token = rampart_context_get_token(rampart_context, env,
                                      AXIS2_FALSE, server_side, AXIS2_TRUE);

    if(!token)
    {
        AXIS2_LOG_INFO(env->log,  "[rampart][shp] Signature Token is not specified");
        return AXIS2_SUCCESS;
    }
    token_type = rp_property_get_type(token, env);

    if(!rampart_context_is_token_type_supported(token_type, env))
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_UNSUPPORTED_SECURITY_TOKEN,
                                      "The token type does not supported", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp] The token type does not supported");

        return  AXIS2_FAILURE;
    }
    
    is_include_token = rampart_context_is_token_include(
                           rampart_context, token, token_type, server_side, AXIS2_TRUE, env);

    key_info_node = oxs_axiom_get_first_child_node_by_name(env, sig_node,
                    OXS_NODE_KEY_INFO, OXS_DSIG_NS, NULL );

    if(!key_info_node)
    {
        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                      "Key Info node is not in the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][shp]Verify failed. Key Info node is not in the message.");
        return AXIS2_FAILURE;
    }
    str_node = oxs_axiom_get_first_child_node_by_name(env, key_info_node,
               OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);

    if(str_node)
    {
        str_child_node = axiom_node_get_first_element(str_node,env);
        if(str_child_node)
        {
            str_child_name = axiom_util_get_localname(str_child_node, env);
            if(str_child_name)
            {
                if(is_include_token)
                {
                    if(axutil_strcmp(str_child_name, OXS_NODE_REFERENCE)!=0)
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Token is not in the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[rampart][shp] Token is not included in the message ");

                        return AXIS2_FAILURE;
                    }
                    cert = oxs_x509_cert_create(env);
                    status = rampart_token_process_direct_ref(env, str_child_node, sec_node, cert);
                }
                else
                {
                    if(0 == axutil_strcmp(str_child_name, OXS_NODE_EMBEDDED))
                    {
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_EMBEDDED, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_EMBEDDED);
                            return AXIS2_FAILURE;
                        }
                        cert = oxs_x509_cert_create(env);
                        status = rampart_token_process_embedded(env, str_child_node, cert);
                    }
                    else if(0 == axutil_strcmp(str_child_name, OXS_NODE_KEY_IDENTIFIER))
                    {
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_KEY_IDENTIFIER, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_KEY_IDENTIFIER);
                            return AXIS2_FAILURE;
                        }
                        cert = get_receiver_x509_cert(env, rampart_context);
                        status = AXIS2_SUCCESS;
                    }
                    else if(0 == axutil_strcmp(str_child_name, OXS_NODE_X509_DATA))
                    {
                        if(!rampart_context_is_key_identifier_type_supported(
                                    rampart_context, token, RAMPART_STR_ISSUER_SERIAL, env))
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                          "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                            "[Rampart][shp]Key Reference Info mismatch (%s, %s)", str_child_name, OXS_NODE_X509_DATA);
                            return AXIS2_FAILURE;
                        }
                        cert = get_receiver_x509_cert(env,rampart_context);
                        status = AXIS2_SUCCESS;
                    }
                    else
                    {
                        rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY,
                                                      "Key Reference Type not supported .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                        "[Rampart][shp]Key Reference %s not supported ", str_child_name);
                        return AXIS2_FAILURE;
                    }
                }
                if(status != AXIS2_SUCCESS || !cert)
                {
                    rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                                  "Cannot load the key to verify the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                    "[Rampart][shp] Cannot load the key to verify the message");
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[Rampart][shp]Cannot get the key Reference Type from the message.");
                return AXIS2_FAILURE;
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[Rampart][shp]No Child node in the Security Token Reference Element.");
            return AXIS2_FAILURE;
        }
    }

    /*So there may be scenarios where there is no Security Token Reference Element.*/
    else
    {

        /*In such case policy support only Isssuer Serial scenario.*/

        if(axutil_strcmp(eki, RAMPART_STR_ISSUER_SERIAL)==0)
        {
            key_info_child_node = axiom_node_get_first_element(key_info_node, env);
            if(key_info_child_node)
            {
                axis2_char_t *key_info_child_name = NULL;
                key_info_child_name = axiom_util_get_localname(key_info_child_node, env);
                if(key_info_child_name)
                {
                    if(0 == axutil_strcmp(key_info_child_name, OXS_NODE_X509_DATA))
                    {
                        status = rampart_token_process_x509_data(env, key_info_child_node, cert);
                        if(status != AXIS2_SUCCESS || !cert)
                        {
                            rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                                          "Cannot load the key to verify the message .", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI ,
                                            "[Rampart][shp] Cannot load the key to verify the message");
                            return AXIS2_FAILURE;
                        }
                    }
                    else
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                        "[Rampart][shp]Cannot get the key Reference Type from the message.");
                        return AXIS2_FAILURE;
                    }
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                    "[Rampart][shp]Cannot get the key Reference Type from the message.");
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[Rampart][shp]Cannot get the key Reference Type from the message.");
                return AXIS2_FAILURE;
            }
        }

        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[Rampart][shp]Can't be used as a direct child of Key Info");
            return AXIS2_FAILURE;
        }
    }

    sign_ctx = oxs_sign_ctx_create(env);

    if(!sign_ctx)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Sign context creation failed. Out of Memeory.");
        return AXIS2_FAILURE;
    }

    /*Set the required values in sig_ctx*/

    oxs_sign_ctx_set_operation(sign_ctx, env, OXS_SIGN_OPERATION_VERIFY);
    oxs_sign_ctx_set_certificate(sign_ctx, env, cert);

    envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
    if(!envelope_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Cannot get the Envelope node from envelope.");
        return AXIS2_FAILURE;
    }

    /*Verify the signature*/

    status = oxs_xml_sig_verify(env, sign_ctx, sig_node, envelope_node);
    if(status != AXIS2_SUCCESS)
    {
        if(!axis2_msg_ctx_get_fault_soap_envelope(msg_ctx, env))
        {
            rampart_create_fault_envelope(
                env, RAMPART_FAULT_INVALID_SECURITY,
                "Signature Verification failed.", RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
        }

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Signature Verification failed.");

        return AXIS2_FAILURE;
    }

    if(sign_ctx)
    {
        oxs_sign_ctx_free(sign_ctx, env);
        sign_ctx = NULL;
    }

    return status;
}

static axis2_status_t
rampart_shp_process_signature(
const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    axiom_soap_envelope_t *soap_envelope,
    axiom_node_t *sec_node,
    axiom_node_t *sig_node)
{
    axis2_status_t status = AXIS2_FAILURE;
    
    if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_ASYMMETRIC_BINDING){
        status = rampart_shp_process_asym_binding_signature(env, msg_ctx, rampart_context, soap_envelope, sec_node, sig_node);
    }else if ((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_SYMMETRIC_BINDING){
        status = rampart_shp_process_sym_binding_signature(env, msg_ctx, rampart_context, soap_envelope, sec_node, sig_node);
    }else if((rampart_context_get_binding_type(rampart_context,env)) == RP_PROPERTY_TRANSPORT_BINDING){
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Transport Binding Not supported" );
        /*Not supported*/
    }else{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Binding type not supported");
        /*Not supported*/
    }
    /*We need to set the Signature Value in the Security Processed Resultsi. This is required for the Signature Confirmation support*/
    if(AXIS2_SUCCESS == status){
      axis2_char_t *sig_val = NULL; 
      axiom_node_t *sig_val_node = NULL;

      sig_val_node = oxs_axiom_get_first_child_node_by_name(env, sig_node, OXS_NODE_SIGNATURE_VALUE, OXS_DSIG_NS, OXS_DS );
      sig_val = oxs_token_get_signature_value(env, sig_val_node);

      rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VERIFIED, RAMPART_YES);
      rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VALUE, sig_val);
    }else{
      rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_SIG_VERIFIED, RAMPART_NO);
    }
    return status;
}

/***/
static axis2_status_t 
rampart_shp_detect_replays(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_soap_envelope_t *soap_envelope,
                            axiom_node_t *sec_node)
{
    axis2_bool_t need_replay_detection = AXIS2_FALSE;
    axis2_status_t status = AXIS2_FAILURE;

        if((NULL == rampart_context_get_rd_val(rampart_context, env)) && (NULL == rampart_context_get_replay_detector_name(rampart_context, env)))
		{
            AXIS2_LOG_INFO(env->log, "[rampart][shp] Replay detection is not specified. Nothing to do");
            need_replay_detection = AXIS2_FALSE;
        }
		else
		{
            AXIS2_LOG_INFO(env->log, "[rampart][shp] Checking message for replay.");
            need_replay_detection = AXIS2_TRUE;
        }
        if(AXIS2_TRUE == need_replay_detection)
		{
			axis2_char_t* replay_detector_name = rampart_context_get_replay_detector_name(rampart_context, env);
			if (replay_detector_name)
			{
				rampart_replay_detector_t* replay_detector = (rampart_replay_detector_t*)rampart_context_get_replay_detector(rampart_context, env);
				if (!replay_detector)
				{
					AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Cannot find the replay detector module");
					rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
					return AXIS2_FAILURE;
				}

				AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Using replay module.");
				status = RAMPART_REPLAY_DETECTOR_IS_REPLAYED(replay_detector, env, msg_ctx, rampart_context);
				if(status != AXIS2_SUCCESS)
				{
					/*Scream .. replayed*/
					AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Message can be replayed");
					rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
					return AXIS2_FAILURE;
				}
				else
				{
					AXIS2_LOG_INFO(env->log, "[rampart][shp] Checked message for replays. Not a replay.");
				}
			}
			else
			{
				rampart_is_replayed_fn rd_fn = NULL;
				AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][shp] Replay module not defined. Using replay function.");
				
				/*Is replayed*/
				rd_fn = rampart_context_get_replay_detect_function(rampart_context, env);
				if(rd_fn)
				{
					status  = (*rd_fn)(env, msg_ctx, rampart_context);
					if(status != AXIS2_SUCCESS)
					{
						/*Scream .. replayed*/
						AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart][shp] Message can be replayed");
						rampart_create_fault_envelope(env, RAMPART_FAULT_INVALID_SECURITY, "Message is replayed", RAMPART_FAULT_MSG_REPLAYED, msg_ctx);
						return AXIS2_FAILURE;
					}
					else
					{
						AXIS2_LOG_INFO(env->log, "[rampart][shp] Checked message for replays. Not a replay.");
					}
				}
				else
				{
					AXIS2_LOG_INFO(env->log, "[rampart][shp] No replay detection function specified. Nothing to do. ");
				}
			}
        }
        return AXIS2_SUCCESS;
}
#if 0
static axis2_status_t
rampart_shp_process_bst(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_node_t *sec_node,
                            axiom_node_t *bst_node)
{
    axis2_char_t *cert_buf = NULL;

    cert_buf = (axis2_char_t*)oxs_axiom_get_node_content(env, bst_node);
    /*Set to Rampart Context*/
    rampart_context_set_certificate(rampart_context, env, cert_buf);
    rampart_context_set_certificate_type(rampart_context, env, AXIS2_KEY_TYPE_PEM);
    return AXIS2_SUCCESS;
}
#endif

static axis2_status_t
rampart_shp_process_derived_key(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_node_t *sec_node,
                            axiom_node_t *dk_node)
{
    oxs_key_t *session_key = NULL;
    oxs_key_t *derived_key = NULL;

    /*Get the session key.*/ 
    session_key = rampart_context_get_session_key(rampart_context, env);
    if(!session_key){
         AXIS2_LOG_INFO(env->log,  "[rampart][shp] On processing ReferenceList, failed to get the session key. Cannot derive the key");
         return AXIS2_FAILURE;
    }

    /*Derive the key*/
    derived_key = oxs_derivation_extract_derived_key_from_token(env, dk_node, sec_node, session_key); 
    
    /*Add to the rampart context*/
    rampart_context_add_derived_key(rampart_context, env, derived_key);

    return AXIS2_SUCCESS; 
}

static axis2_status_t 
rampart_shp_process_saml_token(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_node_t *saml_node)
{
    axis2_bool_t server_side = AXIS2_FALSE;
    rampart_saml_token_t *saml = NULL;
    axis2_char_t *sub_conf = NULL;
    server_side = axis2_msg_ctx_get_server_side(msg_ctx, env);
    
    sub_conf = rampart_saml_token_get_subject_confirmation(env, saml_node);
    if (sub_conf && axutil_strcmp(sub_conf, SAML_SUB_CONFIRMATION_SENDER_VOUCHES) == 0)
    {
        if (!rampart_context_is_include_supporting_saml_token(rampart_context, 
                                                !server_side, AXIS2_FALSE, env))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                 "[Rampart][shp] Unexpected SAML token.");
            return AXIS2_FAILURE;
        }
    }   
    else if (sub_conf && axutil_strcmp(sub_conf, SAML_SUB_CONFIRMATION_HOLDER_OF_KEY) == 0)
    {
        if (!rampart_context_is_include_protection_saml_token(rampart_context, 
                                                !server_side, AXIS2_FALSE, env))
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                 "[Rampart][shp] Unexpected SAML token.");
            return AXIS2_FAILURE;
        }
    }
	/* Set the SAML token to the rampart context */
    saml = rampart_saml_token_create(env, saml_node, RAMPART_ST_CONFIR_TYPE_UNSPECIFIED);
	rampart_context_add_saml_token(rampart_context, env, saml);
    return AXIS2_SUCCESS; 
}

/*Public functions*/

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_shp_process_sec_header(const axutil_env_t *env,
                            axis2_msg_ctx_t *msg_ctx,
                            rampart_context_t *rampart_context,
                            axiom_soap_envelope_t *soap_envelope,
                            axiom_node_t *sec_node)
{
    axiom_node_t *cur_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    AXIS2_LOG_INFO(env->log, "[rampart][shp] Processing security header in Strict layout");

    cur_node = axiom_node_get_first_child(sec_node, env);

    /*Loop all security headers*/
    while(cur_node){
        axis2_char_t *cur_local_name = NULL;
        
        cur_local_name = axiom_util_get_localname(cur_node, env);
        AXIS2_LOG_INFO(env->log, "[rampart][shp] Processing security header element %s", cur_local_name);

        if(0 == axutil_strcmp(cur_local_name, OXS_NODE_ENCRYPTED_KEY)){
            status = rampart_shp_process_encrypted_key(env, msg_ctx, rampart_context, soap_envelope, sec_node, cur_node);
            
        }else if(0 == axutil_strcmp(cur_local_name, RAMPART_SECURITY_TIMESTAMP)){
            status = rampart_shp_process_timestamptoken(env, msg_ctx, rampart_context, sec_node);

        }else if(0 == axutil_strcmp(cur_local_name, RAMPART_SECURITY_USERNAMETOKEN)){
            status = rampart_shp_process_usernametoken(env, msg_ctx, rampart_context, sec_node);

        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE)){
            status = rampart_shp_process_signature(env, msg_ctx, rampart_context, soap_envelope, sec_node, cur_node);

        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_REFERENCE_LIST)){
            status = rampart_shp_process_reference_list(env, msg_ctx, rampart_context, soap_envelope, sec_node, cur_node);

        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_DERIVED_KEY_TOKEN)){
            /* We need to extract this and store in the rampart context*/
            status = rampart_shp_process_derived_key(env, msg_ctx,  rampart_context, sec_node, cur_node);

        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_ENCRYPTED_DATA)){
            /*We do nothing. But this is possible when a security header is Encrypted. But it would be decrypted thru a ref list*/
            status = AXIS2_SUCCESS;
        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SIGNATURE_CONFIRMATION)){
            status = rampart_shp_process_signature_confirmation(env, msg_ctx,  rampart_context,  cur_node);
        
        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_BINARY_SECURITY_TOKEN)){
            /*We do nothing.*/
            status = AXIS2_SUCCESS;
        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SAML_ASSERTION)){
            status = rampart_shp_process_saml_token(env, msg_ctx, rampart_context, cur_node);
		 
        }else if(0 == axutil_strcmp(cur_local_name, OXS_NODE_SECURITY_TOKEN_REFRENCE)){
            /*We do nothing.*/
            status = AXIS2_SUCCESS;
        }else{
            AXIS2_LOG_INFO(env->log, "[rampart][shp] Unknown security header %s", cur_local_name);
            status = AXIS2_SUCCESS;
        }
        if(status != AXIS2_SUCCESS){
             AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] %s processing failed", cur_local_name);
             return AXIS2_FAILURE;
        }

        /*Get next node*/
        cur_node = axiom_node_get_next_sibling(cur_node, env);
    }/*Eof while loop*/
            
    AXIS2_LOG_INFO(env->log, "Security header processing done");
    /*Now detect replays*/
    status = rampart_shp_detect_replays(env, msg_ctx, rampart_context,  soap_envelope, sec_node); 
    if(status != AXIS2_SUCCESS){
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] A replay detected");
        return AXIS2_FAILURE;
    }

    /*Now validate security policies, those cannot be checked on the fly*/
    status = rampart_pv_validate_sec_header(env, rampart_context, sec_node, msg_ctx);
    if(status != AXIS2_SUCCESS){
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][shp] Security policy validation failed");
        return AXIS2_FAILURE;
    }
    return AXIS2_SUCCESS;
}

