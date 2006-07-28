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

#include <axis2_qname.h>
#include <axiom_namespace.h>
#include <axiom_node.h>
#include <stdio.h>
#include <axis2_util.h>
#include <oxs_constants.h>
#include <oxs_ctx.h>
#include <oxs_error.h>
#include <oxs_buffer.h>
#include <oxs_enc_engine.h>
#include <oxs_cipher.h>
#include <openssl_cipher_ctx.h>
#include <openssl_crypt.h>
#include <openssl_constants.h>


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_enc_encrypt(const axis2_env_t *env, 
                enc_ctx_ptr enc_ctx,
                oxs_buffer_ptr input,
                axis2_char_t* key,
                oxs_buffer_ptr result)
{
    unsigned char *out_main_buf;
    openssl_evp_block_cipher_ctx_ptr bc_ctx = NULL;
    axis2_char_t* iv =  "12345678";   
    axis2_char_t* cipher_name =  NULL;   

    int ret;
 
    bc_ctx = openssl_evp_block_cipher_ctx_create(env);
    if(!bc_ctx) return (-1);
    
    /*Set the key*/
    bc_ctx->key = AXIS2_STRDUP(key, env);
    bc_ctx->key_initialized = 1;
    /*Set the IV*/
    bc_ctx->iv =  AXIS2_STRDUP(iv, env);

    /*TODO: Get the cipher by giving the algoritm attribute */
    cipher_name = oxs_get_cipher(env, (unsigned char*)enc_ctx->encmtd_algorithm);
    if(!cipher_name){
        return AXIS2_FAILURE;
    } 

    ret =  openssl_evp_block_cipher_ctx_init(env, bc_ctx,
                            OPENSSL_ENCRYPT, cipher_name);
   
    if(ret < 0){
        return AXIS2_FAILURE;
    }
    ret = openssl_block_cipher_crypt(env, bc_ctx,
                                         input->data,  &out_main_buf, OPENSSL_ENCRYPT);
    if(ret < 0) return AXIS2_FAILURE;
   
#if 0 
    FILE *outf;
    outf = fopen("outbuf", "wb");
    fwrite(out_main_buf, 1, ret, outf);
#endif
    
    oxs_buffer_set_size(env, result, ret);
    result->data = out_main_buf;
    
    return AXIS2_SUCCESS;
}

/*We expect user to provide a template as below*/
AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_enc_encrypt_template(const axis2_env_t *env,
                        axiom_node_t* template, 
                        axis2_char_t* data,
                        enc_ctx_ptr enc_ctx
                        )
{
    axis2_status_t  ret =  AXIS2_FAILURE;
    oxs_buffer_ptr input = NULL;
    oxs_buffer_ptr result = NULL;
    axis2_char_t *key = NULL;
   
       
    /*Populate enc_ctx*/
    enc_ctx->operation = oxs_operation_encrypt;
    enc_ctx->mode = enc_ctx_mode_encrypted_data;
     
    ret = oxs_enc_encryption_data_node_read(env, enc_ctx, template);
    if(ret != AXIS2_SUCCESS){
        return ret;
    }
    
    /*We've populated the context*/
    
    /*Create the input buffer*/
    input = oxs_string_to_buffer(env, data);
    
    result = oxs_create_buffer(env, ret);
    
    key = enc_ctx->key->data;

    oxs_enc_encrypt(env, enc_ctx, input, key, result ); 
    
    printf("Encrypted Result = %s\n", oxs_buffer_to_string(env, result));
     
    return ret;
    
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_enc_cipher_data_node_read(const axis2_env_t *env, 
                                enc_ctx_ptr enc_ctx, axiom_node_t* node_cipher_data)
{
    axiom_node_t* cur = NULL;
    axiom_element_t *ele = NULL;
    int ret;
    /*We've a cipher data node here.
     The child element is either a CipherReference or a CipherValue element*/


    printf("\n Found node CD %s\n", AXIOM_NODE_TO_STRING(node_cipher_data, env)); 
    
    cur = AXIOM_NODE_GET_FIRST_CHILD(node_cipher_data, env); 
    
    if(!cur){        
        
        return AXIS2_FAILURE;
    }

    if( oxs_axiom_check_node_name(env, cur, OXS_NodeCipherValue, OXS_EncNs )){
        /*Got a cipher value*/
        if(enc_ctx->operation == oxs_operation_decrypt)
        {  
            printf("\n Found node CV %s\n", AXIOM_NODE_TO_STRING(node_cipher_data, env)); 
            enc_ctx->cipher_value_node = cur;
        } 
    }else if(oxs_axiom_check_node_name(env, cur, OXS_NodeCipherReference, OXS_EncNs )){
        /*Got a cipher reference*/
        /*TODO : Support Cipher references*/
    }

    return AXIS2_SUCCESS;    
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_enc_encryption_data_node_read(const axis2_env_t *env,
            enc_ctx_ptr enc_ctx, axiom_node_t* node)
{
    axiom_node_t* cur = NULL;
    axiom_element_t *ele = NULL;
    int ret;

    if(!(enc_ctx->operation == oxs_operation_encrypt) || (enc_ctx->operation == oxs_operation_decrypt)) return (-1);

    switch(enc_ctx->mode) {
    case enc_ctx_mode_encrypted_data:
        if(!(oxs_axiom_check_node_name(env, node, OXS_NodeEncryptedData, OXS_EncNs )))
        {
            return AXIS2_FAILURE;
        }
        break;
    case enc_ctx_mode_encrypted_key:
        if(!(oxs_axiom_check_node_name(env, node, OXS_NodeEncryptedKey, OXS_EncNs)))
        {
             return AXIS2_FAILURE;
        }
        break;
    }

    
    ele = AXIOM_NODE_GET_DATA_ELEMENT(node, env);

    if(!ele) return AXIS2_FAILURE;

    enc_ctx->id = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrId);
    enc_ctx->type = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrType);
    enc_ctx->mime_type = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrMimeType);
    enc_ctx->encoding = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrEncoding);

    if(enc_ctx->mode == enc_ctx_mode_encrypted_key) {
        enc_ctx->recipient = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrRecipient);
    }
    
    printf("\n1 Found node %s\n", AXIOM_NODE_TO_STRING(node, env));
    cur = AXIOM_NODE_GET_FIRST_CHILD(node, env);

    /*TODO remove check*/
    if(cur == NULL){    
         printf("Geeeee\n");
         return AXIS2_FAILURE;
    }
    /* first node is optional EncryptionMethod, we'll read it later */
    if((cur != NULL) && (oxs_axiom_check_node_name(env, cur, OXS_NodeEncryptionMethod, OXS_EncNs))) {
    printf("\n2 Found node %s\n", AXIOM_NODE_TO_STRING(cur, env));
        enc_ctx->enc_method_node = cur;
        cur = AXIOM_NODE_GET_NEXT_SIBLING(cur, env);
    }


    /* next node is optional KeyInfo, we'll process it later */
    if((cur != NULL) && (  oxs_axiom_check_node_name(env, cur, OXS_NodeKeyInfo, OXS_DSigNs))) {
        printf("\n3 Found node %s\n", AXIOM_NODE_TO_STRING(cur, env));
        enc_ctx->key_info_node = cur;
        cur = AXIOM_NODE_GET_NEXT_SIBLING(cur, env);
    }



    /* next is required CipherData node */
    if((cur == NULL) || (!oxs_axiom_check_node_name(env, cur, OXS_NodeCipherData, OXS_EncNs))) {
        printf("\n4 Found node %s\n", AXIOM_NODE_TO_STRING(cur, env));
        return AXIS2_FAILURE;
    }


    ret = oxs_enc_cipher_data_node_read(env, enc_ctx, cur);
    if(ret < 0) {
        printf("\n5 Processing failed %s\n", AXIOM_NODE_TO_STRING(cur, env));
        return AXIS2_FAILURE;
    }
    

    cur = AXIOM_NODE_GET_NEXT_SIBLING(cur, env);


    /* next is optional EncryptionProperties node (we simply ignore it) */
    if((cur != NULL) && (oxs_axiom_check_node_name(env, cur, OXS_NodeEncryptionProperties, OXS_EncNs))) {
        printf("\n6 Found node %s\n", AXIOM_NODE_TO_STRING(cur, env));
        cur = AXIOM_NODE_GET_NEXT_SIBLING(cur, env);
    }

    /* there are more possible nodes for the <EncryptedKey> node */
    if(enc_ctx->mode == enc_ctx_mode_encrypted_key) {
    /* next is optional ReferenceList node (we simply ignore it) */
        if((cur != NULL) && (oxs_axiom_check_node_name(env, cur, OXS_NodeReferenceList, OXS_EncNs))) {
            printf("\n6 Found node %s\n", AXIOM_NODE_TO_STRING(cur, env));
            cur = AXIOM_NODE_GET_NEXT_SIBLING(cur, env);
        }
    }

       
    /* now read the encryption method node */
    if(enc_ctx->enc_method_node != NULL) {
        ele = AXIOM_NODE_GET_DATA_ELEMENT(enc_ctx->enc_method_node, env);
        enc_ctx->encmtd_algorithm = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(ele, env, OXS_AttrAlgorithm);

    }
        
return AXIS2_SUCCESS;

}





