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

#include <oxs_key_mgr.h>
#include <oxs_tokens.h>
#include <oxs_xml_key_processor.h>
#include <axiom_util.h>
#include <rampart_token_processor.h>

/**
 * extract certificate related information using given token_reference node and scope node
 * @param env Environment structure
 * @param st_ref_node security token reference node. 
 * @param scope_node node where additional details should be found. Can be NULL for all other 
 *  scenarios but the Direct Reference
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_security_token_reference(
    const axutil_env_t *env,
    axiom_node_t *st_ref_node,
    axiom_node_t *scope_node,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *child_name = NULL;
    axiom_node_t *child_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    child_node = axiom_node_get_first_element(st_ref_node, env);
    child_name = axiom_util_get_localname(child_node, env);

    if(!axutil_strcmp(child_name, OXS_NODE_REFERENCE))
    {
        status = rampart_token_process_direct_ref(env, child_node, scope_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_EMBEDDED))
    {
        status = rampart_token_process_embedded(env, child_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_KEY_IDENTIFIER))
    {
        status = rampart_token_process_key_identifier(env, child_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_X509_DATA))
    {
        status = rampart_token_process_x509_data(env, child_node, cert);
    }
    else
    {
        /* reference method is not supported */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]%s of wsse:SecurityTokenReference is not supported.", child_name);
        return AXIS2_FAILURE;
    }

    return status;
}

/**
 * extract certificate using reference id given in reference node
 * @param env Environment structure
 * @param ref_node security token reference node. 
 * @param scope_node node where certificate details should be found using reference id
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_direct_ref(
    const axutil_env_t *env,
    axiom_node_t *ref_node,
    axiom_node_t *scope_node,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *ref = NULL;
    axis2_char_t *ref_id = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *bst_node = NULL;
    axis2_char_t *data = NULL;
    oxs_x509_cert_t *_cert = NULL;

    /* Select ref using <wsse:Reference> node. Since it is relative reference, we have to remove 
     * first character (which is '#') from the reference */
    ref = oxs_token_get_reference(env, ref_node);
    ref_id = axutil_string_substring_starting_at(axutil_strdup(env, ref), 1);

    /* Find the token with the id = ref_id within the scope of scope_node */
    bst_node = oxs_axiom_get_node_by_id(env, scope_node, OXS_ATTR_ID, ref_id, OXS_WSU_XMLNS);
    if(!bst_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Error retrieving element with ID = %s", ref_id);
        return AXIS2_FAILURE;
    }

    /* Process data. */
    data = oxs_axiom_get_node_content(env, bst_node);
    _cert = oxs_key_mgr_load_x509_cert_from_string(env, data);
    if(_cert)
    {
        status =  AXIS2_SUCCESS;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot load certificate from string =%s", data);
        status =  AXIS2_FAILURE;
    }

    oxs_x509_cert_copy_to(_cert, env, cert);
    oxs_x509_cert_free(_cert, env);
    _cert = NULL;

    return status;
}

/**
 * extract embedded certificate from given embed_node
 * @param env Environment structure
 * @param embed_node node where certificate is embedded. 
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_embedded(
    const axutil_env_t *env,
    axiom_node_t *embed_node,
    oxs_x509_cert_t *cert)
{
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *data = NULL;
    oxs_x509_cert_t *_cert = NULL;
    axiom_node_t *bst_node = NULL;

    bst_node = axiom_node_get_first_element(embed_node, env);

    if(!bst_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]BST element is not found");
        return AXIS2_FAILURE;
    }

    /* Process data */
    data = oxs_axiom_get_node_content(env, bst_node);
    _cert = oxs_key_mgr_load_x509_cert_from_string(env, data);
    if(_cert)
    {
        status =  AXIS2_SUCCESS;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot load certificate from string =%s", data);
        status =  AXIS2_FAILURE;
    }

    oxs_x509_cert_copy_to(_cert, env, cert);
    oxs_x509_cert_free(_cert, env);
    return status;
}

/**
 * extract key identifier and populate the certificate
 * @param env Environment structure
 * @param ki_node node where key identifier is available. 
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_key_identifier(
    const axutil_env_t *env,
    axiom_node_t *ki_node,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *ki = NULL;

    ki = oxs_axiom_get_node_content(env, ki_node);
    oxs_x509_cert_set_key_identifier(cert, env, ki);
    return AXIS2_SUCCESS;
}

/**
 * extract key details from x509data node
 * @param env Environment structure
 * @param x509_data_node x509data node. 
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_x509_data(
    const axutil_env_t *env,
    axiom_node_t *x509_data_node,
    oxs_x509_cert_t *cert)
{
    return oxs_xml_key_process_X509Data(env, x509_data_node, cert);
}
