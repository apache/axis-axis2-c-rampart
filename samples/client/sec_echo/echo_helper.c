#include <axiom.h>
#include <axutil_utils.h>
#include <axutil_env.h>
#include <axutil_log_default.h>
#include <axutil_error_default.h>
#include <stdio.h>
#include <axiom_xml_reader.h>
#include <neethi_engine.h>
#include <axis2_policy_include.h>
#include "echo_helper.h"

axis2_status_t AXIS2_CALL
echo_helper_set_policy(axis2_svc_client_t* svc_client,
    const axis2_char_t *client_home,    
    const axutil_env_t *env)
{

    axiom_xml_reader_t *reader = NULL;
    axiom_stax_builder_t *builder = NULL;
    axiom_document_t *document = NULL;
    axiom_node_t *root = NULL;
    axiom_element_t *root_ele = NULL;
    axis2_svc_t *svc = NULL;
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    axis2_char_t *file_name = NULL;

    if(client_home)
    {
        file_name = axutil_stracat(env, client_home, "policy.xml" );
    }
    else{
        return AXIS2_FAILURE;
    }

    reader = axiom_xml_reader_create_for_file(env, file_name, NULL);

    if (!reader)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_CREATING_XML_STREAM_READER,
                AXIS2_FAILURE);
        printf("xml reader creation failed for policy file %s\n", file_name);
        return AXIS2_FAILURE;
    }
    
    builder = axiom_stax_builder_create(env, reader);
    if(!builder)
    {
        axiom_xml_reader_free(reader, env);
        printf("Builder creation failed\n");
        return AXIS2_FAILURE;
    }
    document = axiom_stax_builder_get_document(builder, env);
    if(!document)
    {
        axiom_stax_builder_free(builder, env);
        printf("Document creation failed\n");
        return AXIS2_FAILURE;
    }

    root = axiom_document_build_all(document, env);
    if(!root)
    {
        axiom_stax_builder_free(builder, env);
        return AXIS2_FAILURE;
    }

    if(root)
    {
        if(axiom_node_get_node_type(root, env) == AXIOM_ELEMENT)
        {
            root_ele = (axiom_element_t*)axiom_node_get_data_element(root, env);
            if(root_ele)
            {
                neethi_policy_t *neethi_policy = NULL;
                neethi_policy = neethi_engine_get_policy(env, root, root_ele);    
                if(!neethi_policy)
                {
                    printf("Policy Creation fails\n");
                    return AXIS2_FAILURE;
                }
                svc = axis2_svc_client_get_svc(svc_client, env);
                if(!svc)
                {
                    printf("service is NULL\n");
                    return AXIS2_FAILURE;
                }                    
                desc = axis2_svc_get_base(svc, env);
                if(!desc)
                {
                    printf("Description is NULL\n");
                    return AXIS2_FAILURE;
                }
                policy_include = axis2_desc_get_policy_include(desc, env);
                if(!policy_include)
                {
                    printf("Policy include is NULL");
                    return AXIS2_FAILURE;
                }    
                axis2_policy_include_add_policy_element(policy_include, env, AXIS2_SERVICE_POLICY, neethi_policy);
            }
        }
    }
    printf("Successful\n");
    return AXIS2_SUCCESS;
}


