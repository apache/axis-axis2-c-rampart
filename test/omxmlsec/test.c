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
#include <oxs_constants.h>
#include <oxs_utility.h>
#include <axiom.h>
#include <axiom_xml_reader.h>
#include <axis2_env.h>
#include <oxs_ctx.h>
#include <oxs_key.h>
#include <oxs_error.h>
#include <oxs_xml_signature.h>
#include <oxs_sign_ctx.h>
#include <oxs_sign_part.h>

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
load_sample_xml(const axis2_env_t *env,
        axiom_node_t* tmpl,
        axis2_char_t* filename
               )
{

    axiom_document_t *doc = NULL;
    axiom_stax_builder_t *builder = NULL;
    axiom_xml_reader_t *reader = NULL;
    /*axiom_xml_writer_t *writer = NULL;*/

    reader = axiom_xml_reader_create_for_file(env, filename, NULL);
    if (!reader) printf("\n Reader is NULL");
    builder = axiom_stax_builder_create(env, reader);
    if (!builder) printf("\n builder is NULL");
    doc = axiom_document_create(env, NULL, builder);
    if (!doc) printf("\n doc is NULL");
    tmpl = AXIOM_DOCUMENT_BUILD_ALL(doc, env);

    /*    tmpl = AXIOM_DOCUMENT_GET_ROOT_ELEMENT(doc, env);*/
    if (!tmpl) printf("\n tmpl is NULL");
    return tmpl;
}

axis2_env_t *test_init()
{
    axis2_allocator_t *allocator = axis2_allocator_init(NULL);
    axis2_error_t *error = (axis2_error_t*)axis2_error_create(allocator);
    axis2_env_t *env = axis2_env_create_with_error(allocator, error);
    return env;
}

int main(int argc, char *argv[])
{
    axis2_env_t *env = NULL;
    axis2_char_t *filename = "input.xml";
    axis2_char_t *signed_result = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *tmpl = NULL;
    oxs_sign_part_t *sign_part = NULL;
    oxs_sign_ctx_t *sign_ctx = NULL;
    FILE *outf;

    env = axis2_env_create_all("echo.log", AXIS2_LOG_LEVEL_TRACE);
    printf("--Testing started--------------------------------------------\n");

    if (argc > 1)
        filename = argv[1];

    tmpl = load_sample_xml(env , tmpl, filename);

    if (tmpl)
    {
        printf("load_sample_xml SUCCESS\n");
    }
    else
    {
        printf("load_sample_xml FAILED");
        return -1;
    }
    
    /*Sign specific*/
    sign_part = oxs_sign_part_create(env);
    status = oxs_sign_part_set_node(sign_part, env, AXIOM_NODE_GET_FIRST_CHILD(tmpl, env));

    sign_ctx = oxs_sign_ctx_create(env);

    
    signed_result = AXIOM_NODE_TO_STRING(tmpl, env) ;

    outf = fopen("result.xml", "wb");
    fwrite(signed_result, 1, AXIS2_STRLEN(signed_result), outf);
    fclose(outf);
    return 0;
}
