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

#include <saml.h>
#include <saml_req.h>

AXIS2_EXTERN int AXIS2_CALL saml_util_set_sig_ctx_defaults(oxs_sign_ctx_t *sig_ctx, axutil_env_t *env, axis2_char_t *id)
{
	oxs_sign_part_t* sig_part = NULL;
	oxs_transform_t *tr = NULL;	
	axutil_array_list_t *sig_parts = NULL, *trans = NULL;
	axiom_namespace_t *ns = NULL;
	trans = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);

	/*create transform sor SAML XML signature with identifier*/
	tr = oxs_transforms_factory_produce_transform(env, OXS_HREF_TRANSFORM_ENVELOPED_SIGNATURE);
	axutil_array_list_add(trans, env, tr);

    /*Create the EXCL-C14N Transformation*/
    tr = oxs_transforms_factory_produce_transform(env, OXS_HREF_TRANSFORM_XML_EXC_C14N);
    axutil_array_list_add(trans, env, tr);

	sig_part = oxs_sign_part_create(env);
	oxs_sign_part_set_digest_mtd(sig_part, env, OXS_HREF_SHA1);

	
	oxs_sign_part_set_transforms(sig_part, env, trans);
	oxs_sign_part_set_id_name(sig_part, env, id);

	//ns = axiom_namespace_create(env, "", "");
	//oxs_sign_part_set_sign_namespace(sig_part,env, ns);

	sig_parts = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	axutil_array_list_add(sig_parts, env, sig_part);
	
	/*create the specific sign context*/
	
	oxs_sign_ctx_set_c14n_mtd(sig_ctx, env, OXS_HREF_XML_EXC_C14N);
	oxs_sign_ctx_set_operation(sig_ctx, env, OXS_SIGN_OPERATION_SIGN);
	oxs_sign_ctx_set_sign_mtd_algo(sig_ctx, env, OXS_HREF_RSA_SHA1);
	oxs_sign_ctx_set_sign_parts(sig_ctx, env, sig_parts);

	return AXIS2_SUCCESS;
}
