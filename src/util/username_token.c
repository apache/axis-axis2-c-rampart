/*
 *Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <axis2_qname.h>
#include <axis2_svc.h>
#include <axiom_soap_header.h>
#include <axiom_soap_body.h>
#include <axiom_soap_header_block.h>
#include <axis2_endpoint_ref.h>
#include <axis2_property.h>
#include <rampart_username_token.h>
#include <rampart_constants.h>
#include <rampart_crypto_util.h>
#include <rampart_util.h>
#include <rampart_callback.h>
#include <rampart_handler_util.h>

typedef struct rampart_username_token_impl
{
    rampart_username_token_t username_token;
}
rampart_username_token_impl_t;

/** Interface to implementation conversion macro */
#define AXIS2_INTF_TO_IMPL(username_token) ((rampart_username_token_impl_t *)username_token)

/*************************** Function headers *********************************/
/** private functions */
static void
rampart_username_token_init_ops(
    rampart_username_token_t *username_token);
/**
 * Get the password for given outflow security configuration
 * @param env pointer to environment struct
 * @param ctx axis2 context
 * @param Outflow security parameter
 * @return password
 */                  
static axis2_char_t* 
rampart_get_password( const axis2_env_t *env,
                      axis2_ctx_t *ctx,
                      rampart_actions_t *actions);          
/**
 *
 * @param env pointer to environment struct
 * @param ctx axis2 context
 * @return property value
 */
static axis2_char_t* 
rampart_username_token_callback_pw( const axis2_env_t *env,
                     axis2_char_t *callback_module_name,
                     const axis2_char_t *username);

/** public functions*/                  
axis2_status_t AXIS2_CALL
rampart_username_token_free(rampart_username_token_t *username_token,
    const axis2_env_t *env);
 
axis2_status_t AXIS2_CALL
rampart_username_token_build(rampart_username_token_t *username_token,
    const axis2_env_t *env,
    axis2_ctx_t *ctx,
    rampart_actions_t *actions,
    axiom_node_t *sec_node,
    axiom_namespace_t *sec_ns_obj);


axis2_status_t AXIS2_CALL
rampart_username_token_validate(rampart_username_token_t *username_token,
    const axis2_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axiom_soap_header_t *soap_header,
    rampart_actions_t *actions);

/************************* End of function headers ****************************/
static void
rampart_username_token_init_ops(
    rampart_username_token_t *username_token)
{
    username_token->ops->free = rampart_username_token_free;
    username_token->ops->build = rampart_username_token_build;
    username_token->ops->validate = rampart_username_token_validate;
}


static axis2_char_t *
rampart_get_password( const axis2_env_t *env,
        axis2_ctx_t *ctx,
        rampart_actions_t *actions)
{
    axis2_char_t *password = NULL;
    axis2_char_t *username = NULL;
    axis2_char_t *pw_callback_module = NULL;

    /*Check if password is in the context.
     i.e.In any context in the cotext hierarchy starting from msg, op, svc, etc.*/
    password = rampart_get_property_from_ctx(env, ctx,  RAMPART_ACTION_PASSWORD);
    if(password)
    {
        return password;
    }
    
    /*If not check weather there is a callback class specified*/
    pw_callback_module = RAMPART_ACTIONS_GET_PW_CB_CLASS(actions, env);
    if(pw_callback_module)
    {
        username = RAMPART_ACTIONS_GET_USER(actions, env);
        password = rampart_username_token_callback_pw(env, pw_callback_module, username);    
    }
    return password;
}


static axis2_char_t* 
rampart_username_token_callback_pw( const axis2_env_t *env,
                     axis2_char_t *callback_module_name,
                     const axis2_char_t *username)
{
    rampart_callback_t* rcb = NULL;
    axis2_char_t *password = NULL;
    axis2_dll_desc_t *dll_desc = NULL;
    void *ptr = NULL;
    axis2_param_t *impl_info_param = NULL;

    dll_desc = axis2_dll_desc_create(env);
    AXIS2_DLL_DESC_SET_NAME(dll_desc, env, callback_module_name);
    impl_info_param = axis2_param_create(env, NULL, NULL);
    AXIS2_PARAM_SET_VALUE(impl_info_param, env, dll_desc);
    axis2_class_loader_init(env);
    ptr = axis2_class_loader_create_dll(env, impl_info_param);

    /*callback()*/
    if(!ptr)
    {
        printf("\nCallback ptr is null");
        return NULL;
    }

    rcb = (rampart_callback_t*)ptr;
    if(!rcb)
    {
        printf("\nrampart_callback_t is null");
        return NULL;
    }
    /*Get the password thru the callback*/
    password = RAMPART_CALLBACK_CALLBACK_PASSWORD(rcb, env, username);

    return password;
}

rampart_username_token_t *AXIS2_CALL
rampart_username_token_create(
    const axis2_env_t *env)
{
    rampart_username_token_impl_t *username_token_impl = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    username_token_impl =  (rampart_username_token_impl_t *) AXIS2_MALLOC (env->allocator,
    sizeof (rampart_username_token_impl_t));

    if(NULL == username_token_impl)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    username_token_impl->username_token.ops = AXIS2_MALLOC (env->allocator,
                                        sizeof(rampart_username_token_ops_t));
    if(NULL == username_token_impl->username_token.ops)
    {
        rampart_username_token_free(&(username_token_impl->username_token), env);
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    rampart_username_token_init_ops(&(username_token_impl->username_token));

    return &(username_token_impl->username_token);

}

axis2_status_t AXIS2_CALL
rampart_username_token_free(rampart_username_token_t *username_token,
    const axis2_env_t *env)
{
    rampart_username_token_impl_t *username_token_impl = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    username_token_impl = AXIS2_INTF_TO_IMPL(username_token);

    if(username_token->ops)
    {
        AXIS2_FREE(env->allocator, username_token->ops);
        username_token->ops = NULL;
    }
    if(username_token_impl)
    {
        AXIS2_FREE(env->allocator, username_token_impl);
        username_token_impl = NULL;
    }
    return AXIS2_SUCCESS;

}

axis2_status_t AXIS2_CALL
rampart_username_token_build(rampart_username_token_t *username_token,
    const axis2_env_t *env,
    axis2_ctx_t *ctx,
    rampart_actions_t *actions,
    axiom_node_t *sec_node,
    axiom_namespace_t *sec_ns_obj
    )
{

    axiom_node_t  *ut_node, *un_node, *pw_node, *nonce_node, *created_node = NULL;    
    axiom_element_t  *ut_ele, *un_ele, *pw_ele,  *nonce_ele, *created_ele = NULL;
    axis2_char_t *username, *password,  *password_type = NULL;
    axis2_char_t *nonce_val, *created_val, *digest_val = NULL;
    axiom_namespace_t *wsu_ns_obj = NULL;
    axiom_attribute_t *om_attr = NULL;
    rampart_username_token_impl_t *username_token_impl = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    username_token_impl = AXIS2_INTF_TO_IMPL(username_token);

    /*Get values from outflow security*/
    
    username = RAMPART_ACTIONS_GET_USER(actions, env);
    password_type = RAMPART_ACTIONS_GET_PASSWORD_TYPE(actions, env);

    password = rampart_get_password(env, ctx, actions);
    
    if(!password)
    {
        return AXIS2_FAILURE;
    }   
 
    ut_ele = axiom_element_create (env, sec_node, 
                                        RAMPART_SECURITY_USERNAMETOKEN, 
                                        sec_ns_obj,
                                        &ut_node);

    wsu_ns_obj = axiom_namespace_create (env, RAMPART_WSU_XMLNS,
                                              RAMPART_WSU);
    AXIOM_ELEMENT_DECLARE_NAMESPACE (ut_ele, env,
                                         ut_node, wsu_ns_obj);

    if(NULL != ut_ele)
    {
               
         un_ele = axiom_element_create (env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_USERNAME, sec_ns_obj,
                                             &un_node);
        if(NULL != un_ele)
        {
            axiom_namespace_t *dec_ns = NULL;
            AXIOM_ELEMENT_SET_TEXT (un_ele, env, username, un_node);
            dec_ns = AXIOM_ELEMENT_FIND_DECLARED_NAMESPACE(un_ele, env, 
                                                                     RAMPART_WSSE_XMLNS,
                                                                    RAMPART_WSSE);


            AXIOM_ELEMENT_SET_NAMESPACE(un_ele, env, sec_ns_obj, un_node);

         }        

        if(0 == AXIS2_STRCMP(password_type, RAMPART_PASSWORD_DIGEST) )
        {   
            axiom_namespace_t *dec_ns = NULL;
          
            nonce_val = rampart_generate_nonce(env) ;
            created_val = rampart_generate_time(env,0);
            digest_val = rampart_crypto_sha1(env, nonce_val, created_val, password);

            pw_ele = axiom_element_create (env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD, sec_ns_obj,
                                             &pw_node);
            if(NULL != pw_ele)
            {               

                AXIOM_ELEMENT_SET_TEXT (pw_ele, env, digest_val, pw_node);
                dec_ns = AXIOM_ELEMENT_FIND_DECLARED_NAMESPACE(pw_ele, env, 
                                                             RAMPART_WSSE_XMLNS,
                                                            RAMPART_WSSE);


                 om_attr = axiom_attribute_create (env,
                                    RAMPART_SECURITY_USERNAMETOKEN_PASSWORD_ATTR_TYPE,
                                    RAMPART_PASSWORD_DIGEST_URI,                                    
                                    NULL);

                AXIOM_ELEMENT_ADD_ATTRIBUTE (pw_ele, env,
                                om_attr, pw_node);

             }                 
            
            nonce_ele = axiom_element_create (env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_NONCE, sec_ns_obj,
                                             &nonce_node);
            if(NULL != nonce_ele)
            {
                axiom_namespace_t *dec_ns = NULL;
                AXIOM_ELEMENT_SET_TEXT (nonce_ele, env, nonce_val , nonce_node);
                dec_ns = AXIOM_ELEMENT_FIND_DECLARED_NAMESPACE(nonce_ele, env, 
                                                             RAMPART_WSSE_XMLNS,
                                                            RAMPART_WSSE);
            }       

            created_ele = axiom_element_create (env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_CREATED, sec_ns_obj,
                                             &created_node);
            if(NULL != created_ele)
            {
                axiom_namespace_t *dec_ns = NULL;
                AXIOM_ELEMENT_SET_TEXT (created_ele, env, created_val, created_node);
                dec_ns = AXIOM_ELEMENT_FIND_DECLARED_NAMESPACE(created_ele, env, 
                                                             RAMPART_WSSE_XMLNS,
                                                            RAMPART_WSSE);

                AXIOM_ELEMENT_SET_NAMESPACE(created_ele, env, wsu_ns_obj, created_node);

            }       
            /*
            AXIS2_FREE(env->allocator, nonce_val);
            AXIS2_FREE(env->allocator, created_val);
            AXIS2_FREE(env->allocator, digest_val);
            */
        }else /*default is passwordText*/ 
        {
            pw_ele = axiom_element_create (env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD, sec_ns_obj,
                                             &pw_node);
            if(NULL != pw_ele)
            {
                axiom_namespace_t *dec_ns = NULL;
                AXIOM_ELEMENT_SET_TEXT (pw_ele, env, password, pw_node);
                dec_ns = AXIOM_ELEMENT_FIND_DECLARED_NAMESPACE(pw_ele, env, 
                                                             RAMPART_WSSE_XMLNS,
                                                            RAMPART_WSSE);
             }                 
         } /*End if passwordType == passwordText*/
    }
    return AXIS2_SUCCESS;
}

axis2_status_t AXIS2_CALL
rampart_username_token_validate(rampart_username_token_t *username_token,
    const axis2_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axiom_soap_header_t *soap_header,
    rampart_actions_t *actions)
{
    axiom_element_t *sec_ele, *ut_ele = NULL;
    axiom_node_t *sec_node, *ut_node = NULL;
    axiom_child_element_iterator_t *children = NULL;
    axis2_char_t *username = NULL, 
       *password = NULL, *nonce = NULL, *created = NULL, *password_type = NULL;    
    axis2_char_t *pw_callback_module = NULL, *password_from_svr = NULL, *password_to_compare = NULL;
    axis2_ctx_t *ctx = NULL;
    axis2_qname_t *qname = NULL;
    rampart_username_token_impl_t *username_token_impl = NULL;

    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    username_token_impl = AXIS2_INTF_TO_IMPL(username_token);

    sec_node = rampart_get_security_token(env, msg_ctx, soap_header);
    if(!sec_node)
    {
        AXIS2_LOG_INFO(env->log," Cannot find sec_node.. :(");
        return AXIS2_FAILURE;
    }
    
    sec_ele = AXIOM_NODE_GET_DATA_ELEMENT(sec_node, env);
    if(!sec_ele)
    {
        AXIS2_LOG_INFO(env->log," Cannot find sec_ele... :(");
        return AXIS2_FAILURE;
    }

    /*TODO Get sec_ele with QNAME*/

    qname = axis2_qname_create(env,
                                 RAMPART_SECURITY_USERNAMETOKEN,
                                 RAMPART_WSSE_XMLNS,
                                 RAMPART_WSSE);
    if(qname)
    {
        ut_ele = AXIOM_ELEMENT_GET_FIRST_CHILD_WITH_QNAME(sec_ele, env, qname, sec_node, &ut_node);
        if(!ut_ele)
        {
            AXIS2_LOG_INFO(env->log,"Cannot find UsernameToken in Security element...");
            return AXIS2_FAILURE;
        }
    }


    /*Get children of UsernameToken element*/
    children = AXIOM_ELEMENT_GET_CHILD_ELEMENTS(ut_ele, env, ut_node);
    if(children)
    {
        /*Go thru children and find username token parameters*/
        while(AXIS2_TRUE == AXIOM_CHILD_ELEMENT_ITERATOR_HAS_NEXT(children, env))
        {
            axiom_node_t *node = NULL;
            axiom_element_t *element = NULL;
            axis2_char_t *localname = NULL;

            node = AXIOM_CHILD_ELEMENT_ITERATOR_NEXT(children, env);
            element = AXIOM_NODE_GET_DATA_ELEMENT(node, env);
            localname =  AXIOM_ELEMENT_GET_LOCALNAME(element, env);
            
            if(0 == AXIS2_STRCMP(localname, RAMPART_SECURITY_USERNAMETOKEN_USERNAME ))
            {
                    username = AXIOM_ELEMENT_GET_TEXT(element, env, node);                

            }else if(0 == AXIS2_STRCMP(localname , RAMPART_SECURITY_USERNAMETOKEN_PASSWORD )){
                    password_type = AXIOM_ELEMENT_GET_ATTRIBUTE_VALUE_BY_NAME(element, 
                                            env,
                                            RAMPART_SECURITY_USERNAMETOKEN_PASSWORD_ATTR_TYPE);
                                            
                    if(!password_type)
                    {
                        password_type = RAMPART_PASSWORD_TEXT_URI;
                    } 
                       

                    password = AXIOM_ELEMENT_GET_TEXT(element, env, node);        

            }else if(0 == AXIS2_STRCMP(localname,  RAMPART_SECURITY_USERNAMETOKEN_NONCE )){
                    nonce = AXIOM_ELEMENT_GET_TEXT(element, env, node);

            }else if(0 == AXIS2_STRCMP(localname ,  RAMPART_SECURITY_USERNAMETOKEN_CREATED )){
                    created = AXIOM_ELEMENT_GET_TEXT(element, env, node);

            }else {
                    AXIS2_LOG_INFO(env->log,"\nUnknown element found %s -> %s", localname, AXIOM_ELEMENT_GET_TEXT(element, env, node));
            }

 
        }/*end of while*/
    }else {
        AXIS2_LOG_INFO(env->log,"Cannot find child elements of Usernametoken");
        return AXIS2_FAILURE;
    }

    /*Now we process collected usernametoken parameters*/    
    if(!username)
    {
        return AXIS2_FAILURE;
    }

    ctx = AXIS2_MSG_CTX_GET_BASE (msg_ctx, env); 
    pw_callback_module = RAMPART_ACTIONS_GET_PW_CB_CLASS(actions, env);

    password_from_svr = rampart_username_token_callback_pw(env,pw_callback_module, username);
   
    if(!password_from_svr)
    {
        return AXIS2_FAILURE; 
    }
    /*Alright NOW we have the password. Is digest needed?*/
    if(0 == AXIS2_STRCMP(password_type, RAMPART_PASSWORD_DIGEST_URI))
    {
        password_to_compare = rampart_crypto_sha1(env, nonce, created, password_from_svr);
    }else {
        password_to_compare = password_from_svr;
    }
    
    /*The BIG moment. Compare passwords*/
    if(0 == AXIS2_STRCMP(password_to_compare , password))
    {
        return AXIS2_SUCCESS;
    }else{
        return AXIS2_FAILURE;
    }
       return AXIS2_SUCCESS;
}
