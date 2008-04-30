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
#include <oxs_error.h>
#include <oxs_axiom.h>
#include <axiom_node.h>
#include <axiom_namespace.h>
#include <axiom_attribute.h>
#include <axiom_element.h>
#include <axiom_document.h>
#include <axiom_stax_builder.h>
#include <axiom_util.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_axiom_add_attribute(const axutil_env_t *env,
                        axiom_node_t* node,
                        axis2_char_t* attribute_ns,
                        axis2_char_t* attribute_ns_uri,
                        axis2_char_t* attribute,
                        axis2_char_t* value)
{
    axiom_attribute_t *attr = NULL;
    axiom_element_t *ele = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_namespace_t *ns = NULL;

    if(attribute_ns_uri)
    {    
        ns =  axiom_namespace_create(env, attribute_ns_uri, attribute_ns);
    }    

    ele =  axiom_node_get_data_element(node, env);
    attr =  axiom_attribute_create(env, attribute , value, ns);
	if(!attr && ns)
	{
		axiom_namespace_free(ns, env);
	}
    status = axiom_element_add_attribute(ele, env, attr, node);
    return status;
}

AXIS2_EXTERN int AXIS2_CALL
oxs_axiom_get_number_of_children_with_qname(const axutil_env_t *env,
        axiom_node_t* parent,
        axis2_char_t* local_name,
        axis2_char_t* ns_uri,
        axis2_char_t* prefix)
{

    axutil_qname_t *qname = NULL;
    axiom_element_t *parent_ele = NULL;
    axiom_children_qname_iterator_t *qname_iter = NULL;
    axiom_node_t *temp_node = NULL;
    int counter = 0;

    qname = axutil_qname_create(env, local_name, ns_uri, prefix);
    parent_ele = axiom_node_get_data_element(parent, env);
    if (!parent_ele)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "Cannot find %s element", local_name);
        return -1;
    }

    qname_iter = axiom_element_get_children_with_qname(parent_ele, env, qname, parent);
    while (AXIS2_TRUE == axiom_children_qname_iterator_has_next(qname_iter , env))
    {

        counter++;
        temp_node = axiom_children_qname_iterator_next(qname_iter, env);
    }
    axutil_qname_free(qname, env);
    qname = NULL;

    return counter;
}

/**
 * Traverse thru the node and its children. Check if the localname is equal to the given name
 * */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_axiom_get_node_by_local_name(const axutil_env_t *env,
                                 axiom_node_t *node,
                                 axis2_char_t *local_name)
{
    axis2_char_t *temp_name = NULL;

    if(!node){return NULL;}

    if(axiom_node_get_node_type(node, env) != AXIOM_ELEMENT){return NULL;}

    temp_name = axiom_util_get_localname(node, env);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][axiom] Checking node %s for %s", temp_name, local_name );

    if(0 == axutil_strcmp(temp_name, local_name) ){
        /*Gottcha.. return this node*/
        return node;
    }else{
        /*Doesn't match? Get the first child*/
        axiom_node_t *temp_node = NULL;

        temp_node = axiom_node_get_first_element(node, env);
        while (temp_node)
        {
            axiom_node_t *res_node = NULL;
            res_node = oxs_axiom_get_node_by_local_name(env, temp_node, local_name);
            if(res_node){
                return res_node;
            }
            temp_node = axiom_node_get_next_sibling(temp_node, env);
        }

    }
    return NULL;
}

/**
 * Traverse thru the node and its children. Check if the id attribute is equal to the given value
 * */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_axiom_get_node_by_id(const axutil_env_t *env,
                         axiom_node_t *node,
                         axis2_char_t *attr,
                         axis2_char_t *val,
                         axis2_char_t *ns)
{
    axis2_char_t *attribute_value = NULL;
    axis2_char_t *localname = NULL;

    if(!node){return NULL;}

    if(axiom_node_get_node_type(node, env) != AXIOM_ELEMENT){return NULL;}

    localname = axiom_util_get_localname(node, env);
    attribute_value = oxs_axiom_get_attribute_value_of_node_by_name(env, node, attr, ns);
    
    if(0 == axutil_strcmp(val, attribute_value) ){
        /*Gottcha.. return this node*/
        return node;
    }else{
        /*Doesn't match? Get the first child*/
        axiom_node_t *temp_node = NULL;

        temp_node = axiom_node_get_first_element(node, env);
        while (temp_node)
        {
            axiom_node_t *res_node = NULL;
            res_node = oxs_axiom_get_node_by_id(env, temp_node, attr, val, ns);
            if(res_node){
                return res_node;
            }
            temp_node = axiom_node_get_next_sibling(temp_node, env);
        }

    }
    return NULL;
}


AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_axiom_get_attribute_value_of_node_by_name(const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *attribute_name,
        axis2_char_t *ns)
{
    axis2_char_t *attribute_value = NULL;
    axiom_element_t *ele = NULL;
    axutil_qname_t *qname = NULL;

    ele = axiom_node_get_data_element(node, env);
    qname = axutil_qname_create(env, attribute_name, ns , NULL);
    attribute_value = oxs_axiom_get_attribute_val_of_node_by_qname(env, node, qname);
    axutil_qname_free(qname, env);
    qname = NULL;
    return attribute_value;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_axiom_get_attribute_val_of_node_by_qname(const axutil_env_t *env,
        axiom_node_t *node,
        axutil_qname_t *qname)
{
    /*Qname might NOT contain the prefix*/
    axiom_element_t *ele = NULL;
    axutil_hash_t *attr_list = NULL;
    axutil_hash_index_t *hi = NULL;
    axis2_char_t *local_name = NULL;
    axis2_char_t *ns_uri = NULL;
    axis2_char_t *found_val = NULL;

    ele = axiom_node_get_data_element(node, env);

    /*Get attribute list of the element*/
    attr_list = axiom_element_extract_attributes(ele, env, node);
    if(!attr_list){
        return NULL;
    }
    /*Get localname of the qname*/
    local_name =  axutil_qname_get_localpart(qname, env);
    /*Get nsuri of the qname*/
    ns_uri = axutil_qname_get_uri(qname, env);
    if(!ns_uri){
        ns_uri = "";
    }
    /*Traverse thru all the attributes. If both localname and the nsuri matches return the val*/
    for (hi = axutil_hash_first(attr_list, env); hi; hi = axutil_hash_next(env, hi))
    {
        void *attr = NULL;
        axiom_attribute_t *om_attr = NULL;
        axutil_hash_this(hi, NULL, NULL, &attr);
        if (attr)
        {
            axis2_char_t *this_attr_name = NULL;
            axis2_char_t *this_attr_ns_uri = NULL;
            axiom_namespace_t *attr_ns = NULL;

            om_attr = (axiom_attribute_t*)attr;
            this_attr_name = axiom_attribute_get_localname(om_attr, env);
            attr_ns = axiom_attribute_get_namespace(om_attr, env);
            if(attr_ns){
                this_attr_ns_uri = axiom_namespace_get_uri(attr_ns, env);
            }else{
                this_attr_ns_uri = "";
            }
            if(0 == axutil_strcmp(local_name, this_attr_name) && 0 == axutil_strcmp(ns_uri, this_attr_ns_uri))
            {
                /*Got it !!!*/
                found_val = axiom_attribute_get_value(om_attr, env);
				if (env)
					AXIS2_FREE(env->allocator, hi);
                break;
            }
        }
    }

    for(hi = axutil_hash_first(attr_list, env); hi; hi = axutil_hash_next(env, hi))
    {
        void *val = NULL;
        axutil_hash_this(hi, NULL, NULL, &val);
        if (val)
        {
            axiom_attribute_free((axiom_attribute_t *)val, env);
            val = NULL;
        }
    }
    axutil_hash_free(attr_list, env);
    attr_list = NULL;

    return found_val;
}


AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_axiom_get_first_child_node_by_name(const axutil_env_t *env,
                                       axiom_node_t* parent,
                                       axis2_char_t* local_name,
                                       axis2_char_t* ns_uri,
                                       axis2_char_t* prefix)
{
    axutil_qname_t *qname = NULL;
    axiom_node_t *node = NULL;
    axiom_element_t *parent_ele = NULL;
    axiom_element_t *ele = NULL;
    axis2_char_t *parent_name = NULL;

    qname = axutil_qname_create(env, local_name, ns_uri, prefix);
    parent_ele = axiom_node_get_data_element(parent, env);
    if (!parent_ele)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "Cannot find %s element", local_name);
        return NULL;
    }
    /*Get the child*/
    ele = axiom_element_get_first_child_with_qname(parent_ele, env, qname, parent, &node);

    axutil_qname_free(qname, env);
    qname = NULL;

    if (!node)
    {
		parent_name = axiom_node_to_string(parent, env);
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "Cannot find child %s of %s", local_name, parent_name);
		AXIS2_FREE(env->allocator, parent_name);
        return NULL;
    }
    return node;
}


AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_axiom_get_node_content(const axutil_env_t *env, axiom_node_t* node)
{
    axiom_element_t *ele = NULL;
    axis2_char_t *content = NULL;

    ele = axiom_node_get_data_element(node, env);
    if (!ele) return NULL;

    content = axiom_element_get_text(ele, env, node);
    if (!content) return NULL;

    return content;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
oxs_axiom_deserialize_node(const axutil_env_t *env,  axis2_char_t* buffer)
{
    axiom_document_t *doc = NULL;
    axiom_stax_builder_t *builder = NULL;
    axiom_xml_reader_t *reader = NULL;
    axiom_node_t *node = NULL;

    if (!buffer)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "buffer is NULL");
        return NULL;
    }
    reader = axiom_xml_reader_create_for_memory(env,
             (void*)buffer, axutil_strlen(buffer), "utf-8", AXIS2_XML_PARSER_TYPE_BUFFER);

    if (!reader)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "axiom_xml_reader is NULL");
        return NULL;
    }

    builder = axiom_stax_builder_create(env, reader);
    if (!builder)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "axiom_stax_builder is NULL");
        return NULL;
    }

    doc = axiom_document_create(env, NULL, builder);
    if (!doc)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "axiom_document is NULL");
        return NULL;
    }
    node = axiom_document_build_all(doc, env);
    if (!node)
    {
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA,
                  "Building node failed");
		axiom_document_free(doc, env);
        return NULL;
    }
    axiom_stax_builder_free_self(builder, env);
    builder = NULL;

	axiom_document_free_self(doc, env);
	doc = NULL;

    /*The stax builder will free the reader.*/
    /*axiom_xml_reader_free(reader, env);
    reader = NULL;*/

    return node;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_axiom_check_node_name(const axutil_env_t *env, axiom_node_t* node, axis2_char_t* name, axis2_char_t* ns)
{
    int ret_name, ret_ns;
    axiom_element_t * ele = NULL;
    axis2_char_t* namestr = NULL;
    axis2_char_t* ns_str = NULL;
    axutil_qname_t* qname = NULL;

    ele = axiom_node_get_data_element(node, env);
    qname = axiom_element_get_qname(ele, env, node);

    namestr = axutil_qname_get_localpart(qname, env);
    ret_name =  axutil_strcmp(namestr, name) ;


    if (ret_name < 0) return 0;

    if (ns)
    {
        ns_str = axutil_qname_get_uri(qname, env);
        ret_ns =  axutil_strcmp(ns_str, ns) ;
        if (ret_ns < 0) return AXIS2_FAILURE;
        else   return AXIS2_SUCCESS;

    }
    else
    {
        return AXIS2_SUCCESS;
    }


}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_axiom_interchange_nodes(const axutil_env_t *env,
                          axiom_node_t *node_to_move,
                          axiom_node_t *node_before)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *temp_node = NULL;

    temp_node = axiom_node_detach(node_to_move,env);
    status = axiom_node_insert_sibling_before(node_before, env, temp_node);

    return status;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_axiom_add_as_the_first_child(const axutil_env_t *env,
                          axiom_node_t *parent,
                          axiom_node_t *child)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *first_child = NULL;
    
    first_child = axiom_node_get_first_child(parent, env);
    status = axiom_node_insert_sibling_before(first_child, env, child);

    return status;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_axiom_get_first_node_by_name_and_attr_val_from_xml_doc(
						 const axutil_env_t *env,
						 axiom_node_t *node,
						 axis2_char_t *e_name,
						 axis2_char_t *e_ns,
						 axis2_char_t *attr_name,
						 axis2_char_t *attr_val,
						 axis2_char_t *attr_ns)
{
	axiom_node_t *p = NULL;	
	axiom_node_t *root = NULL;
	p = node;
	do 
	{
		root = p;
		p = axiom_node_get_parent(root, env);	
	} while (p);	
	return oxs_axiom_get_first_node_by_name_and_attr_val(env, root, e_name,
						 e_ns, attr_name, attr_val, attr_ns);
}

AXIS2_EXTERN axiom_node_t* AXIS2_CALL
oxs_axiom_get_first_node_by_name_and_attr_val(const axutil_env_t *env,
                         axiom_node_t *node,
						 axis2_char_t *e_name,
						 axis2_char_t *e_ns,
                         axis2_char_t *attr_name,
                         axis2_char_t *attr_val,
                         axis2_char_t *attr_ns)
{
    axis2_char_t *attribute_value = NULL;
    axis2_char_t *localname = NULL;    
	axiom_namespace_t *nmsp = NULL;
	axiom_element_t *e = NULL;
    axis2_bool_t element_match = AXIS2_FALSE;
	axiom_node_t *temp_node = NULL;

	if (axiom_node_get_node_type(node, env) != AXIOM_ELEMENT){return NULL;}
	e = axiom_node_get_data_element(node, env);
    
	localname = axiom_element_get_localname(e, env);   
	if (localname && 0 == axutil_strcmp(localname, e_name))
	{
		element_match = AXIS2_TRUE;
		if (e_ns)
		{
			axis2_char_t *namespacea = NULL;
			nmsp = axiom_element_get_namespace(e, env, node);
			if (nmsp)
			{
				namespacea = axiom_namespace_get_uri(nmsp, env);
				if (0 != axutil_strcmp(e_ns, namespacea))
				{
					element_match = AXIS2_FALSE;
				}
			}
		}
		if (element_match == AXIS2_TRUE)
		{
			if (attr_ns)
			{
				axiom_attribute_t *attr = NULL;
				axutil_qname_t *qname = axutil_qname_create(env, attr_name, attr_ns, NULL);
				attr = axiom_element_get_attribute(e, env, qname);
				attribute_value = axiom_attribute_get_value(attr, env);
				axutil_qname_free(qname, env);
			}
			else
			{
				attribute_value = axiom_element_get_attribute_value_by_name(e, env, attr_name);
			}
		}
		if (attribute_value && 0 == axutil_strcmp(attribute_value, attr_val))
		{
			return node;
		}
	}        
    /*Doesn't match? Get the first child*/    
    temp_node = axiom_node_get_first_element(node, env);
    while (temp_node)
    {
        axiom_node_t *res_node = NULL;
        res_node = oxs_axiom_get_first_node_by_name_and_attr_val(env, temp_node, e_name, e_ns, attr_name, attr_val, attr_ns);
        if (res_node)
		{
            return res_node;
        }
        temp_node = axiom_node_get_next_sibling(temp_node, env);
    }    
    return NULL;
}

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
oxs_axiom_clone_node(const axutil_env_t *env,
                         axiom_node_t *node)
{
    axis2_char_t* node_string = NULL;
    axiom_xml_reader_t *reader = NULL;
    axiom_document_t *doc = NULL;
    axiom_stax_builder_t *builder = NULL;
    axiom_node_t *clone = NULL;

    if(!node)
        return NULL;

    node_string = axiom_node_sub_tree_to_string(node, env);
    reader = axiom_xml_reader_create_for_memory(env, node_string, axutil_strlen(node_string),
                                               NULL,
                                               AXIS2_XML_PARSER_TYPE_BUFFER);

    builder = axiom_stax_builder_create(env, reader);
    doc = axiom_document_create(env, NULL, builder);
    clone = axiom_document_build_all(doc, env);

    axiom_xml_reader_xml_free(reader, env, NULL);
    if(node_string)
        AXIS2_FREE(env->allocator, node_string);

    return clone;
}
