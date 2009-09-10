
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
#include <axis2_const.h>
#include <axutil_error.h>
#include <axutil_utils_defines.h>
#include <axutil_utils.h>
#include <axutil_env.h>
#include <axutil_string.h>
#include <axutil_array_list.h>
#include <axiom_element.h>
#include <axiom_children_iterator.h>
#include <axiom_document.h>
#include <axiom_comment.h>
#include <oxs_constants.h>
#include <oxs_c14n.h>
#include "c14n_sorted_list.h"

#define N_C14N_DEBUG

#define DEFAULT_STACK_SIZE 16
#define INIT_BUFFER_SIZE 256

#define c14n_ns_stack_push(save_stack, ctx) \
        (save_stack)->head = (ctx)->ns_stack->head; \
        (save_stack)->def_ns = (ctx)->ns_stack->def_ns;

#define c14n_ns_stack_pop(saved_stack, ctx) \
    (ctx)->ns_stack->head = (saved_stack)->head; \
    (ctx)->ns_stack->def_ns = (saved_stack)->def_ns;

#define c14n_ns_stack_set_default(ns, ctx) \
        ((ctx)->ns_stack->def_ns = (ns))

#define c14n_ns_stack_get_default(ctx) \
        ((ctx)->ns_stack->def_ns)

#define C14N_GET_ROOT_NODE_FROM_DOC_OR_NODE(doc, node, ctx) \
    ((doc) ? axiom_document_get_root_element((axiom_document_t *)(doc), \
        (ctx)->env) : c14n_get_root_node((node), (ctx)))

typedef enum {
    C14N_XML_C14N = 1,
    C14N_XML_C14N_WITH_COMMENTS,
    C14N_XML_EXC_C14N,
    C14N_XML_EXC_C14N_WITH_COMMENTS,
} c14n_algo_t;

typedef struct c14n_ns_stack {
    int head; /*index of the currnt stack TOP*/
    int size; /*total size allocated for current stack*/
    axiom_namespace_t **stack; /*namespace array*/
    axiom_namespace_t *def_ns; /*default ns in current scope*/
} c14n_ns_stack_t;

typedef struct c14n_ctx {
    const axutil_env_t *env;
    const axiom_document_t *doc;
    axis2_bool_t comments;
    axutil_stream_t *outstream;
    axis2_bool_t exclusive;
    const axutil_array_list_t *ns_prefixes;
    const axiom_node_t *node;
    c14n_ns_stack_t *ns_stack;
} c14n_ctx_t;

/*Function prototypes for ns stack*/

static c14n_ns_stack_t*
c14n_ns_stack_create(
    const c14n_ctx_t *ctx
);

static void
c14n_ns_stack_free(
    c14n_ctx_t *ctx
);

static axis2_status_t
c14n_ns_stack_find(
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx
);

static axis2_status_t
c14n_ns_stack_find_with_prefix_uri(
    const axis2_char_t *prefix,
    const axis2_char_t *uri,
    const c14n_ctx_t *ctx
);

static axis2_status_t
c14n_ns_stack_add(
    axiom_namespace_t *ns,
    const c14n_ctx_t *ctx
);

/*ns stack implementation*/

static c14n_ns_stack_t*
c14n_ns_stack_create(
    const c14n_ctx_t *ctx)
{
    c14n_ns_stack_t *ns_stack = NULL;
    ns_stack = (c14n_ns_stack_t *) (AXIS2_MALLOC(ctx->env->allocator, sizeof(c14n_ns_stack_t)));
    if(!ns_stack)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(ctx->env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n ns stack. Insufficient memory");
        return NULL;
    }

    ns_stack->head = 0;
    ns_stack->size = 0;
    ns_stack->stack = NULL;
    ns_stack->def_ns = NULL;
    return ns_stack;
}

static axis2_status_t c14n_ns_stack_add(
    axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    c14n_ns_stack_t *ns_stack = ctx->ns_stack;

    if(!ns_stack->stack)
    {
        ns_stack->stack = (axiom_namespace_t **) (AXIS2_MALLOC(ctx->env->allocator,
            sizeof(axiom_namespace_t*) * DEFAULT_STACK_SIZE));
        if(!ns_stack->stack)
        {
            AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
        else
            ns_stack->size = DEFAULT_STACK_SIZE;
    }
    else if(ns_stack->head >= ns_stack->size)
    {
        int size = 2 * ns_stack->size;
        axiom_namespace_t **tmp_stack = (axiom_namespace_t **) (AXIS2_MALLOC(ctx->env->allocator,
            sizeof(axiom_namespace_t*) * size));
        if(tmp_stack)
        {
            /*int i = 0;*/
            /* TODO:DONE use memcpy for this.*/
            /*for (i=0; i<ns_stack->size; i++)
             tmp_stack[i] = (ns_stack->stack)[i];*/
            memcpy(tmp_stack, ns_stack, sizeof(axiom_namespace_t*) * ns_stack->size);

            ns_stack->size = size;

            AXIS2_FREE(ctx->env->allocator, ns_stack->stack);
            ns_stack->stack = tmp_stack;
        }
        else
        {
            AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
            return AXIS2_FAILURE;
        }
    }

    /*if memory overflow occur we won't be here*/
    (ns_stack->stack)[ns_stack->head] = ns;
    (ns_stack->head)++;

    return AXIS2_SUCCESS;
}

/*
 * TODO: DONE
 * Find process should be changed ( if the ns has the same prefix but diff uri) 
 * Eg: <a xmlns:x="a">
 *      <b xmlns:x="b">
 *       <c xmlns:x="a"/>
 *      </b>
 *     </a>
 * */
static axis2_status_t c14n_ns_stack_find_with_prefix_uri(
    const axis2_char_t *prefix,
    const axis2_char_t *uri,
    const c14n_ctx_t *ctx)
{
    int i;
    c14n_ns_stack_t *ns_stack = ctx->ns_stack;
    if(ns_stack->stack) /*Is this necessary?*/
    {
        for(i = ns_stack->head - 1; i >= 0; i--)
        {
            axis2_char_t *prefix_i = axiom_namespace_get_prefix((ns_stack->stack)[i], ctx->env);

            if(axutil_strcmp(prefix_i, prefix) == 0)
            {
                axis2_char_t *uri_i = axiom_namespace_get_uri((ns_stack->stack)[i], ctx->env);
                if(axutil_strcmp(uri_i, uri) == 0)
                    return AXIS2_SUCCESS;
                else
                    return AXIS2_FALSE;
            }
            else
                continue;

        }
    }
    return AXIS2_FAILURE;
}

static axis2_status_t c14n_ns_stack_find(
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    return (c14n_ns_stack_find_with_prefix_uri(axiom_namespace_get_prefix((axiom_namespace_t *) ns,
        ctx->env), axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env), ctx));
}

static void
c14n_ns_stack_free(
    c14n_ctx_t *ctx)
{
    if(ctx->ns_stack->stack)
    {
        AXIS2_FREE(ctx->env->allocator, ctx->ns_stack->stack);
    }
    AXIS2_FREE(ctx->env->allocator, ctx->ns_stack);
    ctx->ns_stack = NULL;
}

/* Function Prototypes */

static axis2_status_t
c14n_apply_on_element(
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_namespace_axis(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_namespace_axis_exclusive(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_attribute_axis(
    const axiom_element_t *ele,
    const c14n_ctx_t *ctx);

static axis2_status_t
c14n_apply_on_node(
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static void
c14n_apply_on_comment(
    axiom_node_t *node,
    c14n_ctx_t *ctx);

static void
c14n_output(
    const axis2_char_t *str,
    const c14n_ctx_t *ctx);

static int
attr_compare(
    const void *a1,
    const void *a2,
    const void *context);

static int
ns_prefix_compare(
    const void *ns1,
    const void *ns2,
    const void *context);

static int
ns_uri_compare(
    const void *ns1,
    const void *ns2,
    const void *context);

static axis2_char_t*
c14n_normalize_attribute(
    axis2_char_t *attval,
    const c14n_ctx_t *ctx);

static axis2_char_t*
c14n_normalize_text(
    axis2_char_t *text,
    c14n_ctx_t *ctx);

static void
c14n_apply_on_namespace(
    const void *ns,
    const void *ctx);

static axis2_bool_t
c14n_need_to_declare_ns(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axis2_bool_t
c14n_ns_visibly_utilized(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axis2_bool_t
c14n_no_output_ancestor_uses_prefix(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx);

static axiom_node_t*
c14n_get_root_node(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx);

static c14n_algo_t
c14n_get_algorithm(
    const axis2_char_t* algo);

/*static axis2_bool_t
c14n_in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx
    );
*/

/* Implementations */

static void
c14n_ctx_free(
    c14n_ctx_t *ctx)
{
    c14n_ns_stack_free(ctx);
    AXIS2_FREE(ctx->env->allocator, ctx);
}

static c14n_ctx_t*
c14n_init(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axis2_bool_t comments,
    axutil_stream_t *stream,
    const axis2_bool_t exclusive,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) (AXIS2_MALLOC(env->allocator, sizeof(c14n_ctx_t)));
    if(!ctx)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n structure. Insufficient memory");
        return NULL;
    }
    ctx->env = env;
    ctx->doc = doc;
    ctx->comments = comments;
    ctx->exclusive = exclusive;
    ctx->ns_prefixes = ns_prefixes;
    ctx->node = node;
    ctx->outstream = stream;
    ctx->ns_stack = c14n_ns_stack_create(ctx);
    if(!ctx->ns_stack)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]cannot create c14n strucure. ns stack creation failed");
        AXIS2_FREE(env->allocator, ctx);
        ctx = NULL;
    }
    return ctx;
}

/*static axis2_bool_t
c14n_in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx
    )
{
    
    return AXIS2_SUCCESS;
}*/

static axiom_node_t*
c14n_get_root_node(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx)
{
    const axiom_node_t *parent = NULL;
    const axiom_node_t *prv_parent = NULL;

    parent = node;
    while(parent)
    {
        prv_parent = parent;
        parent = axiom_node_get_parent((axiom_node_t *) parent, ctx->env);
    }
    return (axiom_node_t *) prv_parent;
}

static c14n_algo_t c14n_get_algorithm(
    const axis2_char_t* algo)
{
    if(axutil_strcmp(algo, OXS_HREF_XML_C14N) == 0)
        return C14N_XML_C14N;

    if(axutil_strcmp(algo, OXS_HREF_XML_C14N_WITH_COMMENTS) == 0)
        return C14N_XML_C14N_WITH_COMMENTS;

    if(axutil_strcmp(algo, OXS_HREF_XML_EXC_C14N) == 0)
        return C14N_XML_EXC_C14N;

    if(axutil_strcmp(algo, OXS_HREF_XML_EXC_C14N_WITH_COMMENTS) == 0)
        return C14N_XML_EXC_C14N_WITH_COMMENTS;

    return 0; /*c14n_algo_t enum starts with 1*/
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_c14n_apply_stream_algo(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axutil_stream_t *stream,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node,
    const axis2_char_t* algo)
{
    switch(c14n_get_algorithm(algo))
    {
        case C14N_XML_C14N:
            return oxs_c14n_apply_stream(env, doc, AXIS2_FALSE, stream, AXIS2_FALSE, ns_prefixes,
                node);
        case C14N_XML_C14N_WITH_COMMENTS:
            return oxs_c14n_apply_stream(env, doc, AXIS2_TRUE, stream, AXIS2_FALSE, ns_prefixes,
                node);
        case C14N_XML_EXC_C14N:
            return oxs_c14n_apply_stream(env, doc, AXIS2_FALSE, stream, AXIS2_TRUE, ns_prefixes,
                node);
        case C14N_XML_EXC_C14N_WITH_COMMENTS:
            return oxs_c14n_apply_stream(env, doc, AXIS2_TRUE, stream, AXIS2_TRUE, ns_prefixes,
                node);
        default:
            /*TODO: set the error*/
            return AXIS2_FAILURE;
    }
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_c14n_apply_algo(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axis2_char_t **outbuf,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node,
    const axis2_char_t *algo)
{
    switch(c14n_get_algorithm(algo))
    {
        case C14N_XML_C14N:
            return oxs_c14n_apply(env, doc, AXIS2_FALSE, outbuf, AXIS2_FALSE, ns_prefixes, node);
        case C14N_XML_C14N_WITH_COMMENTS:
            return oxs_c14n_apply(env, doc, AXIS2_TRUE, outbuf, AXIS2_FALSE, ns_prefixes, node);
        case C14N_XML_EXC_C14N:
            return oxs_c14n_apply(env, doc, AXIS2_FALSE, outbuf, AXIS2_TRUE, ns_prefixes, node);
        case C14N_XML_EXC_C14N_WITH_COMMENTS:
            return oxs_c14n_apply(env, doc, AXIS2_TRUE, outbuf, AXIS2_TRUE, ns_prefixes, node);
        default:
            /*TODO:set the error*/
            return AXIS2_FAILURE;
    }
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_c14n_apply_stream(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    axis2_bool_t comments,
    axutil_stream_t *stream,
    const axis2_bool_t exclusive,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node)
{
    c14n_ctx_t *ctx = NULL;
    axis2_status_t status = AXIS2_SUCCESS;

    if(!stream)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]stream is not given to do c14n");
        return AXIS2_FAILURE;
    }

    ctx = c14n_init(env, doc, comments, stream, exclusive, ns_prefixes, node);
    if(!ctx)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] c14n structure creating failed");
        return AXIS2_FAILURE;
    }

    if(!node)
    {
        node = C14N_GET_ROOT_NODE_FROM_DOC_OR_NODE(doc, node, ctx);
        if(!node)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]cannot find node to apply c14n");
            return AXIS2_FAILURE;
        }
    }

    status = c14n_apply_on_node((axiom_node_t *)node, ctx);
    c14n_ctx_free(ctx);
    return status;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_c14n_apply(
    const axutil_env_t *env,
    const axiom_document_t *doc,
    const axis2_bool_t comments,
    axis2_char_t **outbuf,
    const axis2_bool_t exclusive,
    const axutil_array_list_t *ns_prefixes,
    const axiom_node_t *node)
{
    axutil_stream_t *stream = axutil_stream_create_basic(env);
    axis2_status_t ret = oxs_c14n_apply_stream(env, doc, comments, stream, exclusive, ns_prefixes,
        node);

    *outbuf = NULL;

    if(!ret)
    {
        return AXIS2_FAILURE;
    }
    else
    {
        int len = axutil_stream_get_len(stream, env) + 1;
        if(len > 0)
        {
            *outbuf = (axis2_char_t *) (AXIS2_MALLOC(env->allocator, sizeof(axis2_char_t) * len));
            axutil_stream_read(stream, env, *outbuf, len);
            axutil_stream_free(stream, env);
            stream = NULL;
            return AXIS2_SUCCESS;
        }
        else
        {
            axutil_stream_free(stream, env);
            stream = NULL;
            return AXIS2_FAILURE;
        }
    }
}

static axis2_status_t
c14n_apply_on_text(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axiom_text_t *text = (axiom_text_t *) axiom_node_get_data_element(node, ctx->env);

    if(text)
    {
        axis2_char_t *textval = (axis2_char_t*) axiom_text_get_text(text, ctx->env);
        if(!textval)
        {
            AXIS2_LOG_ERROR(ctx->env->log, AXIS2_LOG_SI, "[rampart]cannot get text from node");
            return AXIS2_FAILURE;
        }

        textval = c14n_normalize_text(textval, ctx);
        if(!textval)
        {
            AXIS2_LOG_ERROR(ctx->env->log, AXIS2_LOG_SI, "[rampart]cannot normalize text");
            return AXIS2_FAILURE;
        }

        c14n_output(textval, ctx);
        AXIS2_FREE(ctx->env->allocator, textval);
    }

    return AXIS2_SUCCESS;
}

static axis2_status_t
c14n_apply_on_node(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    switch(axiom_node_get_node_type(node, ctx->env))
    {
        case AXIOM_ELEMENT:
            c14n_apply_on_element(node, ctx);
            break;
        case AXIOM_TEXT:
            c14n_apply_on_text(node, ctx);
            break;
        case AXIOM_COMMENT:
            if(ctx->comments)
            {
                c14n_apply_on_comment(node, ctx);
                break;
            }
        case AXIOM_DOCTYPE:
        case AXIOM_PROCESSING_INSTRUCTION:
        default:
            ;
    }

    return AXIS2_SUCCESS;
}

static void
c14n_apply_on_comment(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    /*TODO: HACK*/
    c14n_output("<!--", ctx);
    c14n_output(axiom_comment_get_value((axiom_comment_t*) axiom_node_get_data_element(
        node, ctx->env), ctx->env), ctx);
    c14n_output("-->", ctx);
}

static axis2_status_t
c14n_apply_on_element(
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axis2_status_t res = AXIS2_SUCCESS;
    axiom_element_t *ele = NULL;
    axiom_namespace_t *ns = NULL;
    c14n_ns_stack_t *save_stack = NULL;
    axiom_node_t *child_node = NULL;

    ele = (axiom_element_t *) axiom_node_get_data_element(node, ctx->env);
    if(!ele)
    {
        AXIS2_LOG_ERROR(ctx->env->log, AXIS2_LOG_SI,
            "[rampart] cannot find valid element to apply c14n");
        return AXIS2_FAILURE;
    }

    ns = axiom_element_get_namespace(ele, ctx->env, node);
    save_stack = c14n_ns_stack_create(ctx);
    c14n_ns_stack_push(save_stack, ctx); /*save current ns stack*/

    /*print start tag*/
    c14n_output("<", ctx);
    if(ns)
    {
        axis2_char_t *prefix = axiom_namespace_get_prefix(ns, ctx->env);
        if(axutil_strlen(prefix) > 0)
        {
            c14n_output(prefix, ctx);
            c14n_output(":", ctx);
        }
    }
    c14n_output(axiom_element_get_localname(ele, ctx->env), ctx);

    if(ctx->exclusive)
        res = c14n_apply_on_namespace_axis_exclusive(ele, node, ctx);
    else
        res = c14n_apply_on_namespace_axis(ele, node, ctx);

    /*
     * edited the code so that the same fn does both exc and non-exc.
     * have to be careful here!
     */

    if(!res)
        return res;

    res = c14n_apply_on_attribute_axis(ele, ctx);

    if(!res)
        return res;

    c14n_output(">", ctx);


    /*process child elements*/
    child_node = axiom_node_get_first_child((axiom_node_t *) node, ctx->env);
    while(child_node)
    {
        c14n_apply_on_node(child_node, ctx);
        child_node = axiom_node_get_next_sibling(child_node, ctx->env);
    }

    /*print end tag*/
    c14n_output("</", ctx);
    if(ns)
    {
        axis2_char_t *prefix = axiom_namespace_get_prefix(ns, ctx->env);

        if(axutil_strlen(prefix) > 0)
        {
            c14n_output(prefix, ctx);
            c14n_output(":", ctx);
        }
    }
    c14n_output(axiom_element_get_localname(ele, ctx->env), ctx);
    c14n_output(">", ctx);

    c14n_ns_stack_pop(save_stack, ctx); /*restore to previous ns stack */

    /*since save_stack is used just to memorize the head of the stack,
     * we don't have to worry about freeing its members*/
    AXIS2_FREE(ctx->env->allocator, save_stack);
    return res;
}

static int ns_uri_compare(
    const void *ns1,
    const void *ns2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;

    if(ns1 == ns2)
        return 0;
    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    return (axutil_strcmp((const axis2_char_t *) axiom_namespace_get_uri((axiom_namespace_t *) ns1,
        ctx->env), (const axis2_char_t *) axiom_namespace_get_uri((axiom_namespace_t *) ns2,
        ctx->env)));
}

static int ns_prefix_compare(
    const void *ns1,
    const void *ns2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;

    if(ns1 == ns2)
        return 0;
    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    return (axutil_strcmp((const axis2_char_t *) axiom_namespace_get_prefix(
        (axiom_namespace_t *) ns1, ctx->env), (const axis2_char_t *) axiom_namespace_get_prefix(
        (axiom_namespace_t *) ns2, ctx->env)));
}

static int attr_compare(
    const void *a1,
    const void *a2,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;
    axiom_attribute_t *attr1 = NULL;
    axiom_attribute_t *attr2 = NULL;
    axiom_namespace_t *ns1 = NULL;
    axiom_namespace_t *ns2 = NULL;
    int res;

    if(a1 == a2)
        return 0;
    if(!a1)
        return -1;
    if(!a2)
        return 1;

    attr1 = (axiom_attribute_t *) a1;
    attr2 = (axiom_attribute_t *) a2;
    ns1 = axiom_attribute_get_namespace((axiom_attribute_t *) a1, ctx->env);
    ns2 = axiom_attribute_get_namespace((axiom_attribute_t *) a2, ctx->env);

    if(ns1 == ns2)
        return axutil_strcmp(
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a1, ctx->env),
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a2, ctx->env));

    if(!ns1)
        return -1;
    if(!ns2)
        return 1;

    res = axutil_strcmp(axiom_namespace_get_uri(ns1, ctx->env), axiom_namespace_get_uri(ns2,
        ctx->env));

    if(res == 0)
        return axutil_strcmp(
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a1, ctx->env),
            (const axis2_char_t *) axiom_attribute_get_localname((axiom_attribute_t *) a2, ctx->env));
    else
        return res;

}

static void
c14n_apply_on_attribute(
    const void *attribute,
    const void *context)
{
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;
    axiom_attribute_t *attr = (axiom_attribute_t *) attribute;
    axiom_namespace_t *ns = axiom_attribute_get_namespace(attr, ctx->env);
    axis2_char_t *attvalue = NULL;

    c14n_output(" ", ctx);
    if(ns)
    {
        axis2_char_t *prefix = axiom_namespace_get_prefix(ns, ctx->env);

        if(axutil_strlen(prefix) > 0)
        {
            c14n_output(prefix, ctx);
            c14n_output(":", ctx);
        }
    }
    c14n_output(axiom_attribute_get_localname(attr, ctx->env), ctx);
    c14n_output("=\"", ctx);

    /* TODO:DONE Normalize the text before output */
    attvalue = axiom_attribute_get_value(attr, ctx->env);
    attvalue = c14n_normalize_attribute(attvalue, (c14n_ctx_t const *) context);

    c14n_output(attvalue, ctx);

    c14n_output("\"", ctx);

    if(attvalue)
    {
        AXIS2_FREE(ctx->env->allocator, attvalue);
        attvalue = NULL;
    }
}

static axis2_status_t
c14n_apply_on_attribute_axis(
    const axiom_element_t *ele,
    const c14n_ctx_t *ctx)
{
    axutil_hash_t *attr_ht = NULL;
    axutil_hash_index_t *hi = NULL;
    c14n_sorted_list_t *attr_list = c14n_sorted_list_create(ctx->env);

    attr_ht = axiom_element_get_all_attributes((axiom_element_t *) ele, ctx->env);

    if(attr_ht)
    {
        for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
        {
            void *v = NULL;
            axutil_hash_this(hi, NULL, NULL, &v);

            if(v)
            {
                C14N_SORTED_LIST_INSERT(&attr_list, v, ctx, attr_compare, ctx->env);
            }
        }

        C14N_SORTED_LIST_ITERATE(attr_list, ctx, c14n_apply_on_attribute, ctx->env);
    }

    /*TODO:DONE C14N_SORTED_LIST_FREE();*/
    C14N_SORTED_LIST_FREE_CONTAINER(attr_list, ctx->env);

    return AXIS2_SUCCESS;

    /* TODO: Still need to add the "xml" attrs of the parents in case of doc subsets
     * and non-exclusive c14n
     * */
}

#if 0
static axis2_char_t*
c14n_normalize_text(
    axis2_char_t *text,
    const c14n_ctx_t *ctx
)
{
    axis2_char_t *buf = NULL;
    axis2_char_t *endpivot = NULL;
    axis2_char_t *p = NULL;
    axis2_char_t *old = NULL;
    int bufsz = INIT_BUFFER_SIZE;

    /* TODO:DONE a better buffer implementation */
    buf = (axis2_char_t *)(AXIS2_MALLOC(ctx->env->allocator,
            (sizeof(axis2_char_t) * bufsz) + 10));
    if (!buf)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY,
            AXIS2_FAILURE);
        return buf;
    }

    p = buf;
    endpivot = p + bufsz;

    old = text;

    while (*old !='\0')
    {
        if (p > endpivot)
        {
            int size = bufsz * 2;
            axis2_char_t *temp_buf = (axis2_char_t *)(AXIS2_MALLOC(
                    ctx->env->allocator, sizeof(axis2_char_t) * size + 10));

            if (!temp_buf)
            {
                AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY,
                    AXIS2_FAILURE);
                return buf;
            }

            memcpy(temp_buf, buf, sizeof(axis2_char_t) * bufsz + 10);

            p = temp_buf + (p - buf);

            AXIS2_FREE(ctx->env->allocator, buf);
            buf = temp_buf;
            bufsz = size;
            endpivot = buf + bufsz;
        }

        switch (*old)
        {
            case '&':
            *p++ = '&';
            *p++ = 'a';
            *p++ = 'm';
            *p++ = 'p';
            *p++ = ';';
            break;
            case '>':
            *p++ = '&';
            *p++ = 'g';
            *p++ = 't';
            *p++ = ';';
            break;
            case '<':
            *p++ = '&';
            *p++ = 'l';
            *p++ = 't';
            *p++ = ';';
            break;
            case '\x0D':
            *p++ = '&';
            *p++ = '#';
            *p++ = 'x';
            *p++ = 'D';
            *p++ = ';';
            break;
            default:
            *p++ = *old;
        }
        old ++;
    }
    *p++ = '\0';
    return buf;
}
#endif

static axis2_char_t*
c14n_normalize_text(
    axis2_char_t *text,
    c14n_ctx_t *ctx)
{
    axis2_char_t *buf = NULL;
    int index = 0;
    int bufsz = INIT_BUFFER_SIZE;
    int original_size = axutil_strlen(text);

    /* TODO:DONE a better buffer implementation */

    /* we need atleast the size of original text. worst case is, each character is replaced with
     * 5 other characters (all the texts are special character). But these special characters are
     * rare and will occur less than 10% of the time. Hence we can create a buffer with length
     * max(INIT_BUFFER_SIZE, strlen(text)*1.5).. This will reduce the number of memcpy needed
     */
    if(bufsz < original_size * 1.5)
        bufsz = original_size * 1.5;

    buf = (axis2_char_t *) AXIS2_MALLOC(ctx->env->allocator, (sizeof(axis2_char_t) * bufsz));
    if(!buf)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }

    while(original_size > 0)
    {
        size_t i = 0;
        /* scan buffer until the next special character (&, <, >, \x0D) these need to be escaped,
         * otherwise XML will not be valid*/
        axis2_char_t *pos = (axis2_char_t*) strpbrk(text, "&<>\x0D");
        if(pos)
        {
            i = pos - text;
        }
        else
        {
            i = original_size;
        }

        /* copy everything until the special character */
        if(i > 0)
        {
            if(index + i + 6 > bufsz)
            {
                /* not enough space to write remaining characters + (5 character resulting
                 * from special character + 1 NULL character). So, have to create a new buffer
                 * and populate */
                axis2_char_t *temp_buf = NULL;

                bufsz *= 2;
                temp_buf = (axis2_char_t *) AXIS2_MALLOC(ctx->env->allocator, sizeof(axis2_char_t)
                    * bufsz);
                if(!temp_buf)
                {
                    AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
                    return buf;
                }
                memcpy(temp_buf, buf, index);
                AXIS2_FREE(ctx->env->allocator, buf);
                buf = temp_buf;
            }

            memcpy(buf + index, text, i);
            text += i;
            index += i;
            original_size -= i;
        }

        /* replace the character with the appropriate sequence */
        if(original_size > 0)
        {
            switch(text[0])
            {
                case '&':
                    buf[index++] = '&';
                    buf[index++] = 'a';
                    buf[index++] = 'm';
                    buf[index++] = 'p';
                    buf[index++] = ';';
                    break;
                case '>':
                    buf[index++] = '&';
                    buf[index++] = 'g';
                    buf[index++] = 't';
                    buf[index++] = ';';
                    break;
                case '<':
                    buf[index++] = '&';
                    buf[index++] = 'l';
                    buf[index++] = 't';
                    buf[index++] = ';';
                    break;
                case '\x0D':
                    buf[index++] = '&';
                    buf[index++] = '#';
                    buf[index++] = 'x';
                    buf[index++] = 'D';
                    buf[index++] = ';';
                    break;
                default:
                    ;
            }

            ++text;
            --original_size;
        }
    }

    buf[index] = '\0';
    /*printf("buffer [%s]\n", buf);*/
    return buf;
}

static axis2_char_t*
c14n_normalize_attribute(
    axis2_char_t *attval,
    const c14n_ctx_t *ctx)
{
    axis2_char_t *buf = NULL;
    axis2_char_t *endpivot = NULL;
    axis2_char_t *p = NULL;
    axis2_char_t *old = NULL;
    int bufsz = INIT_BUFFER_SIZE;

    /* TODO:DONE a better buffer implementation */
    buf = (axis2_char_t *) (AXIS2_MALLOC(ctx->env->allocator, sizeof(axis2_char_t)
        * INIT_BUFFER_SIZE + 10));
    if(!buf)
    {
        AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return buf;
    }

    p = buf;
    endpivot = buf + bufsz;

    old = attval;

    while(*old != '\0')
    {
        if(p > endpivot)
        {
            int size = bufsz * 2;
            axis2_char_t *temp_buf = (axis2_char_t *) (AXIS2_MALLOC(ctx->env->allocator,
                sizeof(axis2_char_t) * size + 10));

            if(!temp_buf)
            {
                AXIS2_ERROR_SET(ctx->env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
                return buf;
            }

            memcpy(temp_buf, buf, sizeof(axis2_char_t) * bufsz + 10);

            p = temp_buf + (p - buf);

            AXIS2_FREE(ctx->env->allocator, buf);
            buf = temp_buf;
            bufsz = size;
            endpivot = buf + bufsz;
        }

        switch(*old)
        {
            case '&':
                *p++ = '&';
                *p++ = 'a';
                *p++ = 'm';
                *p++ = 'p';
                *p++ = ';';
                break;
            case '<':
                *p++ = '&';
                *p++ = 'l';
                *p++ = 't';
                *p++ = ';';
                break;
            case '"':
                *p++ = '&';
                *p++ = 'q';
                *p++ = 'u';
                *p++ = 'o';
                *p++ = 't';
                *p++ = ';';
                break;
            case '\x09':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = '9';
                *p++ = ';';
                break;
            case '\x0A':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = 'A';
                *p++ = ';';
                break;
            case '\x0D':
                *p++ = '&';
                *p++ = '#';
                *p++ = 'x';
                *p++ = 'D';
                *p++ = ';';
                break;
            default:
                *p++ = *old;
        }
        old++;
    }
    *p++ = '\0';
    return buf;
}

static axis2_status_t c14n_apply_on_namespace_axis(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const c14n_ctx_t *ctx)
{
    axutil_hash_t *ns_ht = NULL;
    axutil_hash_index_t *hi = NULL;

    c14n_sorted_list_t *out_list = c14n_sorted_list_create(ctx->env);

    ns_ht = axiom_element_get_namespaces((axiom_element_t *) ele, ctx->env);

    if(ns_ht)
    {
        for(hi = axutil_hash_first(ns_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
        {
            void *v = NULL;
            axutil_hash_this(hi, NULL, NULL, &v);

            if(v)
            {
                axiom_namespace_t *ns = (axiom_namespace_t *) v;

                axis2_char_t *pfx = axiom_namespace_get_prefix(ns, ctx->env);
                axis2_char_t *uri = axiom_namespace_get_uri(ns, ctx->env);

                if(axutil_strlen(pfx) == 0)
                {
                    /*process for default namespace*/
                    /*int nsc = ns_prefix_compare(c14n_ns_stack_get_default(ctx), ns, ctx);
                     int len = axutil_strlen(uri);*/

                    if(axutil_strlen(uri) == 0)
                    {
                        if(c14n_ns_stack_get_default(ctx) != NULL)
                        {
                            c14n_ns_stack_set_default(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                ctx->env);
                        }

                    }
                    else
                    {
                        axiom_namespace_t *prev_def = c14n_ns_stack_get_default(ctx);

                        axis2_char_t *prev_def_uri = ((prev_def) ? axiom_namespace_get_uri(
                            prev_def, ctx->env)
                            : NULL);

                        if(!prev_def_uri || axutil_strcmp(prev_def_uri, uri) != 0)
                        {
                            c14n_ns_stack_set_default(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                ctx->env);
                        }
                    }
                }
                else if(!c14n_ns_stack_find(ns, ctx))
                {
                    /*non-default namespace*/
                    c14n_ns_stack_add(ns, ctx);
                    C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                        ctx->env);
                }
            }
        }
    }

    C14N_SORTED_LIST_ITERATE(out_list, ctx, c14n_apply_on_namespace, ctx->env);

    C14N_SORTED_LIST_FREE_CONTAINER(out_list, ctx->env);

    /*TODO:DONE C14N_SORTED_LIST_FREE();*/
    return AXIS2_SUCCESS;
}

static axis2_status_t
c14n_apply_on_namespace_axis_exclusive(
    axiom_element_t *ele,
    axiom_node_t *node,
    c14n_ctx_t *ctx)
{
    axutil_hash_t *ns_ht = NULL;
    axutil_hash_index_t *hi = NULL;
    axiom_node_t *pnode = NULL;
    axiom_element_t *pele = NULL;
    axiom_namespace_t *ns = NULL;

    c14n_sorted_list_t *out_list = c14n_sorted_list_create(ctx->env);

    pele = ele;
    pnode = node;

    /*treat the default namespace specially*/

    ns = axiom_element_get_namespace(pele, ctx->env, pnode);

    if(ns)
    {
        if(axutil_strlen(axiom_namespace_get_prefix((axiom_namespace_t *) ns, ctx->env)) == 0)
        {
            axiom_namespace_t *def_ns = c14n_ns_stack_get_default(ctx);
            if(def_ns || axutil_strlen(axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env))
                != 0)
            {
                if(ns_uri_compare(ns, def_ns, ctx) != 0)
                {
                    c14n_ns_stack_set_default(ns, ctx);
                    C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                        ctx->env);
                }
            }
        }
    }

    while(pnode)
    {
        pele = axiom_node_get_data_element(pnode, ctx->env);
        ns_ht = axiom_element_get_namespaces(pele, ctx->env);

        if(ns_ht)
        {
            for(hi = axutil_hash_first(ns_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axis2_char_t *pfx = NULL;
                    ns = (axiom_namespace_t *) v;

                    pfx = axiom_namespace_get_prefix(ns, ctx->env);
                    /*axis2_char_t *uri = axiom_namespace_get_uri(ns, ctx->env);*/

                    if(axutil_strlen(pfx) == 0)
                    {
                        /* process for default namespace.
                         * NOTE: This part was taken out of here due to the 
                         * search thruogh parent-axis
                         * */
                    }
                    else if(!c14n_ns_stack_find(ns, ctx))
                    {
                        /*non-default namespace*/
                        if(c14n_need_to_declare_ns(ele, node, ns, ctx))
                        {
                            c14n_ns_stack_add(ns, ctx);
                            C14N_SORTED_LIST_INSERT(&out_list, (void *) ns, ctx, ns_prefix_compare,
                                ctx->env);
                        }
                    }
                }
            }
        }
        pnode = axiom_node_get_parent(pnode, ctx->env);
    } /*while*/
    C14N_SORTED_LIST_ITERATE(out_list, ctx, c14n_apply_on_namespace, ctx->env);

    C14N_SORTED_LIST_FREE_CONTAINER(out_list, ctx->env);

    /*TODO:DONE C14N_SORTED_LIST_FREE();*/
    return AXIS2_SUCCESS;
}

static void c14n_apply_on_namespace(
    const void *namespace,
    const void *context)
{
    axiom_namespace_t *ns = (axiom_namespace_t *) namespace;
    c14n_ctx_t *ctx = (c14n_ctx_t *) context;

    axis2_char_t *pfx = axiom_namespace_get_prefix(ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri(ns, ctx->env);

    /*c14n_output(" *", ctx);
     c14n_output(axiom_namespace_to_string(ns, ctx->env), ctx);
     c14n_output("*", ctx);*/

    if(axutil_strlen(pfx) > 0)
    {
        c14n_output(" xmlns:", ctx);
        c14n_output(pfx, ctx);
    }
    else
        c14n_output(" xmlns", ctx);

    c14n_output("=\"", ctx);

    if(axutil_strlen(uri) > 0)
        c14n_output(uri, ctx);
    c14n_output("\"", ctx);

}

static void c14n_output(
    const axis2_char_t *str,
    const c14n_ctx_t *ctx)
{
    axutil_stream_write(ctx->outstream, ctx->env, str, axutil_strlen(str) * sizeof(axis2_char_t));
}

static axis2_bool_t c14n_need_to_declare_ns(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_bool_t vu = c14n_ns_visibly_utilized(ele, node, ns, ctx);

    if(vu || (ctx->ns_prefixes && axutil_array_list_contains(
        (axutil_array_list_t*) (ctx->ns_prefixes), ctx->env, (void*) (axiom_namespace_get_prefix(
            (axiom_namespace_t*) ns, ctx->env)))))
        return c14n_no_output_ancestor_uses_prefix(ele, node, ns, ctx);

    return AXIS2_FALSE;
}

static axis2_bool_t c14n_ns_visibly_utilized(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_bool_t vu = AXIS2_FALSE;
    axiom_namespace_t *ns_ele = NULL;

    axis2_char_t *pfx = axiom_namespace_get_prefix((axiom_namespace_t*) ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env);
    axis2_char_t *pfx_ele = NULL;
    axis2_char_t *uri_ele = NULL;
    ns_ele = axiom_element_get_namespace((axiom_element_t*) ele, ctx->env, (axiom_node_t *) node);

    if(ns_ele) /* return AXIS2_FALSE; TODO:check */
    {
        pfx_ele = axiom_namespace_get_prefix(ns_ele, ctx->env);
        uri_ele = axiom_namespace_get_uri(ns_ele, ctx->env);
    }
    if((axutil_strcmp(pfx, pfx_ele) == 0) && (axutil_strcmp(uri, uri_ele) == 0))
        vu = AXIS2_TRUE;
    else
    {
        axutil_hash_t *attr_ht =
            axiom_element_get_all_attributes((axiom_element_t *) ele, ctx->env);
        axutil_hash_index_t *hi = NULL;
        if(attr_ht)
        {
            for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axiom_attribute_t *attr = (axiom_attribute_t*) v;
                    axiom_namespace_t *ns_attr = axiom_attribute_get_namespace(attr, ctx->env);
                    axis2_char_t *attr_pfx = NULL;

                    /*if in_nodelist(attr) {*/
                    if(ns_attr)
                        attr_pfx = axiom_namespace_get_prefix(ns_attr, ctx->env);

                    if(axutil_strcmp(attr_pfx, pfx) == 0)
                    {
                        vu = AXIS2_TRUE;
                        if(ctx->env)
                            AXIS2_FREE(ctx->env->allocator, hi);
                        break;
                    }
                    /*}*/
                }
            }
        }

    }

    return vu;
}

static axis2_bool_t in_nodeset(
    const axiom_node_t *node,
    const c14n_ctx_t *ctx)
{
    axiom_node_t *pnode = NULL;
    pnode = axiom_node_get_parent((axiom_node_t *) node, ctx->env);

    while(pnode)
    {
        if(ctx->node == pnode)
            return AXIS2_TRUE;
        pnode = axiom_node_get_parent((axiom_node_t *) pnode, ctx->env);
    }

    return AXIS2_FALSE;
}

static axis2_bool_t c14n_no_output_ancestor_uses_prefix(
    const axiom_element_t *ele,
    const axiom_node_t *node,
    const axiom_namespace_t *ns,
    const c14n_ctx_t *ctx)
{
    axis2_char_t *pfx = axiom_namespace_get_prefix((axiom_namespace_t*) ns, ctx->env);
    axis2_char_t *uri = axiom_namespace_get_uri((axiom_namespace_t *) ns, ctx->env);

    axiom_node_t *parent_node = axiom_node_get_parent((axiom_node_t *) node, ctx->env);
    axiom_element_t *parent_element = NULL;
    axiom_namespace_t *parent_ns = NULL;
    axis2_char_t *parent_pfx = NULL;
    axis2_char_t *parent_uri = NULL;

    /* assuming the parent  of an element is always an element node in AXIOM*/
    while(parent_node)
    {
        axutil_hash_index_t *hi = NULL;
        axutil_hash_t *attr_ht = NULL;

        /* TODO:
         * HACK: since we only use a single node as the subset
         * the following hack should work instead of a more
         * general in_nodest()*/

        if(!in_nodeset(parent_node, ctx))
        {
            /*we reached a node beyond the nodeset,
             * so the prefix is not used*/
            return AXIS2_TRUE;
        }

        /* if (in_nodeset(parent)){*/
        parent_element = axiom_node_get_data_element((axiom_node_t *) parent_node, ctx->env);
        parent_ns = axiom_element_get_namespace((axiom_element_t *) parent_element, ctx->env,
            (axiom_node_t *) parent_node);

        if(parent_ns)
        {
            parent_pfx = axiom_namespace_get_prefix((axiom_namespace_t *) parent_ns, ctx->env);
            if(axutil_strcmp(pfx, parent_pfx) == 0)
            {
                parent_uri = axiom_namespace_get_uri((axiom_namespace_t*) parent_ns, ctx->env);
                return (!(axutil_strcmp(uri, parent_uri) == 0));
            }
        }

        attr_ht = axiom_element_get_all_attributes((axiom_element_t *) parent_element, ctx->env);
        if(attr_ht)
        {
            for(hi = axutil_hash_first(attr_ht, ctx->env); hi; hi = axutil_hash_next(ctx->env, hi))
            {
                void *v = NULL;
                axutil_hash_this(hi, NULL, NULL, &v);

                if(v)
                {
                    axiom_attribute_t *attr = (axiom_attribute_t*) v;
                    axiom_namespace_t *attr_ns = axiom_attribute_get_namespace(attr, ctx->env);
                    axis2_char_t *attr_pfx = NULL;
                    axis2_char_t *attr_uri = NULL;

                    if(attr_ns)
                    {
                        attr_pfx = axiom_namespace_get_prefix(attr_ns, ctx->env);
                        attr_uri = axiom_namespace_get_uri(attr_ns, ctx->env);

                        if(axutil_strcmp(attr_pfx, pfx) == 0)
                            return (!(axutil_strcmp(attr_uri, uri) == 0));
                        /*test for this case*/
                    }
                }
            }
        }
        /*}*/
        parent_node = axiom_node_get_parent((axiom_node_t *) parent_node, ctx->env);
    }

    return AXIS2_TRUE;
}
