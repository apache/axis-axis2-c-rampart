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
#ifndef ECHO_HELPER_H
#define ECHO_HELPER_H


#include <axis2_svc_client.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
echo_helper_set_policy(axis2_svc_client_t* svc_client,
    const axis2_char_t *client_home,                
    const axutil_env_t *env);


#endif /* ECHO_HELPER*/
