/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

#ifndef RAMPART_RD_RECORD_H
#define RAMPART_RD_RECORD_H


/**
  * @file rampart_rd_record.h
  * @brief A record that can be used in the Replay Detection mechanism. Represents a SOAP message instance
  */

/**
* @defgroup rampart_rd_record Replay Detection Record
* @ingroup rampart_utils
* @{
*/
#include <rampart_util.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct rampart_rd_record_t rampart_rd_record_t;
    /**
    * Create function
    * @param env pointer to environment struct
    * @return return pointer on success otherwise NULL 
    */
    AXIS2_EXTERN rampart_rd_record_t *AXIS2_CALL
    rampart_rd_record_create(const axutil_env_t *env);

    /**
    * Free function
    * @param rd_record the record
    * @param env pointer to environment struct
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_rd_record_free(rampart_rd_record_t *rd_record,
                           const axutil_env_t *env);


    /**
    * Get the record ID
    * @param rd_record the record
    * @param env pointer to environment struct
    * @return record ID on success otherwise NULL
    */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_rd_record_get_id(
        const rampart_rd_record_t *rd_record,
        const axutil_env_t *env);

    /**
    * Get the timestamp
    * @param rd_record the record
    * @param env pointer to environment struct
    * @param
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_char_t *AXIS2_CALL
    rampart_rd_record_get_timestamp(
        const rampart_rd_record_t *rd_record,
        const axutil_env_t *env);

    /**
    * Set the ID
    * @param rd_record the record
    * @param env pointer to environment struct
    * @param id Record ID
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_rd_record_set_id(
        rampart_rd_record_t *rd_record,
        const axutil_env_t *env,
        axis2_char_t *id);

    /**
    * Set the timestamp
    * @param rd_record the record
    * @param env pointer to environment struct
    * @param timestamp the time stamp
    * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
    */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    rampart_rd_record_set_timestamp(
        rampart_rd_record_t *rd_record,
        const axutil_env_t *env,
        axis2_char_t *timestamp);




#ifdef __cplusplus
}
#endif
#endif
