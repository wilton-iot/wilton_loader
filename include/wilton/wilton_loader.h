/*
 * Copyright 2017, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   wilton_db.h
 * Author: alex
 *
 * Created on June 10, 2017, 1:23 PM
 */

#ifndef WILTON_LOADER_H
#define WILTON_LOADER_H

#include "wilton/wilton.h"

#ifdef __cplusplus
extern "C" {
#endif

char* wilton_loader_initialize(
        const char* conf_json,
        int conf_json_len);

char* wilton_load_resource(
        const char* url,
        int url_len,
        char** contents_out,
        int* contents_out_len);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_LOADER_H */

