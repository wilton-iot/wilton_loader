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

char* wilton_load_script(
        const char* url,
        int url_len,
        char** contents_out,
        int* contents_out_len);

#ifdef __cplusplus
}
#endif

#endif /* WILTON_LOADER_H */

