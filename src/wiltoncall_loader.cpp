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
 * File:   wiltoncall_loader.cpp
 * Author: alex
 *
 * Created on July 17, 2017, 9:03 PM
 */

#include "staticlib/io.hpp"
#include "staticlib/json.hpp"
#include "staticlib/support.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wilton_loader.h"

#include "wilton/support/buffer.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/registrar.hpp"

namespace wilton {
namespace loader {

support::buffer load_module_resource(sl::io::span<const char> data) {
    char* out = nullptr;
    int out_len = 0;
    char* err = wilton_load_resource(data.data(), static_cast<int>(data.size()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) {
        support::throw_wilton_error(err, TRACEMSG(err));
    }
    return support::wrap_wilton_buffer(out, out_len);
}

} // namespace
}

extern "C" char* wilton_module_init() {
    try {
        // get conf
        char* conf = nullptr;
        int len = 0;
        auto err_conf = wilton_config(std::addressof(conf), std::addressof(len));
        if (nullptr != err_conf) wilton::support::throw_wilton_error(err_conf, TRACEMSG(err_conf));
        auto deferred = sl::support::defer([conf]() STATICLIB_NOEXCEPT {
            wilton_free(conf);
        });

        // init unzip index
        auto err_init = wilton_loader_initialize(const_cast<const char*>(conf), len);
        if (nullptr != err_init) wilton::support::throw_wilton_error(err_init, TRACEMSG(err_init));

        // register calls
        wilton::support::register_wiltoncall("load_module_resource", wilton::loader::load_module_resource);
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}
