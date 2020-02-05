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
    // json parse
    auto json = sl::json::load(data);
    auto rurl = std::ref(sl::utils::empty_string());
    auto hex = false;
    for (const sl::json::field& fi : json.as_object()) {
        auto& name = fi.name();
        if ("url" == name) {
            rurl = fi.as_string_nonempty_or_throw(name);
        } else if ("hex" == name) {
            hex = fi.as_bool_or_throw(name);
        } else {
            throw support::exception(TRACEMSG("Unknown data field: [" + name + "]"));
        }
    }
    if (rurl.get().empty()) throw support::exception(TRACEMSG(
            "Required parameter 'url' not specified"));
    const std::string& url = rurl.get();
    // call wilton
    char* out = nullptr;
    int out_len = 0;
    char* err = wilton_load_resource(url.c_str(), static_cast<int> (url.length()),
            std::addressof(out), std::addressof(out_len));
    if (nullptr != err) {
        support::throw_wilton_error(err, TRACEMSG(err));
    }
    if (hex) {
        auto deferred = sl::support::defer([out]() STATICLIB_NOEXCEPT {
            wilton_free(out);
        });
        auto src = sl::io::array_source(out, out_len);
        return support::make_hex_buffer(src);
    } else {
        return support::wrap_wilton_buffer(out, out_len);
    }
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
