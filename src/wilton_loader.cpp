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
 * File:   wilton_loader.cpp
 * Author: alex
 *
 * Created on October 18, 2017, 8:43 AM
 */

#include "wilton/wilton_loader.h"

#include <cstdint>
#include <atomic>
#include <string>
#include <vector>

#include "staticlib/config.hpp"
#include "staticlib/json.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/unzip.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/misc.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.loader");

std::atomic_bool initialized{false};

std::vector<sl::unzip::file_index>& static_modules_indices(
        std::vector<sl::unzip::file_index> vec = std::vector<sl::unzip::file_index>()) {
    static std::vector<sl::unzip::file_index> indices = std::move(vec);
    return indices;
}

sl::io::span<char> read_zip_resource(const std::string& path) {
    // search modules.zip indices
    for (auto& idx : static_modules_indices()) {
        // normalize path
        auto path_norm = sl::tinydir::normalize_path(path);
        // load zip entry
        auto& zippath = idx.get_zip_file_path();
        if (path.length() > zippath.length() + 1 && sl::utils::starts_with(path_norm, zippath)) {
            auto en_path = path_norm.substr(zippath.length() + 1);
            auto stream = sl::unzip::open_zip_entry(idx, en_path);
            auto src = sl::io::streambuf_source(stream.get());
            auto sink = sl::io::make_array_sink(wilton_alloc, wilton_free);
            sl::io::copy_all(src, sink);
            return sink.release();
        }
    }
    throw wilton::support::exception(TRACEMSG("Error loading zip entry," +
            " path: [" + path + "]"));
}

sl::io::span<char> read_fs_resource(const std::string& path) {
    auto src = sl::tinydir::file_source(path);
    auto sink = sl::io::make_array_sink(wilton_alloc, wilton_free);
    sl::io::copy_all(src, sink);
    return sink.release();
}

sl::io::span<char> read_zip_or_fs_resource(const std::string& url) {
    wilton::support::log_debug(logger, "Loading resource, URL: [" + url + "] ...");
    if (sl::utils::starts_with(url, wilton::support::file_proto_prefix)) {
        auto res = read_fs_resource(url.substr(wilton::support::file_proto_prefix.length()));
        wilton::support::log_debug(logger, "Resource loaded successfully, size: [" + sl::support::to_string(res.size()) + "] ...");
        return res;
    } else if (sl::utils::starts_with(url, wilton::support::zip_proto_prefix)) {
        auto zurl = url.substr(wilton::support::zip_proto_prefix.length());
        auto res = read_zip_resource(zurl);
        wilton::support::log_debug(logger, "Resource loaded successfully, size: [" + sl::support::to_string(res.size()) + "] ...");
        return res;
    } else {
        throw wilton::support::exception(TRACEMSG("Unknown protocol prefix, url: [" + url + "]"));
    }
}

} // namespace

char* wilton_loader_initialize(const char* conf_json, int conf_json_len) /* noexcept */ {
    if (nullptr == conf_json) return wilton::support::alloc_copy(TRACEMSG("Null 'conf_json' parameter specified"));
    if (!sl::support::is_uint32_positive(conf_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'conf_json_len' parameter specified: [" + sl::support::to_string(conf_json_len) + "]"));
    try {
        bool the_false = false;
        if (initialized.compare_exchange_strong(the_false, true, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            auto cf = sl::json::load({conf_json, conf_json_len});
            auto stdpath = cf["requireJs"]["baseUrl"].as_string_nonempty_or_throw("requireJs.baseUrl");
            auto vec = std::vector<sl::unzip::file_index>();
            if (sl::utils::starts_with(stdpath, wilton::support::zip_proto_prefix)) {
                auto zippath = stdpath.substr(wilton::support::zip_proto_prefix.length());
                auto zippath_norm = sl::tinydir::normalize_path(zippath);
                vec.emplace_back(sl::unzip::file_index(zippath_norm));
            }
            for (auto& fi : cf["requireJs"]["paths"].as_object_or_throw("requireJs.paths")) {
                auto modpath = fi.val().as_string_nonempty_or_throw("requireJs.paths[]");
                if (sl::utils::starts_with(modpath, wilton::support::zip_proto_prefix)) {
                    auto zippath = modpath.substr(wilton::support::zip_proto_prefix.length());
                    auto zippath_norm = sl::tinydir::normalize_path(zippath);
                    vec.emplace_back(sl::unzip::file_index(zippath_norm));
                }
            }
            static_modules_indices(std::move(vec));
        }
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

char* wilton_load_resource(const char* url, int url_len,
        char** contents_out, int* contents_out_len) /* noexcept */ {
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (!sl::support::is_uint16_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (nullptr == contents_out) return wilton::support::alloc_copy(TRACEMSG("Null 'contents_out' parameter specified"));
    if (nullptr == contents_out_len) return wilton::support::alloc_copy(TRACEMSG("Null 'contents_out_len' parameter specified"));
    try {
        auto url_str = std::string(url, static_cast<uint16_t>(url_len));
        auto span = read_zip_or_fs_resource(url_str);
        *contents_out = span.data();
        *contents_out_len = span.size_int();
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}
