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

#include "openssl/evp.h"

#include "staticlib/config.hpp"
#include "staticlib/crypto.hpp"
#include "staticlib/json.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/unzip.hpp"
#include "staticlib/utils.hpp"

#include "wilton/wilton.h"
#include "wilton/wiltoncall.h"
#include "wilton/wilton_crypto.h"

#include "wilton/support/alloc.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/logging.hpp"
#include "wilton/support/misc.hpp"

namespace { // anonymous

const std::string logger = std::string("wilton.loader");

std::atomic_flag initialized = ATOMIC_FLAG_INIT;

struct loader_ctx {
    std::vector<sl::unzip::file_index> indices;
    std::string crypt_key;
    std::string init_vec;
    std::string base_wlib_path;

    loader_ctx() { }

    loader_ctx(std::vector<sl::unzip::file_index> idx_list,
            const std::string& key, const std::string& iv, const std::string& base_wlib) :
    indices(std::move(idx_list)),
    crypt_key(key.data(), key.length()),
    init_vec(iv.data(), iv.length()),
    base_wlib_path(base_wlib.data(), base_wlib.length()) { }

    loader_ctx(const loader_ctx&) = delete;

    loader_ctx& operator=(const loader_ctx&) = delete;

    loader_ctx(loader_ctx&& other):
    indices(std::move(other.indices)),
    crypt_key(std::move(other.crypt_key)),
    init_vec(std::move(other.init_vec)),
    base_wlib_path(std::move(other.base_wlib_path)) { }

    loader_ctx& operator=(loader_ctx&&) = delete;
};

// initialized from wilton_loader_initialize
loader_ctx& static_loader_context(loader_ctx ctx_in = loader_ctx()) {
    static loader_ctx ctx = std::move(ctx_in);
    return ctx;
}

sl::io::span<char> read_zip_resource(const std::string& path) {
    loader_ctx& ctx = static_loader_context();
    // search modules.zip indices
    for (auto& idx : ctx.indices) {
        // normalize path
        auto path_norm = sl::tinydir::normalize_path(path);
        // load zip entry
        auto& zippath = idx.get_zip_file_path();
        if (path.length() > zippath.length() + 1 && sl::utils::starts_with(path_norm, zippath)) {
            auto en_path = path_norm.substr(zippath.length() + 1);
            auto stream = sl::unzip::open_zip_entry(idx, en_path);
            auto src = sl::io::streambuf_source(stream->rdbuf());
            auto sink = sl::io::make_array_sink(wilton_alloc, wilton_free);
            // normal loading
            if (ctx.crypt_key.empty() || zippath == ctx.base_wlib_path) {
                sl::io::copy_all(src, sink);
            } else { // encrypted loading
                auto crypt_sink = sl::crypto::make_decrypt_sink(sink, EVP_aes_256_cbc(),
                        ctx.crypt_key, ctx.init_vec);
                sl::io::copy_all(src, crypt_sink);
            }
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

std::pair<std::string, std::string> init_crypt(const std::string& crypt_call) {
    // check crypt enabled
    if (crypt_call.empty()) {
        return std::make_pair(std::string(), std::string());
    }

    // get secret
    char* secret = nullptr;
    int secret_len = 0;
    auto err_secret = wiltoncall(crypt_call.c_str(), static_cast<int>(crypt_call.length()),
            "{}", 2, std::addressof(secret), std::addressof(secret_len));
    if (nullptr != err_secret) {
        wilton::support::throw_wilton_error(err_secret, TRACEMSG(err_secret));
    }
    auto deferred_secret = sl::support::defer([secret]() STATICLIB_NOEXCEPT {
        wilton_free(secret);
    });

    // create crypt params
    char* key = nullptr;
    int key_len = 0;
    char* iv = nullptr;
    int iv_len = 0;
    char* err_key = wilton_crypto_aes_create_crypt_key(secret, secret_len,
                std::addressof(key), std::addressof(key_len),
                std::addressof(iv), std::addressof(iv_len));
    if (nullptr != err_key) {
        wilton::support::throw_wilton_error(err_key, TRACEMSG(err_key));
    }
    auto deferred_key = sl::support::defer([key, iv]() STATICLIB_NOEXCEPT {
        wilton_free(key);
        wilton_free(iv);
    });
    
    auto key_str = std::string(key, static_cast<size_t>(key_len));
    auto iv_str = std::string(iv, static_cast<size_t>(iv_len));
    return std::make_pair(key_str, iv_str);
}

} // namespace

char* wilton_loader_initialize(const char* conf_json, int conf_json_len) /* noexcept */ {
    if (nullptr == conf_json) return wilton::support::alloc_copy(TRACEMSG("Null 'conf_json' parameter specified"));
    if (!sl::support::is_uint32_positive(conf_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'conf_json_len' parameter specified: [" + sl::support::to_string(conf_json_len) + "]"));
    try {
        // check called once
        if (initialized.test_and_set(std::memory_order_acq_rel)) {
            throw wilton::support::exception(TRACEMSG("'wilton_loader' is already initialized"));
        }

        // prepare zip indices
        auto cf = sl::json::load({conf_json, conf_json_len});
        auto stdpath = cf["requireJs"]["baseUrl"].as_string_nonempty_or_throw("requireJs.baseUrl");
        auto vec = std::vector<sl::unzip::file_index>();
        auto base_wlib_path = std::string();
        if (sl::utils::starts_with(stdpath, wilton::support::zip_proto_prefix)) {
            auto zippath = stdpath.substr(wilton::support::zip_proto_prefix.length());
            base_wlib_path = sl::tinydir::normalize_path(zippath);
            vec.emplace_back(sl::unzip::file_index(base_wlib_path));
        }
        auto zipmods = std::vector<std::string>();
        for (auto& fi : cf["requireJs"]["paths"].as_object_or_throw("requireJs.paths")) {
            auto modpath = fi.val().as_string_nonempty_or_throw("requireJs.paths[]");
            if (sl::utils::starts_with(modpath, wilton::support::zip_proto_prefix)) {
                auto zippath = modpath.substr(wilton::support::zip_proto_prefix.length());
                auto zippath_norm = sl::tinydir::normalize_path(zippath);
                vec.emplace_back(sl::unzip::file_index(zippath_norm));
                zipmods.push_back(zippath_norm);
            }
        }

        // prepare crypt params
        auto crypt_call = cf["cryptCall"].as_string_or_throw("cryptCall");
        auto crypt_pars = init_crypt(crypt_call);

        // create context
        auto ctx = loader_ctx(std::move(vec), crypt_pars.first, crypt_pars.second, base_wlib_path);
        static_loader_context(std::move(ctx));

        // check crypt sanity
        if (!crypt_pars.first.empty()) { 
            for (auto& path : zipmods) {
                auto span = read_zip_resource(path + "/sanity.txt");
                auto deferred = sl::support::defer([span]() STATICLIB_NOEXCEPT {
                    wilton_free(span.data());
                });
                if (6 != span.size() || std::string("sanity") != std::string(span.data(), span.size())) {
                    throw wilton::support::exception(TRACEMSG(
                            "Decryption sanity check failed, path: [" + path + "]"));
                }
            }
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
