/* 
 * File:   wilton_loader.cpp
 * Author: alex
 *
 * Created on October 18, 2017, 8:43 AM
 */


#include "wilton/wilton_loader.h"

#include <cstdint>

#include "staticlib/config.hpp"
#include "staticlib/json.hpp"
#include "staticlib/tinydir.hpp"
#include "staticlib/unzip.hpp"
#include "staticlib/utils.hpp"

#include "wilton/support/alloc_copy.hpp"
#include "wilton/support/exception.hpp"
#include "wilton/support/misc.hpp"

namespace { // anonymous

sl::support::observer_ptr<sl::unzip::file_index> static_modules_idx(sl::unzip::file_index* index = nullptr) {
    static std::unique_ptr<sl::unzip::file_index> idx = std::unique_ptr<sl::unzip::file_index>(index);
    return sl::support::make_observer_ptr(idx.get());
}

sl::io::span<char> read_zip_resource(const std::string& path) {
    // get modules.zip index
    auto idx_ptr = static_modules_idx();
    if (!idx_ptr.has_value()) {
        throw wilton::support::exception(TRACEMSG(
                "Modules index not loaded, requested zip path: [" + path + "]"));
    }
    auto& idx = *idx_ptr;
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
    throw wilton::support::exception(TRACEMSG("Error loading zip entry," +
            " path: [" + path + "], zip file: [" + zippath + "]"));
}

sl::io::span<char> read_fs_resource(const std::string& path) {
    auto src = sl::tinydir::file_source(path);
    auto sink = sl::io::make_array_sink(wilton_alloc, wilton_free);
    sl::io::copy_all(src, sink);
    return sink.release();
}

sl::io::span<char> read_zip_or_fs_resource(const std::string& url) {
    if (sl::utils::starts_with(url, wilton::support::file_proto_prefix)) {
        return read_fs_resource(url.substr(wilton::support::file_proto_prefix.length()));
    } else if (sl::utils::starts_with(url, wilton::support::zip_proto_prefix)) {
        auto zurl = url.substr(wilton::support::zip_proto_prefix.length());
        return read_zip_resource(zurl);
    } else {
        throw wilton::support::exception(TRACEMSG("Unknown protocol prefix, url: [" + url + "]"));
    }
}

std::string read_main_from_package_json(const std::string& url) {
    std::string pjurl = std::string(url) + "package.json";
    try {
        auto span = read_zip_or_fs_resource(pjurl);
        auto deferred = sl::support::defer([span] () STATICLIB_NOEXCEPT {
            wilton_free(span.data());
        });
        auto pj = sl::json::load(span);
        auto main = pj["main"].as_string("index.js");
        if (!sl::utils::ends_with(main, ".js")) {
            main.append(".js");
        }
        return main;
    } catch (const std::exception&) {
        return "index.js";
    }
}

} // namespace

char* wilton_loader_initialize(const char* conf_json, int conf_json_len) /* noexcept */ {
    if (nullptr == conf_json) return wilton::support::alloc_copy(TRACEMSG("Null 'conf_json' parameter specified"));
    if (!sl::support::is_uint32_positive(conf_json_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'conf_json_len' parameter specified: [" + sl::support::to_string(conf_json_len) + "]"));
    try {
        auto cf = sl::json::load({conf_json, conf_json_len});
        auto modpath = cf["requireJs"]["baseUrl"].as_string_nonempty_or_throw("requireJs.baseUrl");
        if (sl::utils::starts_with(modpath, wilton::support::zip_proto_prefix)) {
            auto zippath = modpath.substr(wilton::support::zip_proto_prefix.length());
            auto zippath_norm = sl::tinydir::normalize_path(zippath);
            static_modules_idx(new sl::unzip::file_index(zippath_norm));
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
        *contents_out_len = static_cast<int>(span.size());
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}

// todo: think about dropping exceptions
char* wilton_load_script(const char* url, int url_len,
        char** contents_out, int* contents_out_len) /* noexcept */ {
    if (nullptr == url) return wilton::support::alloc_copy(TRACEMSG("Null 'url' parameter specified"));
    if (!sl::support::is_uint16_positive(url_len)) return wilton::support::alloc_copy(TRACEMSG(
            "Invalid 'url_len' parameter specified: [" + sl::support::to_string(url_len) + "]"));
    if (nullptr == contents_out) return wilton::support::alloc_copy(TRACEMSG("Null 'contents_out' parameter specified"));
    if (nullptr == contents_out_len) return wilton::support::alloc_copy(TRACEMSG("Null 'contents_out_len' parameter specified"));
    try {
        auto url_str = std::string(url, static_cast<uint16_t>(url_len));
        try {
            auto span = read_zip_or_fs_resource(url_str);
            *contents_out = span.data();
            *contents_out_len = static_cast<int>(span.size());
        } catch (const std::exception& epath) {
            if (sl::utils::ends_with(url_str, ".js")) {
                url_str.resize(url_str.length() - 3);
            }
            if (!sl::utils::ends_with(url_str, "/")) {
                url_str.push_back('/');
            }
            auto main = read_main_from_package_json(url_str);
            url_str.append(main);
            try {
                auto span = read_zip_or_fs_resource(url_str);
                *contents_out = span.data();
                *contents_out_len = static_cast<int>(span.size());
            } catch (const std::exception& etpath) {
                throw wilton::support::exception(TRACEMSG(epath.what()));
            }
        }
        return nullptr;
    } catch (const std::exception& e) {
        return wilton::support::alloc_copy(TRACEMSG(e.what() + "\nException raised"));
    }
}
