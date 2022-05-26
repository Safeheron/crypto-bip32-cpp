/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#include "hd_path.h"
#include <sstream>

namespace safeheron {
namespace bip32 {

bool HDPath::ParseHDPath(const std::string &keypath_str, std::vector<uint32_t> &keypath) {
    std::stringstream ss(keypath_str);
    std::string item;
    bool first = true;
    while (std::getline(ss, item, '/')) {
        if (item.compare("m") == 0) {
            if (first) {
                first = false;
                continue;
            }
            return false;
        }
        // Finds whether it is hardened
        uint32_t path = 0;
        size_t pos = item.find("'");
        if (pos != std::string::npos) {
            // The hardened tick can only be in the last index of the string
            if (pos != item.size() - 1) {
                return false;
            }
            path |= 0x80000000;
            item = item.substr(0, item.size() - 1); // Drop the last character which is the hardened tick
        }

        // Ensure this is only numbers
        if (item.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }
        uint32_t number;
        char *ptr = nullptr;
        number = strtoul(item.c_str(), &ptr, 10);
        path |= number;

        keypath.push_back(path);
        first = false;
    }
    return true;
}

std::string HDPath::FormatHDPath(const std::vector<uint32_t> &path) {
    std::string str;
    for (auto i : path) {
        str.append("/");
        str.append(std::to_string(i));
        if (i >> 31) str.append("\'");
    }
    return str;
}

std::string HDPath::WriteHDPath(const std::vector<uint32_t> &keypath) {
    return "m" + FormatHDPath(keypath);
}

}
}
