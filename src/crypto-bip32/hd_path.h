//
// Created by Sword03 on 2021/9/10.
//

#ifndef SAFEHERON_CRYPTOBIP32_HDPATH_H
#define SAFEHERON_CRYPTOBIP32_HDPATH_H

#include <string>
#include <vector>

namespace safeheron {
namespace bip32 {

class HDPath {
public:
    /** Parse an HD keypaths like "m/7/0'/2000". */
    static bool ParseHDPath(const std::string &keypath_str, std::vector<uint32_t> &keypath);

    /** Write HD keypaths as strings */
    static std::string WriteHDPath(const std::vector<uint32_t> &keypath);

    static std::string FormatHDPath(const std::vector<uint32_t> &path);
};

}
}

#endif //SAFEHERON_CRYPTOBIP32_HDPATH_H
