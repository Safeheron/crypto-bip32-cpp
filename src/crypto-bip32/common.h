//
// Created by Sword03 on 2022/3/11.
//

#ifndef SAFEHERON_CRYPTOBIP32_COMMON_H
#define SAFEHERON_CRYPTOBIP32_COMMON_H

namespace safeheron {
namespace bip32 {

/**
 * Curve type
 */
enum class Bip32Version : uint32_t {
    INVALID_VERSION = 0,
    BITCOIN_VERSION_PRIVATE = 0x0488ADE4,
    BITCOIN_VERSION_PUBLIC = 0x0488B21E,
    EDDSA_VERSIONS_PRIVATE = 0x03126f7c,
    EDDSA_VERSIONS_PUBLIC = 0x031273b7,
};

typedef struct {
    uint32_t curve_type_;
    uint32_t depth_;
    uint32_t child_num_;
    uint8_t chain_code_[32];

    uint8_t private_key_[32];
    uint8_t private_key_extension_[32];

    uint8_t public_key_[33];
} HDNode;

}
}

#endif //SAFEHERON_CRYPTOBIP32_COMMON_H
