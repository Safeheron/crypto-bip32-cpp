//
// Created by Sword03 on 2021/5/16.
//

#ifndef SAFEHERON_CRYPTO_BIP32_ECDSA_H
#define SAFEHERON_CRYPTO_BIP32_ECDSA_H

#include <string>
#include "crypto-curve/curve.h"
#include "common.h"

namespace safeheron {
namespace bip32 {
namespace _ecdsa {

int hdnode_from_seed(const uint8_t *seed, int seed_len, safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *out);

void hdnode_from_xprv(uint32_t depth, uint32_t child_num,
                      const uint8_t *chain_code, const uint8_t *private_key,
                      safeheron::curve::CurveType curve_type, HDNode *out);

int hdnode_from_xpub(uint32_t depth, uint32_t child_num,
                     const uint8_t *chain_code, const uint8_t *public_key,
                     safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *out);

uint32_t hdnode_fingerprint(const safeheron::bip32::HDNode *node);

void hdnode_fill_public_key(safeheron::bip32::HDNode *node);

int hdnode_private_ckd(safeheron::bip32::HDNode *inout, uint32_t i);

int hdnode_public_ckd_cp_ex(const curve::CurvePoint &parent,
                            const uint8_t *parent_chain_code, uint32_t i,
                            curve::CurvePoint &child, uint8_t *child_chain_code, safeheron::bignum::BN &delta);

int hdnode_public_ckd_ex(safeheron::bip32::HDNode *inout, uint32_t i, safeheron::bignum::BN &delta, curve::CurveType curve_type,
                         bool hd_node_has_private_key);

// check for validity of curve point in case of public data not performed
int hdnode_deserialize_ex(const char *str, uint32_t *version,
                          bool use_private, safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                          uint32_t *fingerprint);

int hdnode_deserialize_public_ex(const char *str, uint32_t *version,
                                 safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                                 uint32_t *fingerprint);

int hdnode_deserialize_private_ex(const char *str, uint32_t *version,
                                  safeheron::curve::CurveType curve_type, safeheron::bip32::HDNode *node,
                                  uint32_t *fingerprint);

std::string hdnode_serialize(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                             uint32_t version, bool use_private);

std::string hdnode_serialize_public(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                                    uint32_t version);

std::string hdnode_serialize_private(const safeheron::bip32::HDNode *node, uint32_t fingerprint,
                                     uint32_t version);
};
}
}


#endif //SAFEHERON_CRYPTO_BIP32_ECDSA_H
