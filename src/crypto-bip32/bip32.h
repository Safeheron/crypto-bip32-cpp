//
// Created by Sword03 on 2021/7/1.
//

#ifndef SAFEHERON_CRYPTO_BIP32_H
#define SAFEHERON_CRYPTO_BIP32_H

#include <string>
#include <vector>
#include "crypto-curve/curve.h"
#include "common.h"

namespace safeheron {
namespace bip32{


class HDKey {
    safeheron::curve::CurveType curve_type_;
    HDNode hd_node_;
    uint32_t fingerprint_;

public:
    HDKey();
    HDKey(const HDKey &hdKey);            // copy constructor
    HDKey &operator=(const HDKey &hdKey); // copy assignment
    ~HDKey();

    static HDKey CreateHDKey(safeheron::curve::CurveType c_type, const safeheron::bignum::BN & privateKey, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);
    static HDKey CreateHDKey(safeheron::curve::CurveType c_type, const safeheron::curve::CurvePoint & publicKey, const uint8_t *chain_code, uint32_t depth=0, uint32_t child_num=0, uint32_t fingerprint=0);

    bool HasPrivateKey() const;

    void GetPrivateKey(safeheron::bignum::BN &priv) const;
    void GetPrivateKey(uint8_t *buf32) const;

    void GetPublicKey(safeheron::curve::CurvePoint &point) const;
    static void GetPublicKeyEx(safeheron::curve::CurvePoint &point, const HDNode &hd_node, safeheron::curve::CurveType curve_type, bool hd_node_is_private);

    void GetChainCode(uint8_t *buf32) const;

    HDKey PrivateCKD(uint32_t i) const;
    HDKey PublicCKD(uint32_t i) const;
    HDKey PublicCKD(uint32_t i, safeheron::bignum::BN &delta) const;

    HDKey PrivateCKDPath(const char * path) const;
    HDKey PrivateCKDPath(std::string &path) const;
    HDKey PublicCKDPath(const char *path, safeheron::bignum::BN &delta) const;
    HDKey PublicCKDPath(const std::string &path, safeheron::bignum::BN &delta) const;
    HDKey PublicCKDPath(const char *path) const;
    HDKey PublicCKDPath(const std::string &path) const;

    bool FromExtendedPublicKey(const char * xpub, safeheron::curve::CurveType c_type);
    bool FromExtendedPublicKey(const std::string &xpub, safeheron::curve::CurveType c_type);
    bool FromExtendedPrivateKey(const char * xprv, safeheron::curve::CurveType c_type);
    bool FromExtendedPrivateKey(const std::string &xprv, safeheron::curve::CurveType c_type);
    bool ToExtendedPublicKey(std::string &xpub) const;
    bool ToExtendedPrivateKey(std::string &xprv) const;

    bool FromSeed(safeheron::curve::CurveType curve_type, const uint8_t *seed, int seed_len);
};

};
};


#endif //SAFEHERON_CRYPTO_BIP32_H
