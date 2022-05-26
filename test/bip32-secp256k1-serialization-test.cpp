#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-bn/bn.h"
#include "exception/located_exception.h"
#include "crypto-curve/curve.h"
#include "crypto-bip32/bip32.h"
#include "crypto-encode/hex.h"
#include "crypto-encode/base58.h"
#include "crypto-encode/base64.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::bip32::HDKey;
using safeheron::exception::LocatedException;
using namespace safeheron::encode;

std::vector<std::vector<string>> case_data_serialize_hdkey_secp256k1 = {
        {
                "xprvA1CnPMjbTkNNtEVrTvG8SHrLPp7tc6xXDkpY59NGSy6fyHmLzTrFdcHWq5cqsiwK758pGuBaX9XJY1kR6PacgG3sJbAmcQCsarTgh8EJvY2",
                "xpub6EC8nsGVJ7vg6iaKZwo8oRo4wqxP1ZgNayk8sXmt1Jder66VY1AWBQbzgKz2X9fhvyJDtAZ425KwFm9bKLYD9cUUjddMevsRD2Qdrnk9a1m"
        },
        {
                "xprv9yUAqePdq9JYrAnxHWns8ooPknGjWSLkCYtKNB1EEqFKoqrX4DV91bP7YAefJzQU8CRHpsioXdVTMGHu8BhmGhPYSnXRoe8Sy31aoQGnQco",
                "xpub6CTXF9vXfWrr4esRPYKsVwk8Jp7Duu4bZmovAZQqoAnJgeBfbkoPZPhbPTvgcm2HRM7TmyYuLKS6MNh4eHvGV2nZAjtYXg7hbNWz2vZ7rMv"
        }
};

void testSerializeHDKey_Secp256k1(const std::string &xprv, const std::string &xpub){
    safeheron::bip32::HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::SECP256K1));

    std::string t_xpriv;
    hdKey.ToExtendedPrivateKey(t_xpriv);
    //std::cout << "t_xpriv:        " << t_xpriv << std::endl;
    //std::cout << "xprv: " << xprv << std::endl;
    std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(t_xpriv)) << std::endl;
    std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    EXPECT_TRUE(t_xpriv == xprv);

    safeheron::bip32::HDKey hdKey2;
    EXPECT_TRUE(hdKey2.FromExtendedPublicKey(xpub, CurveType::SECP256K1));
    std::string t_xpub;
    hdKey2.ToExtendedPublicKey(t_xpub);
    //std::cout << "t_xpub:        " << t_xpub << std::endl;
    //std::cout << "xpub: " << xpub << std::endl;
    EXPECT_TRUE(t_xpub == xpub);
}

TEST(Bip32, SerializeHDKey_Secp256k1)
{
    for(const auto &hd_key_pair: case_data_serialize_hdkey_secp256k1){
        const string &xprv = hd_key_pair[0];
        const string &xpub = hd_key_pair[1];
        testSerializeHDKey_Secp256k1(xprv, xpub);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
