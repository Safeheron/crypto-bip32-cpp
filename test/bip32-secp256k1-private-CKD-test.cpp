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

std::vector<string> case_data_root_xprv_secp256k1 = {"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"};
std::vector<std::vector<std::vector<std::string>>> case_data_private_ckd_child_key_secp256k1 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m/0'",
                        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
                },
                {
                        "m/0'/1",
                        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
                },
                {
                        "m/0'/1/2'",
                        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
                },
                {
                        "m/0'/1/2'/2",
                        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
                },
                {
                        "m/0'/1/2'/2/1000000000",
                        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
                },
        },
};
void testprivateCKD_Secp256k1(const string &xprv, const string &path, const string &child_xprv) {
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPrivateKey(xprv, CurveType::SECP256K1);
    ASSERT_TRUE(ok);
    std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string t_child_xprv;
    child_hd_key.ToExtendedPrivateKey(t_child_xprv);
    std::cout << "child_xprv: " << child_xprv << std::endl;
    ASSERT_EQ(t_child_xprv, child_xprv);
}

TEST(Bip32, PrivateCKDTestCase_Secp256k1) {
    for (size_t i = 0; i < case_data_root_xprv_secp256k1.size(); i++) {
        for (size_t j = 0; j < case_data_private_ckd_child_key_secp256k1[i].size(); j++) {
            const string &xprv = case_data_root_xprv_secp256k1[i];
            const string &path = case_data_private_ckd_child_key_secp256k1[i][j][0];
            const string &child_xprv = case_data_private_ckd_child_key_secp256k1[i][j][1];
            testprivateCKD_Secp256k1(xprv, path, child_xprv);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
