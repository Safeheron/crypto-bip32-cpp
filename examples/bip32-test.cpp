//
// Created by Sword03 on 2020/10/22.
//
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

std::vector<std::vector<string>> case_data_public_cdk_secp256k1 = {
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/0",
                "xpub6FhYNQEVoQX8hDWvvuagZu7w2oBhgwWLJcQKeUpqeMbD4F5mYcHe3cWdzcLkuWVgXQbCoYDcWo1GT9gjDJxfR1a3UiL8YdEccCtduJZSYm8",
                "68ccb77ec22767916e6364c4f514021169a14bec0e40fd817b5d08ee04345349"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/1",
                "xpub6FhYNQEVoQX8kAAWmYh966iMnE1sQ8ThaYK1UYeihUPEdM3oEWMaWgmTWSxm8nUnAHe2VAWEJmYfNqLfcRT8c8aBwuRQ1VEsYEue6bryKnH",
                "572d022fd0c1fdd9e90bf0f85a6b6d9492469df4b3beec5350b5a634f940d97"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/2",
                "xpub6FhYNQEVoQX8nZKHbeokzeuJLgSPruJmgjHVeSDiWETiWJ4hZGEPEpQNzXsYXtZ14xt8pUA4yPh9yCSB1ysHstNAeWo7hd4sNV1CcztdfZW",
                "4c48648d91bd8ab02872a5631930783e59b42f9aa16339e2703ac9293ccafe43"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/3",
                "xpub6FhYNQEVoQX8poKL4mpc9754yphsqSJqVtJUEVVn846GyR9ReXR4bhkFmSDac3ui479KTvTDsQAR1yHcL3XFG6om8D7oRCEGxrMiYNRbG6G",
                "d13d3f61687bc407c23cf25ee88fa012b51f1937ddd4491179329d7734f0f788"
        },
        {
                "xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9",
                "m/44/60/0/0/4",
                "xpub6FhYNQEVoQX8thvrJ96vR3VcMo345uwvjrt2ybS5kMzGez3YR1w2MVQ6CqHmWgNDYrbqVX3SincAuX6Qa4KxsPv9X3n43edWnC3vD7xz8km",
                "f35243e947cf29d324e3266dc08bdd6486e311c7b16a68e09a2f9f6a596c5ebd"
        }
};

void testPublicCKD_Secp256k1(std::string xprv, std::string path, std::string child_xpub, std::string deltaStr){
    BN delta = BN::FromHexStr(deltaStr);
    safeheron::bip32::HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::SECP256K1));

    safeheron::bip32::HDKey childHDKey;
    BN t_delta;
    childHDKey = hdKey.PublicCKDPath(path, t_delta);
    std::string t_child_xpub;
    childHDKey.ToExtendedPublicKey(t_child_xpub);
    std::cout << "  child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    std::cout << "t_child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(t_child_xpub)) << std::endl;
    EXPECT_TRUE(child_xpub == t_child_xpub);
    EXPECT_TRUE(delta == t_delta);


    std::string t_delta_str;
    t_delta.ToHexStr(t_delta_str);
    //std::cout << "delta: " << t_delta_str << std::endl;
}


TEST(Bip32, PublicCDK_Secp256k1)
{
    for(const auto &item: case_data_public_cdk_secp256k1){
        const string &xprv = item[0];
        const string &path = item[1];
        const string &child_xpub = item[2];
        const string &delta = item[3];
        testPublicCKD_Secp256k1(xprv, path, child_xpub, delta);
    }
}


// Official test cases in standard "BIP 32"
std::vector<string> case_data_official_seeds_secp256k1 = {"000102030405060708090a0b0c0d0e0f",
                                                          "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                                                          "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                                                          "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"};
std::vector<std::vector<std::vector<std::string>>> case_data_official_child_key_secp256k1 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m",
                        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                },
                {
                        "m/0'",
                        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
                },
                {
                        "m/0'/1",
                        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                },
                {
                        "m/0'/1/2'",
                        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
                },
                {
                        "m/0'/1/2'/2",
                        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                },
                {
                        "m/0'/1/2'/2/1000000000",
                        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                },
        },

        {
                // extendedKeys for seed "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
                {
                        "m",
                        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                },
                {
                        "m/0",
                        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                },
                {
                        "m/0/2147483647'",
                        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
                },
                {
                        "m/0/2147483647'/1",
                        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                },
                {
                        "m/0/2147483647'/1/2147483646'",
                        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
                },
                {
                        "m/0/2147483647'/1/2147483646'/2",
                        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
                },
        },
        {
                // extendedKeys for seed "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
                {
                        "m",
                        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                },
                {
                        "m/0'",
                        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
                },
        },

        {
                // extendedKeys for seed "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"
                {
                        "m",
                        "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
                },
                {
                        "m/0'",
                        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
                },
                {
                        "m/0'/1'",
                        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
                },
        }
};

void testSeedAndCKD_Secp256k1(const string &seed, const string &path, const string &xprv, const string &xpub){
    bool ok;
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed);
    ok = root_hd_key.FromSeed(CurveType::SECP256K1, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    //std::cout << "child_xprv: " << child_xprv << std::endl;
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    std::cout << "child_xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xpub)) << std::endl;
    std::cout << "      xpub: " << hex::EncodeToHex(base58::DecodeFromBase58(xpub)) << std::endl;
    ASSERT_EQ(child_xprv, xprv);
    ASSERT_EQ(child_xpub, xpub);
}

TEST(Bip32, OfficialTestCase_Secp256k1)
{
    for(size_t i = 0; i < case_data_official_seeds_secp256k1.size(); i++ ){
        for(size_t j = 0; j < case_data_official_child_key_secp256k1[i].size(); j++){
            const string & seed = case_data_official_seeds_secp256k1[i];
            const string & path = case_data_official_child_key_secp256k1[i][j][0];
            const string & xprv = case_data_official_child_key_secp256k1[i][j][1];
            const string & xpub = case_data_official_child_key_secp256k1[i][j][2];
            try{
                testSeedAndCKD_Secp256k1(seed, path, xprv, xpub);
            }catch (const LocatedException &e){
                std::cout << "exception: " << e.detail() << std::endl;
            }
        }
    }
}

std::vector<string> case_data_root_xpub_secp256k1 = {"xpub661MyMwAqRbcGQmVCzudmLbsCwDVcyZPHEumbwahrVxrBwS3QkGDEbVtTBwvUP4HruZn2cssHsywMREQh9R3XgUbe7hjfK2Z5sxJrJQEnNh"};
std::vector<std::vector<std::vector<std::string>>> case_data_public_ckd_child_key_secp256k1 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m/44/60/0/0/0",
                        "xpub6FhYNQEVoQX8hDWvvuagZu7w2oBhgwWLJcQKeUpqeMbD4F5mYcHe3cWdzcLkuWVgXQbCoYDcWo1GT9gjDJxfR1a3UiL8YdEccCtduJZSYm8",
                },
                {
                        "m/44/60/0/0/1",
                        "xpub6FhYNQEVoQX8kAAWmYh966iMnE1sQ8ThaYK1UYeihUPEdM3oEWMaWgmTWSxm8nUnAHe2VAWEJmYfNqLfcRT8c8aBwuRQ1VEsYEue6bryKnH"
                },
                {
                        "m/44/60/0/0/2",
                        "xpub6FhYNQEVoQX8nZKHbeokzeuJLgSPruJmgjHVeSDiWETiWJ4hZGEPEpQNzXsYXtZ14xt8pUA4yPh9yCSB1ysHstNAeWo7hd4sNV1CcztdfZW"
                },
                {
                        "m/44/60/0/0/3",
                        "xpub6FhYNQEVoQX8poKL4mpc9754yphsqSJqVtJUEVVn846GyR9ReXR4bhkFmSDac3ui479KTvTDsQAR1yHcL3XFG6om8D7oRCEGxrMiYNRbG6G"
                },
                {
                        "m/44/60/0/0/4",
                        "xpub6FhYNQEVoQX8thvrJ96vR3VcMo345uwvjrt2ybS5kMzGez3YR1w2MVQ6CqHmWgNDYrbqVX3SincAuX6Qa4KxsPv9X3n43edWnC3vD7xz8km"
                },
        },
};

void testPublicCKD_Secp256k1(const string &xpub, const string &path, const string &child_xpub){
    bool ok;
    HDKey root_hd_key;
    ok = root_hd_key.FromExtendedPublicKey(xpub, CurveType::SECP256K1);
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    BN delta;
    HDKey child_hd_key = root_hd_key.PublicCKDPath(path.c_str(), delta);
    string t_child_xpub;
    child_hd_key.ToExtendedPublicKey(t_child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(t_child_xpub, child_xpub);

    const Curve *curv = GetCurveParam(CurveType::SECP256K1);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Secp256k1)
{
    for(size_t i = 0; i < case_data_root_xpub_secp256k1.size(); i++ ){
        for(size_t j = 0; j < case_data_public_ckd_child_key_secp256k1[i].size(); j++){
            const string & xpub = case_data_root_xpub_secp256k1[i];
            const string & path = case_data_public_ckd_child_key_secp256k1[i][j][0];
            const string & child_xpub = case_data_public_ckd_child_key_secp256k1[i][j][1];
            testPublicCKD_Secp256k1(xpub, path, child_xpub);
        }
    }
}


std::vector<std::vector<string>> case_data_serialize_hdkey_ed25519 = {
        {
                "eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c",
                "epub8YjJEGN2T9xLdin8GVPo4JD8jS9FWrCtvP4j48pZUA7zjuFWN7igGdB4F39s7umSx7CoiLF13yzPL8sUJWL14sPkVMdY9VHQjZVeVQSjWPZ",
        },
        {
                "eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm",
                "epub8fRQ8yUwFP8cyL4S6pkNgEnhovARJJ4fGiA7AK18bghTwdaL8WmVNtey5uWHTYN8V63YFCD8L1xW9YCoKd6vwd7jtzLnBfeGqJ4De4Fe9wB"
        },
        {
                "eprv48jMzZSh71Sx9f2jQAshscVct4EEMS4dkcPHvWmNM6g5uZrqtLFJ9574cUzHbEX3UatTSEtcVsJVS1eYZAFy6sAK1PJpk14qFsyen9riCtv",
                "epub8fRQ8yUwFP8d384XHpYJH29jT5kAWmFYKuz5D2ofmNUUk47cWj4tKZivnXy97eKHQY5oQUv5qTMLJng16n4PAfB4U8ap7Z7b7FXVijt2pzg"
        },
};

void testSerializeHDKey_Ed25519(const std::string &xprv, const std::string &xpub){
    HDKey hdKey;
    EXPECT_TRUE(hdKey.FromExtendedPrivateKey(xprv, CurveType::ED25519));

    std::string t_xpriv;
    hdKey.ToExtendedPrivateKey(t_xpriv);
    //std::cout << "t_xpriv:        " << t_xpriv << std::endl;
    //std::cout << "xprv: " << xprv << std::endl;
    EXPECT_TRUE(t_xpriv == xprv);

    HDKey hdKey2;
    EXPECT_TRUE(hdKey2.FromExtendedPublicKey(xpub, CurveType::ED25519));
    std::string t_xpub;
    hdKey2.ToExtendedPublicKey(t_xpub);
    //std::cout << "t_xpub:        " << t_xpub << std::endl;
    //std::cout << "xpub: " << xpub << std::endl;
    EXPECT_TRUE(t_xpub == xpub);
}

TEST(Bip32, SerializeHDKey_Ed25519)
{
    for(const auto &hd_key_pair: case_data_serialize_hdkey_ed25519){
        const string &xprv = hd_key_pair[0];
        const string &xpub = hd_key_pair[1];
        testSerializeHDKey_Ed25519(xprv, xpub);
    }
}
std::vector<string> case_data_seeds_ed25519 = {"0102030405060708090A0B0C0D0E0F10"};
std::vector<std::vector<std::vector<std::string>>> case_data_child_key_ed25519 = {
        {
                // extendedKeys for seed "000102030405060708090a0b0c0d0e0f"
                {
                        "m",
                        "eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c",
                        "epub8YjJEGN2T9xLdin8GVPo4JD8jS9FWrCtvP4j48pZUA7zjuFWN7igGdB4F39s7umSx7CoiLF13yzPL8sUJWL14sPkVMdY9VHQjZVeVQSjWPZ",
                },
                {
                        "m/44/60/0",
                        "eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm",
                        "epub8fRQ8yUwFP8cyL4S6pkNgEnhovARJJ4fGiA7AK18bghTwdaL8WmVNtey5uWHTYN8V63YFCD8L1xW9YCoKd6vwd7jtzLnBfeGqJ4De4Fe9wB"
                },
                {
                        "m/44/60/1",
                        "eprv48jMzZSh71Sx9f2jQAshscVct4EEMS4dkcPHvWmNM6g5uZrqtLFJ9574cUzHbEX3UatTSEtcVsJVS1eYZAFy6sAK1PJpk14qFsyen9riCtv",
                        "epub8fRQ8yUwFP8d384XHpYJH29jT5kAWmFYKuz5D2ofmNUUk47cWj4tKZivnXy97eKHQY5oQUv5qTMLJng16n4PAfB4U8ap7Z7b7FXVijt2pzg"
                },
                {
                        "m/44/60/2",
                        "eprv48jMzZSh71SxAQfV9mHKJmhBP6pvzZsdZGTYCuzJb2bNnKhvsEjU2d3sfBEZZ4xfFfNCQrXMsF7fgQJs3vJoU5poivTkVhCTbjW31HxrPtU",
                        "epub8fRQ8yUwFP8d3shH3QwuiBMHx8Ls9u4Y8a4KVS2c1JPmcoxhVdZ4D7fjqEyjfxpwGsXzGDT5TW6CX5Vjk9bHRpcYW7q2KCdfNYpsoKckHGc"
                },
                {
                        "m/44/60/3",
                        "eprv48jMzZSh71SxEY29US1HTD117pa7WvqPimsEANK8zLMaHNYa4XD8gmMqLXWtNXit5uEtsCzjqLZaBdNE2aX2rPM9EgzwmyTYtzYRFWcNPgi",
                        "epub8fRQ8yUwFP8d813wN5fsrcf7gr63gG2JJ5U1StMSQc9y7roLgv2isFyhWafzi6dkndaoAVakLJ1fELVCVTXqRVdjcnhcvnQPgMRJRB2TY3d"
                },
                {
                        "m/44/60/4",
                        "eprv48jMzZSh71SxGQr3YyAizSjsdjx5MqFq9nSupn39wR4wMyprnF3xPuYdkcpBWEYBwjDCJH3z3X8ovjWTJTmx5xxwvpofDRsY9RTwWVPWpC8",
                        "epub8fRQ8yUwFP8d9ssqScqKPrPzCmU1XASjj63h7J5TMgsLCU5dQdsYaQAVvfiKyvAJSoQMsSW6AweVYWnAuEgLrmq7TwJptRCtpLqPShfCdBR"
                },
        },
};

void testSeedAndCKD_Ed25519(const string &seed_hex, const string &path, const string &xprv, const string &xpub){
    bool ok;
    HDKey root_hd_key;
    string data = hex::DecodeFromHex(seed_hex);
    ok = root_hd_key.FromSeed(CurveType::ED25519, reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
    ASSERT_TRUE(ok);
    //std::cout << "path: " << path << std::endl;
    HDKey child_hd_key = root_hd_key.PrivateCKDPath(path.c_str());
    string child_xprv, child_xpub;
    child_hd_key.ToExtendedPrivateKey(child_xprv);
    child_hd_key.ToExtendedPublicKey(child_xpub);

    //std::cout << "child_xprv: " << child_xprv << std::endl;
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    std::cout << "child_xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(child_xprv)) << std::endl;
    std::cout << "      xprv: " << hex::EncodeToHex(base58::DecodeFromBase58(xprv)) << std::endl;
    ASSERT_EQ(child_xprv, xprv);
    ASSERT_EQ(child_xpub, xpub);

    BN delta(0);
    string root_xpub;
    root_hd_key.ToExtendedPublicKey(root_xpub);
    HDKey root_hd_key_p;
    ok = root_hd_key_p.FromExtendedPublicKey(root_xpub, CurveType::ED25519);
    ASSERT_TRUE(ok);
    child_hd_key = root_hd_key_p.PublicCKDPath(path.c_str(), delta);
    child_hd_key.ToExtendedPublicKey(child_xpub);
    //std::cout << "child_xpub: " << child_xpub << std::endl;
    ASSERT_EQ(child_xpub, xpub);


    const Curve *curv = safeheron::curve::GetCurveParam(CurveType::ED25519);
    CurvePoint root_point;
    root_hd_key.GetPublicKey(root_point);
    CurvePoint child_point;
    child_hd_key.GetPublicKey(child_point);
    EXPECT_TRUE((root_point +  curv->g * delta == child_point));
}

TEST(Bip32, PublicCKDTestCase_Ed25519)
{
    for(size_t i = 0; i < case_data_child_key_ed25519.size(); i++ ){
        for(size_t j = 0; j < case_data_child_key_ed25519[i].size(); j++){
            const string & seed = case_data_seeds_ed25519[i];
            const string & path = case_data_child_key_ed25519[i][j][0];
            const string & xprv = case_data_child_key_ed25519[i][j][1];
            const string & xpub = case_data_child_key_ed25519[i][j][2];
            testSeedAndCKD_Ed25519(seed, path, xprv, xpub);
        }
    }
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
