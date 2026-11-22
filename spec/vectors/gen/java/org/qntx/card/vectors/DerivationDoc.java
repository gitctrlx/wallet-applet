// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * {@code derivation.json}: master keys and child derivations of spec/protocol.md §10.2–10.4. The
 * official BIP-32 test vectors 1–5 and SLIP-0010 ed25519 test vectors 1–2 are copied verbatim from
 * the standards documents; every {@code privateKey}/{@code chainCode}/{@code publicKey} the
 * generator derives is asserted against the value decoded from the official {@code xprv}/{@code
 * xpub} (Base58Check; chain code = bytes 13..45, key = bytes 45..78) or printed in SLIP-0010.
 * Wei25519 points additionally cross the RFC 8032 public keys computed by BouncyCastle's own
 * Ed25519 implementation and the §10.4 worked example.
 */
final class DerivationDoc {
    static final byte[] TEMPLATE_SEED = Vec.det("derivation/template", 64);

    private static final String XPRV_VERSION = "0488ade4";
    private static final String XPUB_VERSION = "0488b21e";

    /** One BIP-32 chain entry of the standard: path, official ext pub, official ext prv. */
    private record Official(String path, String xpub, String xprv) {}

    /** One SLIP-0010 chain entry: path and the official private, chain code and public values. */
    private record Slip(String path, String privateKey, String chainCode, String publicKey) {}

    private DerivationDoc() {}

    static Object document() {
        rfc8032WorkedExample();
        return Vec.object(
                "bip32", bip32(),
                "bip32Invalid", bip32Invalid(),
                "slip10", slip10(),
                "invalidChild", invalidChild(),
                "invalidMaster", invalidMaster(),
                "templates", templates(),
                "wei25519", wei25519());
    }

    // BIP-32 test vectors 1–4 (github.com/bitcoin/bips/bip-0032.mediawiki), verbatim.
    private static final String[][] BIP32_SEEDS = {
        {"000102030405060708090a0b0c0d0e0f"},
        {
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        },
        {
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        },
        {"3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"},
    };

    private static final Official[][] BIP32_NODES = {
        {
            new Official(
                    "m",
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
            new Official(
                    "m/0'",
                    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
            new Official(
                    "m/0'/1",
                    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
            new Official(
                    "m/0'/1/2'",
                    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
            new Official(
                    "m/0'/1/2'/2",
                    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
            new Official(
                    "m/0'/1/2'/2/1000000000",
                    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
        },
        {
            new Official(
                    "m",
                    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"),
            new Official(
                    "m/0",
                    "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                    "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
            new Official(
                    "m/0/2147483647'",
                    "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                    "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
            new Official(
                    "m/0/2147483647'/1",
                    "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                    "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
            new Official(
                    "m/0/2147483647'/1/2147483646'",
                    "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                    "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
            new Official(
                    "m/0/2147483647'/1/2147483646'/2",
                    "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                    "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
        },
        {
            new Official(
                    "m",
                    "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                    "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"),
            new Official(
                    "m/0'",
                    "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                    "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"),
        },
        {
            new Official(
                    "m",
                    "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
                    "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"),
            new Official(
                    "m/0'",
                    "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
                    "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"),
            new Official(
                    "m/0'/1'",
                    "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
                    "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"),
        },
    };

    // BIP-32 test vector 5, verbatim: extended keys a host MUST reject.
    private static final String[][] BIP32_INVALID = {
        {
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
            "pubkey version / prvkey mismatch"
        },
        {
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
            "prvkey version / pubkey mismatch"
        },
        {
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
            "invalid pubkey prefix 04"
        },
        {
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
            "invalid prvkey prefix 04"
        },
        {
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
            "invalid pubkey prefix 01"
        },
        {
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
            "invalid prvkey prefix 01"
        },
        {
            "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
            "zero depth with non-zero parent fingerprint"
        },
        {
            "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
            "zero depth with non-zero parent fingerprint"
        },
        {
            "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
            "zero depth with non-zero index"
        },
        {
            "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
            "zero depth with non-zero index"
        },
        {
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
            "unknown extended key version"
        },
        {
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
            "unknown extended key version"
        },
        {
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
            "private key 0 not in 1..n-1"
        },
        {
            "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
            "private key n not in 1..n-1"
        },
        {
            "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
            "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007"
        },
        {
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
            "invalid checksum"
        },
    };

    // SLIP-0010 ed25519 test vectors 1 and 2 (github.com/satoshilabs/slips/slip-0010), verbatim.
    private static final String[] SLIP10_SEEDS = {
        "000102030405060708090a0b0c0d0e0f",
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    };

    private static final Slip[][] SLIP10_NODES = {
        {
            new Slip(
                    "m",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                    "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
            new Slip(
                    "m/0'",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                    "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
            new Slip(
                    "m/0'/1'",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                    "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
            new Slip(
                    "m/0'/1'/2'",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                    "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"),
            new Slip(
                    "m/0'/1'/2'/2'",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                    "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"),
            new Slip(
                    "m/0'/1'/2'/2'/1000000000'",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                    "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"),
        },
        {
            new Slip(
                    "m",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                    "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                    "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"),
            new Slip(
                    "m/0'",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                    "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                    "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"),
            new Slip(
                    "m/0'/2147483647'",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                    "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                    "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"),
            new Slip(
                    "m/0'/2147483647'/1'",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                    "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                    "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"),
            new Slip(
                    "m/0'/2147483647'/1'/2147483646'",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                    "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                    "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"),
            new Slip(
                    "m/0'/2147483647'/1'/2147483646'/2'",
                    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                    "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                    "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0"),
        },
    };

    private static List<Object> bip32() {
        List<Object> out = new ArrayList<>();
        for (int v = 0; v < BIP32_NODES.length; v++) {
            List<Object> nodes = new ArrayList<>();
            Hd.Node node = Hd.bip32Master(Vec.unhex(BIP32_SEEDS[v][0]));
            int depth = 0;
            for (Official o : BIP32_NODES[v]) {
                long[] idx = Hd.indices(o.path());
                while (depth < idx.length) {
                    node = Hd.bip32Child(node, idx[depth++]);
                    if (node == null) {
                        throw new IllegalStateException("invalid child on " + o.path());
                    }
                }
                byte[] pub =
                        Crypto.compress(Crypto.publicKey(new BigInteger(1, node.privateKey())));
                byte[] prv = Base58.decodeCheck(o.xprv());
                byte[] xpb = Base58.decodeCheck(o.xpub());
                assertHex(Arrays.copyOf(prv, 4), XPRV_VERSION, "xprv version of " + o.path());
                assertHex(Arrays.copyOf(xpb, 4), XPUB_VERSION, "xpub version of " + o.path());
                if (prv[45] != 0) {
                    throw new IllegalStateException("xprv key prefix: " + o.path());
                }
                assertHex(
                        node.privateKey(),
                        Vec.hex(Arrays.copyOfRange(prv, 46, 78)),
                        "privateKey of " + o.path());
                assertHex(
                        node.chainCode(),
                        Vec.hex(Arrays.copyOfRange(prv, 13, 45)),
                        "chainCode of " + o.path());
                assertHex(
                        pub, Vec.hex(Arrays.copyOfRange(xpb, 45, 78)), "publicKey of " + o.path());
                assertHex(
                        node.chainCode(),
                        Vec.hex(Arrays.copyOfRange(xpb, 13, 45)),
                        "xpub chainCode of " + o.path());
                if (o.path().equals("m")) {
                    nodes.add(
                            Vec.object(
                                    "path", o.path(),
                                    "privateKey", Vec.hex(node.privateKey()),
                                    "chainCode", Vec.hex(node.chainCode()),
                                    "publicKey", Vec.hex(pub),
                                    "xpub", o.xpub(),
                                    "xprv", o.xprv()));
                } else {
                    nodes.add(
                            Vec.object(
                                    "path", o.path(),
                                    "wire", Vec.hex(Hd.wire(o.path())),
                                    "privateKey", Vec.hex(node.privateKey()),
                                    "chainCode", Vec.hex(node.chainCode()),
                                    "publicKey", Vec.hex(pub),
                                    "xpub", o.xpub(),
                                    "xprv", o.xprv()));
                }
            }
            out.add(
                    Vec.object(
                            "name",
                            "vector-" + (v + 1),
                            "seed",
                            BIP32_SEEDS[v][0],
                            "nodes",
                            nodes));
        }
        return out;
    }

    private static List<Object> bip32Invalid() {
        return Arrays.stream(BIP32_INVALID)
                .<Object>map(e -> Vec.object("key", e[0], "reason", e[1]))
                .toList();
    }

    private static List<Object> slip10() {
        List<Object> out = new ArrayList<>();
        for (int v = 0; v < SLIP10_NODES.length; v++) {
            List<Object> nodes = new ArrayList<>();
            Hd.Node node = Hd.slip10Master(Vec.unhex(SLIP10_SEEDS[v]));
            int depth = 0;
            for (Slip s : SLIP10_NODES[v]) {
                long[] idx = Hd.indices(s.path());
                while (depth < idx.length) {
                    node = Hd.slip10Child(node, idx[depth++]);
                }
                assertHex(node.privateKey(), s.privateKey(), "privateKey of " + s.path());
                assertHex(node.chainCode(), s.chainCode(), "chainCode of " + s.path());
                byte[] official = Vec.unhex(s.publicKey());
                if (official[0] != 0 || official.length != 33) {
                    throw new IllegalStateException("SLIP-10 public key form: " + s.path());
                }
                byte[] wei = weiPoint(node.privateKey());
                byte[] enc = Wei25519.encode(wei);
                assertHex(
                        enc,
                        Vec.hex(Arrays.copyOfRange(official, 1, 33)),
                        "publicKey of " + s.path());
                assertEqual(
                        edPublicKey(node.privateKey()), enc, "BouncyCastle Ed25519 of " + s.path());
                if (s.path().equals("m")) {
                    nodes.add(
                            Vec.object(
                                    "path", s.path(),
                                    "privateKey", s.privateKey(),
                                    "chainCode", s.chainCode(),
                                    "publicKey", Vec.hex(enc),
                                    "wei", Vec.hex(wei)));
                } else {
                    nodes.add(
                            Vec.object(
                                    "path", s.path(),
                                    "wire", Vec.hex(Hd.wire(s.path())),
                                    "privateKey", s.privateKey(),
                                    "chainCode", s.chainCode(),
                                    "publicKey", Vec.hex(enc),
                                    "wei", Vec.hex(wei)));
                }
            }
            out.add(
                    Vec.object(
                            "name", "vector-" + (v + 1), "seed", SLIP10_SEEDS[v], "nodes", nodes));
        }
        return out;
    }

    private static List<Object> invalidChild() {
        byte[] parent = Vec.scalar(Cards.scalar("invalidChild/parent"));
        BigInteger p = new BigInteger(1, parent);
        List<Object> out = new ArrayList<>();
        out.add(childCase("il-equals-n", parent, Vec.scalar(Crypto.N), null));
        byte[] max = new byte[32];
        Arrays.fill(max, (byte) 0xff);
        out.add(childCase("il-max", parent, max, null));
        out.add(childCase("sum-zero", parent, Vec.scalar(Crypto.N.subtract(p)), null));
        out.add(
                childCase(
                        "il-n-minus-1",
                        parent,
                        Vec.scalar(Crypto.N.subtract(BigInteger.ONE)),
                        Vec.scalar(p.subtract(BigInteger.ONE))));
        byte[] nMinus1 = Vec.scalar(Crypto.N.subtract(BigInteger.ONE));
        out.add(childCase("sum-wraps", nMinus1, Vec.scalar(5), Vec.scalar(4)));
        out.add(childCase("il-zero", parent, new byte[32], parent));
        return out;
    }

    private static Object childCase(String name, byte[] parentKey, byte[] il, byte[] expected) {
        byte[] child = Hd.childStep(parentKey, il);
        if ((child != null) != (expected != null)
                || (expected != null && !Arrays.equals(child, expected))) {
            throw new IllegalStateException("invalidChild case disagrees: " + name);
        }
        if (expected == null) {
            return Vec.object(
                    "name",
                    name,
                    "parentKey",
                    Vec.hex(parentKey),
                    "il",
                    Vec.hex(il),
                    "valid",
                    false);
        }
        return Vec.object(
                "name", name,
                "parentKey", Vec.hex(parentKey),
                "il", Vec.hex(il),
                "valid", true,
                "childKey", Vec.hex(child));
    }

    private static List<Object> invalidMaster() {
        List<Object> out = new ArrayList<>();
        out.add(masterCase("zero", new byte[32], false));
        out.add(masterCase("n", Vec.scalar(Crypto.N), false));
        out.add(masterCase("n-minus-1", Vec.scalar(Crypto.N.subtract(BigInteger.ONE)), true));
        out.add(masterCase("one", Vec.scalar(1), true));
        return out;
    }

    /** The §10.2 master rule {@code 1 ≤ kM ≤ n − 1}, asserted against the stated outcome. */
    private static Object masterCase(String name, byte[] il, boolean valid) {
        BigInteger k = new BigInteger(1, il);
        if ((k.signum() > 0 && k.compareTo(Crypto.N) < 0) != valid) {
            throw new IllegalStateException("invalidMaster case disagrees: " + name);
        }
        return Vec.object("name", name, "il", Vec.hex(il), "valid", valid);
    }

    private static Object templates() {
        Hd.Node master = Hd.bip32Master(TEMPLATE_SEED); // throws on an invalid master
        byte[] masterPublic =
                Crypto.compress(Crypto.publicKey(new BigInteger(1, master.privateKey())));
        List<Object> secp256k1 = new ArrayList<>();
        for (String[] e :
                new String[][] {
                    {"evm", "m/44'/60'/0'/0/0"},
                    {"tron", "m/44'/195'/0'/0/0"},
                    {"btc-bip84-account", "m/84'/0'/0'"},
                    {"btc-bip84", "m/84'/0'/0'/0/0"},
                    {"btc-bip86", "m/86'/0'/0'/0/0"},
                    {"nostr", "m/44'/1237'/0'/0/0"},
                    {"btc-bip48", "m/48'/0'/0'/2'/0/0"},
                    {"depth-10", "m/0/1'/2/3'/4/5'/6/7'/8/9'"},
                }) {
            secp256k1.add(secpEntry(e[0], e[1], Hd.bip32Derive(TEMPLATE_SEED, e[1])));
        }
        List<Object> ed25519 = new ArrayList<>();
        for (String[] e :
                new String[][] {
                    {"solana", "m/44'/501'/0'/0'"},
                    {"solana-1", "m/44'/501'/1'/0'"},
                    {"depth-10", "m/0'/1'/2'/3'/4'/5'/6'/7'/8'/9'"},
                }) {
            ed25519.add(edEntry(e[0], e[1], Hd.slip10Derive(TEMPLATE_SEED, e[1])));
        }
        return Vec.object(
                "seed",
                Vec.hex(TEMPLATE_SEED),
                "masterPublicKey",
                Vec.hex(masterPublic),
                "secp256k1",
                secp256k1,
                "ed25519",
                ed25519);
    }

    private static Object secpEntry(String name, String path, Hd.Node node) {
        byte[] pub = Crypto.compress(Crypto.publicKey(new BigInteger(1, node.privateKey())));
        return Vec.object(
                "name", name,
                "path", path,
                "wire", Vec.hex(Hd.wire(path)),
                "privateKey", Vec.hex(node.privateKey()),
                "chainCode", Vec.hex(node.chainCode()),
                "publicKey", Vec.hex(pub));
    }

    private static Object edEntry(String name, String path, Hd.Node node) {
        byte[] wei = weiPoint(node.privateKey());
        byte[] enc = Wei25519.encode(wei);
        assertEqual(edPublicKey(node.privateKey()), enc, "BouncyCastle Ed25519 of " + path);
        return Vec.object(
                "name", name,
                "path", path,
                "wire", Vec.hex(Hd.wire(path)),
                "privateKey", Vec.hex(node.privateKey()),
                "chainCode", Vec.hex(node.chainCode()),
                "publicKey", Vec.hex(enc),
                "wei", Vec.hex(wei));
    }

    private static Object wei25519() {
        byte[] base = Wei25519.wei(Wei25519.G);
        byte[] baseEnc = Wei25519.encode(base);
        assertHex(
                baseEnc,
                "5866666666666666666666666666666666666666666666666666666666666666",
                "base point encoding");
        List<Object> points = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            byte[] sk = Vec.det("wei25519/point/" + i);
            BigInteger scalar = Wei25519.scalar(sk);
            byte[] wei = Wei25519.wei(Wei25519.G.multiply(scalar));
            byte[] enc = Wei25519.encode(wei);
            assertEqual(edPublicKey(sk), enc, "BouncyCastle Ed25519 of point-" + i);
            points.add(
                    Vec.object(
                            "name", "point-" + i,
                            "sk", Vec.hex(sk),
                            "scalar", Vec.hex(Vec.scalar(scalar)),
                            "wei", Vec.hex(wei),
                            "encoding", Vec.hex(enc)));
        }
        return Vec.object(
                "q", Vec.hex(Vec.scalar(Wei25519.Q)),
                "aW", Vec.hex(Vec.scalar(Wei25519.A_W)),
                "bW", Vec.hex(Vec.scalar(Wei25519.B_W)),
                "gW", Vec.hex(base),
                "order", Vec.hex(Vec.scalar(Wei25519.ORDER)),
                "a3", Vec.hex(Vec.scalar(Wei25519.A3)),
                "c", Vec.hex(Vec.scalar(Wei25519.C)),
                "base", Vec.object("wei", Vec.hex(base), "encoding", Vec.hex(baseEnc)),
                "points", points);
    }

    /** {@code W((a mod ℓ)·G_W)} for the RFC 8032 private key {@code sk} (§10.4). */
    private static byte[] weiPoint(byte[] sk) {
        return Wei25519.wei(Wei25519.G.multiply(Wei25519.scalar(sk)));
    }

    /** BouncyCastle's own RFC 8032 public key of {@code sk} — the independent oracle. */
    private static byte[] edPublicKey(byte[] sk) {
        byte[] out = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(sk, 0, out, 0);
        return out;
    }

    /**
     * The §10.4 worked example: RFC 8032 §7.1 TEST 1 secret key {@code 9d61b19d…7f60} maps to
     * {@code W(A) = 5961a13b…96b48329 ‖ 53373f33…2aca8de5} and the TEST 1 public key {@code
     * d75a9801…f707511a}.
     */
    private static void rfc8032WorkedExample() {
        byte[] sk = Vec.unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        String wei = Vec.hex(weiPoint(sk));
        String x = wei.substring(0, 64);
        String y = wei.substring(64);
        if (!x.startsWith("5961a13b")
                || !x.endsWith("96b48329")
                || !y.startsWith("53373f33")
                || !y.endsWith("2aca8de5")) {
            throw new IllegalStateException("RFC 8032 worked example W(A) mismatch: " + wei);
        }
        byte[] enc = Wei25519.encode(Vec.unhex(wei));
        assertHex(
                enc,
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "RFC 8032 TEST 1 public key");
        assertEqual(edPublicKey(sk), enc, "BouncyCastle Ed25519 of TEST 1");
    }

    private static void assertHex(byte[] actual, String expected, String what) {
        if (!Vec.hex(actual).equals(expected)) {
            throw new IllegalStateException(what + ": " + Vec.hex(actual) + " != " + expected);
        }
    }

    private static void assertEqual(byte[] a, byte[] b, String what) {
        if (!Arrays.equals(a, b)) {
            throw new IllegalStateException(what + ": " + Vec.hex(a) + " != " + Vec.hex(b));
        }
    }
}
