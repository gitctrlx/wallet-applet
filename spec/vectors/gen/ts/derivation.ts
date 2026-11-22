// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// derivation.json: master keys and child derivations of spec/protocol.md §10.2–10.4.
// The official BIP-32 test vectors 1–5 and SLIP-0010 ed25519 test vectors 1–2 are copied verbatim
// from the standards documents; every privateKey/chainCode/publicKey the generator derives is
// asserted against the value decoded from the official xprv/xpub (Base58Check; chain code = bytes
// 13..45, key = bytes 45..78) or printed in SLIP-0010. Wei25519 points additionally cross the
// RFC 8032 public keys computed by noble's ed25519 and the §10.4 worked example.
// Mirrors gen/java/.../{DerivationDoc,Hd,Wei25519,Base58}.java.
import { ed25519 } from '@noble/curves/ed25519.js';
import { weierstrass } from '@noble/curves/abstract/weierstrass.js';
import { Field } from '@noble/curves/abstract/modular.js';
import {
  bytesToNumberBE,
  bytesToNumberLE,
  numberToBytesBE,
  numberToBytesLE,
} from '@noble/curves/utils.js';
import {
  N,
  bytesToHex,
  compress,
  concatBytes,
  det,
  detLen,
  detScalar,
  hexToBytes,
  hmacSha512,
  publicKey,
  scalarBytes,
  sha256,
  sha512,
  utf8ToBytes,
} from './lib.ts';

export const TEMPLATE_SEED = detLen('derivation/template', 64);

const HARDENED = 0x80000000n;
const u32 = (v: bigint): Uint8Array => numberToBytesBE(v, 4);

type Node = { privateKey: Uint8Array; chainCode: Uint8Array };

const bip32Master = (seed: Uint8Array): Node => {
  const i = hmacSha512(utf8ToBytes('Bitcoin seed'), seed);
  const k = bytesToNumberBE(i.subarray(0, 32));
  if (k <= 0n || k >= N) throw new Error('invalid BIP-32 master key');
  return { privateKey: i.subarray(0, 32), chainCode: i.subarray(32, 64) };
};

/** k = (int(IL) + k_par) mod n; null when int(IL) ≥ n or the sum is zero (§10.3). */
const childStep = (parentKey: Uint8Array, il: Uint8Array): Uint8Array | null => {
  const left = bytesToNumberBE(il);
  if (left >= N) return null;
  const k = (left + bytesToNumberBE(parentKey)) % N;
  return k === 0n ? null : scalarBytes(k);
};

const bip32Child = (parent: Node, index: bigint): Node | null => {
  const prefix =
    index >= HARDENED
      ? concatBytes(new Uint8Array(1), parent.privateKey)
      : compress(publicKey(bytesToNumberBE(parent.privateKey)));
  const i = hmacSha512(parent.chainCode, prefix, u32(index));
  const k = childStep(parent.privateKey, i.subarray(0, 32));
  return k === null ? null : { privateKey: k, chainCode: i.subarray(32, 64) };
};

const slip10Master = (seed: Uint8Array): Node => {
  const i = hmacSha512(utf8ToBytes('ed25519 seed'), seed);
  return { privateKey: i.subarray(0, 32), chainCode: i.subarray(32, 64) };
};

const slip10Child = (parent: Node, index: bigint): Node => {
  if (index < HARDENED || index > 0xffffffffn) {
    throw new Error(`ed25519 paths are hardened: ${index}`);
  }
  const i = hmacSha512(
    parent.chainCode,
    concatBytes(new Uint8Array(1), parent.privateKey),
    u32(index),
  );
  return { privateKey: i.subarray(0, 32), chainCode: i.subarray(32, 64) };
};

/** The "m/…" string form to the wire indices: '44'' is 44 + 2³¹. */
const indices = (path: string): bigint[] => {
  if (path === 'm') return [];
  if (!path.startsWith('m/')) throw new Error(`path must start with m/: ${path}`);
  const parts = path.slice(2).split('/');
  if (parts.length < 1 || parts.length > 10) {
    throw new Error(`path depth must be in [1, 10]: ${path}`);
  }
  return parts.map((p) => {
    let index = 0n;
    if (p.endsWith("'")) {
      index = HARDENED;
      p = p.slice(0, -1);
    }
    if (p === '' || !/^[0-9]+$/.test(p)) throw new Error(`bad path index: ${path}`);
    const v = BigInt(p);
    if (v >= HARDENED) throw new Error(`path index too large: ${path}`);
    return index + v;
  });
};

/** The §9.2 wire form of a non-master path: depth(1) ‖ u32(index)…. */
const wire = (path: string): Uint8Array => {
  const idx = indices(path);
  if (idx.length === 0) throw new Error('the master path has no wire form');
  return concatBytes(new Uint8Array([idx.length]), ...idx.map(u32));
};

// Wei25519 (§10.4): Y² = X³ + a_W·X + b_W over q = 2²⁵⁵ − 19, constants printed in protocol.md.
const Q = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;
const A_W = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144n;
const B_W = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864n;
const ORDER = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const A3 = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451n;
const C = 0x70d9120b9f5ff9442d84f723fc03b0813a5e2c2eb482e57d3391fb5500ba81e7n;
const GX = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245an;
const GY = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9n;
const Fq = Field(Q);
const WeiPoint = weierstrass({ p: Q, Fp: Fq, n: ORDER, h: 1n, a: A_W, b: B_W, Gx: GX, Gy: GY });
// (ℓ−1)·G + G = O is the ℓ·G = O check: noble rejects scalars ≥ n in multiply.
if (!WeiPoint.BASE.multiply(ORDER - 1n).add(WeiPoint.BASE).equals(WeiPoint.ZERO)) {
  throw new Error('G_W is not an order-ℓ Wei25519 point');
}

/** a mod ℓ for the RFC 8032 private key sk: a = clamp(SHA-512(sk)[0..32)) read little-endian. */
const weiScalar = (sk: Uint8Array): bigint => {
  const a = sha512(sk).subarray(0, 32);
  a[0] &= 0xf8;
  a[31] &= 0x7f;
  a[31] |= 0x40;
  return bytesToNumberLE(a) % ORDER;
};

/** W(P) = X(32) ‖ Y(32), affine Wei25519 coordinates big-endian (§10.4). */
const weiPoint = (scalar: bigint): Uint8Array => {
  const p = WeiPoint.BASE.multiply(scalar).toAffine();
  return concatBytes(numberToBytesBE(p.x, 32), numberToBytesBE(p.y, 32));
};

/**
 * The §10.4 host map: u = X − A₃, y = (u−1)/(u+1), x = c·u/Y, le32(y) with bit 255 = x mod 2.
 * Rejects a point not on Wei25519.
 */
const weiEncode = (wei64: Uint8Array): Uint8Array => {
  if (wei64.length !== 64) throw new Error('W(P) must be 64 bytes');
  const x = bytesToNumberBE(wei64.subarray(0, 32));
  const y = bytesToNumberBE(wei64.subarray(32, 64));
  if (x >= Q || y >= Q || !Fq.eql(Fq.sqr(y), Fq.add(Fq.add(Fq.pow(x, 3n), Fq.mul(A_W, x)), B_W))) {
    throw new Error('not a Wei25519 point');
  }
  const u = Fq.sub(x, A3);
  const ey = Fq.mul(Fq.sub(u, 1n), Fq.inv(Fq.add(u, 1n)));
  const ex = Fq.mul(Fq.mul(C, u), Fq.inv(y));
  const out = numberToBytesLE(ey, 32);
  if (ex & 1n) out[31] |= 0x80;
  return out;
};

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Base58Check decode: the 78-byte payload, verified against the 4-byte double-SHA-256 checksum. */
const decodeCheck = (s: string): Uint8Array => {
  let v = 0n;
  for (const ch of s) {
    const d = BASE58.indexOf(ch);
    if (d < 0) throw new Error(`not base58: ${ch}`);
    v = v * 58n + BigInt(d);
  }
  const body: number[] = [];
  while (v > 0n) {
    body.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const raw = concatBytes(new Uint8Array(zeros), new Uint8Array(body));
  if (raw.length !== 82) throw new Error('extended key must decode to 82 bytes');
  const sum = sha256(sha256(raw.subarray(0, 78)));
  if (bytesToHex(raw.subarray(78, 82)) !== bytesToHex(sum.subarray(0, 4))) {
    throw new Error('Base58Check checksum mismatch');
  }
  return raw.subarray(0, 78);
};

const assertHex = (actual: Uint8Array, expected: string, what: string) => {
  if (bytesToHex(actual) !== expected) {
    throw new Error(`${what}: ${bytesToHex(actual)} != ${expected}`);
  }
};

// BIP-32 test vectors 1–4 (github.com/bitcoin/bips/bip-0032.mediawiki), verbatim.
const BIP32_SEEDS = [
  '000102030405060708090a0b0c0d0e0f',
  'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
  '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
  '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
];

const BIP32_NODES: [string, string, string][][] = [
  [
    ['m', 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8', 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
    ["m/0'", 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw', 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
    ["m/0'/1", 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ', 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
    ["m/0'/1/2'", 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5', 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
    ["m/0'/1/2'/2", 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV', 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'],
    ["m/0'/1/2'/2/1000000000", 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy', 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'],
  ],
  [
    ['m', 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB', 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'],
    ['m/0', 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH', 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'],
    ["m/0/2147483647'", 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a', 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'],
    ["m/0/2147483647'/1", 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon', 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'],
    ["m/0/2147483647'/1/2147483646'", 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL', 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'],
    ["m/0/2147483647'/1/2147483646'/2", 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt', 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'],
  ],
  [
    ['m', 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13', 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'],
    ["m/0'", 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y', 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'],
  ],
  [
    ['m', 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa', 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv'],
    ["m/0'", 'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m', 'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G'],
    ["m/0'/1'", 'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt', 'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1'],
  ],
];

// BIP-32 test vector 5, verbatim: extended keys a host MUST reject.
const BIP32_INVALID: [string, string][] = [
  ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm', 'pubkey version / prvkey mismatch'],
  ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH', 'prvkey version / pubkey mismatch'],
  ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn', 'invalid pubkey prefix 04'],
  ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ', 'invalid prvkey prefix 04'],
  ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4', 'invalid pubkey prefix 01'],
  ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J', 'invalid prvkey prefix 01'],
  ['xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv', 'zero depth with non-zero parent fingerprint'],
  ['xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ', 'zero depth with non-zero parent fingerprint'],
  ['xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN', 'zero depth with non-zero index'],
  ['xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8', 'zero depth with non-zero index'],
  ['DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4', 'unknown extended key version'],
  ['DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9', 'unknown extended key version'],
  ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx', 'private key 0 not in 1..n-1'],
  ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G', 'private key n not in 1..n-1'],
  ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY', 'invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007'],
  ['xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL', 'invalid checksum'],
];

// SLIP-0010 ed25519 test vectors 1 and 2 (github.com/satoshilabs/slips/slip-0010), verbatim.
const SLIP10_SEEDS = [BIP32_SEEDS[0], BIP32_SEEDS[1]];

const SLIP10_NODES: [string, string, string, string][][] = [
  [
    ['m', '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7', '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb', '00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'],
    ["m/0'", '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3', '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69', '008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'],
    ["m/0'/1'", 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2', 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14', '001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'],
    ["m/0'/1'/2'", '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9', '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c', '00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1'],
    ["m/0'/1'/2'/2'", '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662', '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc', '008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c'],
    ["m/0'/1'/2'/2'/1000000000'", '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793', '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230', '003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a'],
  ],
  [
    ['m', '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012', 'ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b', '008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a'],
    ["m/0'", '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635', '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d', '0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037'],
    ["m/0'/2147483647'", 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4', '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f', '005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d'],
    ["m/0'/2147483647'/1'", '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c', '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90', '002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45'],
    ["m/0'/2147483647'/1'/2147483646'", '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72', '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a', '00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b'],
    ["m/0'/2147483647'/1'/2147483646'/2'", '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d', '5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4', '0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0'],
  ],
];

const bip32Doc = (): object[] =>
  BIP32_NODES.map((nodes, v) => {
    let node = bip32Master(hexToBytes(BIP32_SEEDS[v]));
    let depth = 0;
    const out = nodes.map(([path, xpub, xprv]) => {
      const idx = indices(path);
      while (depth < idx.length) {
        const child = bip32Child(node, idx[depth++]);
        if (child === null) throw new Error(`invalid child on ${path}`);
        node = child;
      }
      const pub = compress(publicKey(bytesToNumberBE(node.privateKey)));
      const prv = decodeCheck(xprv);
      const xpb = decodeCheck(xpub);
      assertHex(prv.subarray(0, 4), '0488ade4', `xprv version of ${path}`);
      assertHex(xpb.subarray(0, 4), '0488b21e', `xpub version of ${path}`);
      if (prv[45] !== 0) throw new Error(`xprv key prefix: ${path}`);
      assertHex(node.privateKey, bytesToHex(prv.subarray(46, 78)), `privateKey of ${path}`);
      assertHex(node.chainCode, bytesToHex(prv.subarray(13, 45)), `chainCode of ${path}`);
      assertHex(pub, bytesToHex(xpb.subarray(45, 78)), `publicKey of ${path}`);
      assertHex(node.chainCode, bytesToHex(xpb.subarray(13, 45)), `xpub chainCode of ${path}`);
      return {
        path,
        ...(path === 'm' ? {} : { wire: bytesToHex(wire(path)) }),
        privateKey: bytesToHex(node.privateKey),
        chainCode: bytesToHex(node.chainCode),
        publicKey: bytesToHex(pub),
        xpub,
        xprv,
      };
    });
    return { name: `vector-${v + 1}`, seed: BIP32_SEEDS[v], nodes: out };
  });

const slip10Doc = (): object[] =>
  SLIP10_NODES.map((nodes, v) => {
    let node = slip10Master(hexToBytes(SLIP10_SEEDS[v]));
    let depth = 0;
    const out = nodes.map(([path, privateKey, chainCode, publicKey]) => {
      const idx = indices(path);
      while (depth < idx.length) {
        node = slip10Child(node, idx[depth++]);
      }
      assertHex(node.privateKey, privateKey, `privateKey of ${path}`);
      assertHex(node.chainCode, chainCode, `chainCode of ${path}`);
      const official = hexToBytes(publicKey);
      if (official.length !== 33 || official[0] !== 0) {
        throw new Error(`SLIP-10 public key form: ${path}`);
      }
      const wei = weiPoint(weiScalar(node.privateKey));
      const enc = weiEncode(wei);
      assertHex(enc, bytesToHex(official.subarray(1, 33)), `publicKey of ${path}`);
      const noble = ed25519.getPublicKey(node.privateKey);
      if (bytesToHex(noble) !== bytesToHex(enc)) {
        throw new Error(`noble Ed25519 of ${path}`);
      }
      return {
        path,
        ...(path === 'm' ? {} : { wire: bytesToHex(wire(path)) }),
        privateKey,
        chainCode,
        publicKey: bytesToHex(enc),
        wei: bytesToHex(wei),
      };
    });
    return { name: `vector-${v + 1}`, seed: SLIP10_SEEDS[v], nodes: out };
  });

const childCase = (
  name: string,
  parentKey: Uint8Array,
  il: Uint8Array,
  expected: Uint8Array | null,
): object => {
  const child = childStep(parentKey, il);
  if ((child !== null) !== (expected !== null) ||
      (expected !== null && bytesToHex(child!) !== bytesToHex(expected))) {
    throw new Error(`invalidChild case disagrees: ${name}`);
  }
  return {
    name,
    parentKey: bytesToHex(parentKey),
    il: bytesToHex(il),
    valid: expected !== null,
    ...(expected === null ? {} : { childKey: bytesToHex(child!) }),
  };
};

const invalidChildDoc = (): object[] => {
  const parent = scalarBytes(detScalar('invalidChild/parent'));
  const p = bytesToNumberBE(parent);
  const nMinus1 = scalarBytes(N - 1n);
  return [
    childCase('il-equals-n', parent, scalarBytes(N), null),
    childCase('il-max', parent, new Uint8Array(32).fill(0xff), null),
    childCase('sum-zero', parent, scalarBytes(N - p), null),
    childCase('il-n-minus-1', parent, nMinus1, scalarBytes(p - 1n)),
    childCase('sum-wraps', nMinus1, scalarBytes(5n), scalarBytes(4n)),
    childCase('il-zero', parent, new Uint8Array(32), parent),
  ];
};

const masterCase = (name: string, il: Uint8Array, valid: boolean): object => {
  const k = bytesToNumberBE(il);
  if ((k > 0n && k < N) !== valid) throw new Error(`invalidMaster case disagrees: ${name}`);
  return { name, il: bytesToHex(il), valid };
};

const bip32Derive = (seed: Uint8Array, path: string): Node => {
  let node = bip32Master(seed);
  for (const index of indices(path)) {
    const child = bip32Child(node, index);
    if (child === null) throw new Error(`invalid child on template path ${path}`);
    node = child;
  }
  return node;
};

const slipDerive = (seed: Uint8Array, path: string): Node => {
  let node = slip10Master(seed);
  for (const index of indices(path)) {
    node = slip10Child(node, index);
  }
  return node;
};

const secpEntry = (name: string, path: string, node: Node): object => ({
  name,
  path,
  wire: bytesToHex(wire(path)),
  privateKey: bytesToHex(node.privateKey),
  chainCode: bytesToHex(node.chainCode),
  publicKey: bytesToHex(compress(publicKey(bytesToNumberBE(node.privateKey)))),
});

const edEntry = (name: string, path: string, node: Node): object => {
  const wei = weiPoint(weiScalar(node.privateKey));
  const enc = weiEncode(wei);
  if (bytesToHex(ed25519.getPublicKey(node.privateKey)) !== bytesToHex(enc)) {
    throw new Error(`noble Ed25519 of ${path}`);
  }
  return {
    name,
    path,
    wire: bytesToHex(wire(path)),
    privateKey: bytesToHex(node.privateKey),
    chainCode: bytesToHex(node.chainCode),
    publicKey: bytesToHex(enc),
    wei: bytesToHex(wei),
  };
};

const templatesDoc = (): object => {
  const masterPublic = compress(
    publicKey(bytesToNumberBE(bip32Master(TEMPLATE_SEED).privateKey)),
  );
  const secp256k1Entries: [string, string][] = [
    ['evm', "m/44'/60'/0'/0/0"],
    ['tron', "m/44'/195'/0'/0/0"],
    ['btc-bip84-account', "m/84'/0'/0'"],
    ['btc-bip84', "m/84'/0'/0'/0/0"],
    ['btc-bip86', "m/86'/0'/0'/0/0"],
    ['nostr', "m/44'/1237'/0'/0/0"],
    ['btc-bip48', "m/48'/0'/0'/2'/0/0"],
    ['depth-10', "m/0/1'/2/3'/4/5'/6/7'/8/9'"],
  ];
  const ed25519Entries: [string, string][] = [
    ['solana', "m/44'/501'/0'/0'"],
    ['solana-1', "m/44'/501'/1'/0'"],
    ['depth-10', "m/0'/1'/2'/3'/4'/5'/6'/7'/8'/9'"],
  ];
  return {
    seed: bytesToHex(TEMPLATE_SEED),
    masterPublicKey: bytesToHex(masterPublic),
    secp256k1: secp256k1Entries.map(([name, path]) =>
      secpEntry(name, path, bip32Derive(TEMPLATE_SEED, path)),
    ),
    ed25519: ed25519Entries.map(([name, path]) =>
      edEntry(name, path, slipDerive(TEMPLATE_SEED, path)),
    ),
  };
};

const wei25519Doc = (): object => {
  const base = weiPoint(1n);
  const baseEnc = weiEncode(base);
  assertHex(
    baseEnc,
    '5866666666666666666666666666666666666666666666666666666666666666',
    'base point encoding',
  );
  const points = Array.from({ length: 8 }, (_, i) => {
    const sk = det(`wei25519/point/${i}`);
    const scalar = weiScalar(sk);
    const wei = weiPoint(scalar);
    const enc = weiEncode(wei);
    if (bytesToHex(ed25519.getPublicKey(sk)) !== bytesToHex(enc)) {
      throw new Error(`noble Ed25519 of point-${i}`);
    }
    return {
      name: `point-${i}`,
      sk: bytesToHex(sk),
      scalar: bytesToHex(scalarBytes(scalar)),
      wei: bytesToHex(wei),
      encoding: bytesToHex(enc),
    };
  });
  return {
    q: bytesToHex(scalarBytes(Q)),
    aW: bytesToHex(scalarBytes(A_W)),
    bW: bytesToHex(scalarBytes(B_W)),
    gW: bytesToHex(base),
    order: bytesToHex(scalarBytes(ORDER)),
    a3: bytesToHex(scalarBytes(A3)),
    c: bytesToHex(scalarBytes(C)),
    base: { wei: bytesToHex(base), encoding: bytesToHex(baseEnc) },
    points,
  };
};

/**
 * The §10.4 worked example: RFC 8032 §7.1 TEST 1 secret key 9d61b19d…7f60 maps to
 * W(A) = 5961a13b…96b48329 ‖ 53373f33…2aca8de5 and the TEST 1 public key d75a9801…f707511a.
 */
const rfc8032WorkedExample = () => {
  const sk = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const wei = bytesToHex(weiPoint(weiScalar(sk)));
  const [x, y] = [wei.slice(0, 64), wei.slice(64)];
  if (
    !x.startsWith('5961a13b') ||
    !x.endsWith('96b48329') ||
    !y.startsWith('53373f33') ||
    !y.endsWith('2aca8de5')
  ) {
    throw new Error(`RFC 8032 worked example W(A) mismatch: ${wei}`);
  }
  const enc = weiEncode(hexToBytes(wei));
  assertHex(
    enc,
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'RFC 8032 TEST 1 public key',
  );
  if (bytesToHex(ed25519.getPublicKey(sk)) !== bytesToHex(enc)) {
    throw new Error('noble Ed25519 of TEST 1');
  }
};

export function derivationDoc(): unknown {
  rfc8032WorkedExample();
  return {
    bip32: bip32Doc(),
    bip32Invalid: BIP32_INVALID.map(([key, reason]) => ({ key, reason })),
    slip10: slip10Doc(),
    invalidChild: invalidChildDoc(),
    invalidMaster: [
      masterCase('zero', new Uint8Array(32), false),
      masterCase('n', scalarBytes(N), false),
      masterCase('n-minus-1', scalarBytes(N - 1n), true),
      masterCase('one', scalarBytes(1n), true),
    ],
    templates: templatesDoc(),
    wei25519: wei25519Doc(),
  };
}
