import * as BN from "bn.js";
export declare let fastPailHandler_EncryptWithR: any;
export declare let fastPailHandler_Decrypt: any;
export declare let fastPailHandler_Mul: any;
export declare let fastPailHandler_AddPlain: any;
export declare class PailPubKey {
    readonly n: BN;
    readonly g: BN;
    readonly nSqr: BN;
    /**
     * Constructor of PailPubKey
     * @param n = pq
     * @param g = n + 1
     * @constructor
     */
    constructor(n: BN, g: BN);
    /**
     * Encrypt:
     *     c = g^m * r^n mod n^2
     *
     * @param {BN} m: number to be encrypted
     * @param {BN} r : random number
     */
    encryptWithR(m: BN, r: BN): BN;
    /**
     * Not suggested
     * Encrypt:
     *     c = g^m * r^n mod n^2
     * Optimise:
     *     c = (1 + m*n) * r^n mod n^2
     *
     * @param {BN} m: number to be encrypted
     */
    encrypt(m: BN): Promise<BN>;
    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * E(b) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} eB: encrypted num b
     */
    homomorphicAdd(eA: BN, eB: BN): BN;
    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * g^b mod n^2
     *            = E(a) * (1 + b*n) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} b: plain num b
     */
    homomorphicAddPlain(eA: BN, b: BN): BN;
    /**
     * Homomorphic multiple:
     *     E(ka) = E(a) ^ k mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} k: plain num to multiple
     */
    homomorphicMulPlain(eA: BN, k: BN): BN;
}
export declare class PailPrivKey {
    readonly lambda: BN;
    readonly mu: BN;
    readonly n: BN;
    readonly nSqr: BN;
    readonly p: BN;
    readonly q: BN;
    readonly pSqr: BN;
    readonly qSqr: BN;
    readonly pMinus1: BN;
    readonly qMinus1: BN;
    readonly hp: BN;
    readonly hq: BN;
    readonly qInvP: BN;
    readonly pInvQ: BN;
    /**
     * Construct of PailPrivKey
     * @param lambda = (p-1)(q-1)
     * @param mu = lambda^-1 mod n
     * @param n = pq
     * @param p
     * @param q
     * @param pSqr: p^2
     * @param qSqr: q^2
     * @param pMinus1: p-1
     * @param qMinus1: q-1
     * @param hp
     * @param hq
     * @param pInvQ: p.invm(q)
     * @param qInvP: q.invm(p)
     * @constructor
     */
    constructor(lambda: BN, mu: BN, n: BN, p: BN, q: BN, pSqr: BN, qSqr: BN, pMinus1: BN, qMinus1: BN, hp: BN, hq: BN, qInvP: BN, pInvQ: any);
    /**
     * Decrypt:
     *     c = L(c^lambda mod n^2) * mu mod n
     *
     * @param {BN} c: encrypted number
     */
    decrypt(c: BN): BN;
}
/**
 * Create a Paillier Key Pair
 *
 * @param keyByteLength
 * @returns {Promise<(PailPrivKey|PailPubKey)[]>}
 */
export declare function createPailKeyPair(keyByteLength: number): Promise<[PailPrivKey, PailPubKey]>;
