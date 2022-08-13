'use strict';
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createPailKeyPair = exports.PailPrivKey = exports.PailPubKey = exports.fastPailHandler_AddPlain = exports.fastPailHandler_Mul = exports.fastPailHandler_Decrypt = exports.fastPailHandler_EncryptWithR = void 0;
const BN = require("bn.js");
const crypto_rand_1 = require("@safeheron/crypto-rand");
exports.fastPailHandler_EncryptWithR = null;
exports.fastPailHandler_Decrypt = null;
exports.fastPailHandler_Mul = null;
exports.fastPailHandler_AddPlain = null;
/**
 * L_p(x) = (x-1)/p
 * @param prime
 * @param x
 * @returns {*}
 */
function l_function(prime, x) {
    return x.subn(1).div(prime);
}
/**
 * Calculate CRT
 *
 * @param mp
 * @param mq
 * @param p
 * @param q
 * @param qInvP = q^(-1) mod p
 * @param pInvQ = p^(-1) mod q
 * @param pq = p * q
 * @returns {Long.Long}
 * @constructor
 */
function CRT(mp, mq, p, q, qInvP, pInvQ, pq) {
    // a1 = mp, m1 = p, M1 = q, t1 = M1^(-1) mod p = qInvP
    // a2 = mq, m2 = q, M2 = p, t2 = M2^(-1) mod q = pInvQ
    // x1 = a * t1 * M1
    const x1 = mp.mul(qInvP).mul(q);
    // x2 = a * t2 * M2
    const x2 = mq.mul(pInvQ).mul(p);
    return x1.add(x2).mod(pq);
}
class PailPubKey {
    /**
     * Constructor of PailPubKey
     * @param n = pq
     * @param g = n + 1
     * @constructor
     */
    constructor(n, g) {
        this.n = n;
        this.g = g;
        this.nSqr = n.sqr();
    }
    /**
     * Encrypt:
     *     c = g^m * r^n mod n^2
     *
     * @param {BN} m: number to be encrypted
     * @param {BN} r : random number
     */
    encryptWithR(m, r) {
        // Fast pail: native implement
        if (exports.fastPailHandler_EncryptWithR) {
            let str_n = this.n.toString(16);
            let str_g = this.g.toString(16);
            let str_m = m.toString(16);
            let str_r = r.toString(16);
            let str_c = (0, exports.fastPailHandler_EncryptWithR)(str_n, str_g, str_m, str_r);
            return new BN(str_c, 16);
        }
        const ctx = BN.red(this.nSqr);
        let rRed = r.toRed(ctx);
        // let g_m = gRed.redPow(m)
        // optimize: g_m = 1 + m * n
        let g_m = this.n.toRed(ctx).redMul(m.toRed(ctx)).addn(1);
        let r_n = rRed.redPow(this.n);
        return g_m.redMul(r_n).fromRed();
    }
    /**
     * Not suggested
     * Encrypt:
     *     c = g^m * r^n mod n^2
     * Optimise:
     *     c = (1 + m*n) * r^n mod n^2
     *
     * @param {BN} m: number to be encrypted
     */
    encrypt(m) {
        return __awaiter(this, void 0, void 0, function* () {
            const r = yield crypto_rand_1.Rand.randomBNLtGCD(this.n);
            return this.encryptWithR(m, r);
        });
    }
    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * E(b) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} eB: encrypted num b
     */
    homomorphicAdd(eA, eB) {
        const ctx = BN.red(this.nSqr);
        return eA.toRed(ctx).redMul(eB.toRed(ctx)).fromRed();
    }
    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * g^b mod n^2
     *            = E(a) * (1 + b*n) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} b: plain num b
     */
    homomorphicAddPlain(eA, b) {
        if (exports.fastPailHandler_AddPlain) {
            let str_n = this.n.toString(16);
            let str_g = this.g.toString(16);
            let str_eA = eA.toString(16);
            let str_b = b.toString(16);
            let str_c = (0, exports.fastPailHandler_AddPlain)(str_n, str_g, str_eA, str_b);
            return new BN(str_c, 16);
        }
        const ctx = BN.red(this.nSqr);
        //let gRed = this.g.toRed(ctx)
        //let g_b = gRed.redPow(b)
        let g_b = this.n.toRed(ctx).redMul(b.toRed(ctx)).addn(1);
        return eA.toRed(ctx).redMul(g_b).fromRed();
    }
    /**
     * Homomorphic multiple:
     *     E(ka) = E(a) ^ k mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} k: plain num to multiple
     */
    homomorphicMulPlain(eA, k) {
        if (exports.fastPailHandler_Mul) {
            let str_n = this.n.toString(16);
            let str_g = this.g.toString(16);
            let str_eA = eA.toString(16);
            let str_k = k.toString(16);
            let str_c = (0, exports.fastPailHandler_Mul)(str_n, str_g, str_eA, str_k);
            return new BN(str_c, 16);
        }
        const ctx = BN.red(this.nSqr);
        return eA.toRed(ctx).redPow(k).fromRed();
    }
}
exports.PailPubKey = PailPubKey;
class PailPrivKey {
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
    constructor(lambda, mu, n, p, q, pSqr, qSqr, pMinus1, qMinus1, hp, hq, qInvP, pInvQ) {
        this.lambda = lambda;
        this.mu = mu;
        this.n = n;
        this.nSqr = n.sqr();
        this.p = p;
        this.q = q;
        this.pSqr = pSqr;
        this.qSqr = qSqr;
        this.pMinus1 = pMinus1;
        this.qMinus1 = qMinus1;
        this.hp = hp;
        this.hq = hq;
        this.qInvP = qInvP;
        this.pInvQ = pInvQ;
    }
    /**
     * Decrypt:
     *     c = L(c^lambda mod n^2) * mu mod n
     *
     * @param {BN} c: encrypted number
     */
    decrypt(c) {
        if (exports.fastPailHandler_Decrypt) {
            let str_lambda = this.lambda.toString(16);
            let str_mu = this.mu.toString(16);
            let str_n = this.n.toString(16);
            let str_p = this.p.toString(16);
            let str_q = this.q.toString(16);
            let str_pSqr = this.pSqr.toString(16);
            let str_qSqr = this.qSqr.toString(16);
            let str_pMinus1 = this.pMinus1.toString(16);
            let str_qMinus1 = this.qMinus1.toString(16);
            let str_hp = this.hp.toString(16);
            let str_hq = this.hq.toString(16);
            let str_qInvP = this.qInvP.toString(16);
            let str_pInvQ = this.pInvQ.toString(16);
            let str_c = c.toString(16);
            let str_m = (0, exports.fastPailHandler_Decrypt)(str_lambda, str_mu, str_n, str_p, str_q, str_pSqr, str_qSqr, str_pMinus1, str_qMinus1, str_hp, str_hq, str_qInvP, str_pInvQ, str_c);
            return new BN(str_m, 16);
        }
        // reduce context p^2
        const ctxPSqr = BN.red(this.pSqr);
        // reduce context q^2
        const ctxQSqr = BN.red(this.qSqr);
        const cRedPSqr = c.toRed(ctxPSqr);
        const cRedQSqr = c.toRed(ctxQSqr);
        // xp = c^(p-1) mod p^2
        const cPMinus1 = cRedPSqr.redPow(this.pMinus1).fromRed();
        // xq = c^(q-1) mod q^2
        const cQMinus1 = cRedQSqr.redPow(this.qMinus1).fromRed();
        // mp = lp(xp)^(-1) mod p
        const mp = cPMinus1.div(this.p).mul(this.hp).mod(this.p);
        // mq = lp(xq)^(-1) mod q
        const mq = cQMinus1.div(this.q).mul(this.hq).mod(this.q);
        return CRT(mp, mq, this.p, this.q, this.qInvP, this.pInvQ, this.n);
    }
}
exports.PailPrivKey = PailPrivKey;
/**
 * Create a Paillier Key Pair
 *
 * @param keyByteLength
 * @returns {Promise<(PailPrivKey|PailPubKey)[]>}
 */
function createPailKeyPair(keyByteLength) {
    return __awaiter(this, void 0, void 0, function* () {
        let p = yield crypto_rand_1.Rand.randomPrimeStrict(keyByteLength / 2);
        let q = yield crypto_rand_1.Rand.randomPrimeStrict(keyByteLength / 2);
        // make p > q
        if (p < q) {
            // swap
            const tmp = p;
            p = q;
            q = tmp;
        }
        const n = p.mul(q);
        const g = n.addn(1);
        const pMinus1 = p.subn(1);
        const qMinus1 = q.subn(1);
        const lambda = pMinus1.mul(qMinus1);
        const mu = lambda.invm(n);
        // p^2
        const pSqr = p.mul(p);
        // q^2
        const qSqr = q.mul(q);
        // reduce context p^2
        const ctxPSqr = BN.red(pSqr);
        // reduce context q^2
        const ctxQSqr = BN.red(qSqr);
        const gRedPSqr = g.toRed(ctxPSqr);
        const gRedQSqr = g.toRed(ctxQSqr);
        // xp = g^(p-1) mod p^2
        const gPMinus1 = gRedPSqr.redPow(pMinus1).fromRed();
        // xq = g^(q-1) mod q^2
        const gQMinus1 = gRedQSqr.redPow(qMinus1).fromRed();
        // hp = lp(xp)^(-1) mod p
        const hp = gPMinus1.div(p).invm(p);
        // hq = lp(xq)^(-1) mod q
        const hq = gQMinus1.div(q).invm(q);
        const pInvQ = p.invm(q);
        const qInvP = q.invm(p);
        return [new PailPrivKey(lambda, mu, n, p, q, pSqr, qSqr, pMinus1, qMinus1, hp, hq, qInvP, pInvQ), new PailPubKey(n, g)];
    });
}
exports.createPailKeyPair = createPailKeyPair;
//# sourceMappingURL=paillier.js.map