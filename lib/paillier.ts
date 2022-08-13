'use strict'
import * as BN from "bn.js"
import {Rand} from '@safeheron/crypto-rand'

export let fastPailHandler_EncryptWithR = null
export let fastPailHandler_Decrypt = null
export let fastPailHandler_Mul = null
export let fastPailHandler_AddPlain = null

/**
 * L_p(x) = (x-1)/p
 * @param prime
 * @param x
 * @returns {*}
 */
function l_function(prime: BN, x: BN): BN{
    return x.subn(1).div(prime)
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
function CRT(mp: BN, mq: BN, p: BN, q: BN, qInvP: BN, pInvQ: BN, pq: BN): BN{
    // a1 = mp, m1 = p, M1 = q, t1 = M1^(-1) mod p = qInvP
    // a2 = mq, m2 = q, M2 = p, t2 = M2^(-1) mod q = pInvQ
    // x1 = a * t1 * M1
    const x1 = mp.mul(qInvP).mul(q)
    // x2 = a * t2 * M2
    const x2 = mq.mul(pInvQ).mul(p)
    return x1.add(x2).mod(pq)
}

export class PailPubKey{
    public readonly n: BN
    public readonly g: BN
    public readonly nSqr: BN

    /**
     * Constructor of PailPubKey
     * @param n = pq
     * @param g = n + 1
     * @constructor
     */
    public constructor(n: BN, g: BN) {
        this.n = n
        this.g = g
        this.nSqr = n.sqr()
    }

    /**
     * Encrypt:
     *     c = g^m * r^n mod n^2
     *
     * @param {BN} m: number to be encrypted
     * @param {BN} r : random number
     */
    public encryptWithR(m: BN, r: BN): BN{
        // Fast pail: native implement
        if(fastPailHandler_EncryptWithR){
            let str_n = this.n.toString(16)
            let str_g = this.g.toString(16)
            let str_m = m.toString(16)
            let str_r = r.toString(16)
            let str_c = fastPailHandler_EncryptWithR(str_n, str_g, str_m, str_r)
            return new BN(str_c, 16)
        }
        const ctx = BN.red(this.nSqr)
        let rRed = r.toRed(ctx)
        // let g_m = gRed.redPow(m)
        // optimize: g_m = 1 + m * n
        let g_m = this.n.toRed(ctx).redMul(m.toRed(ctx)).addn(1)
        let r_n = rRed.redPow(this.n)
        // @ts-ignore
        return g_m.redMul(r_n).fromRed()
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
    public async encrypt(m: BN): Promise<BN>{
        const r = await Rand.randomBNLtGCD(this.n)
        return this.encryptWithR(m, r)
    }

    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * E(b) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} eB: encrypted num b
     */
    public homomorphicAdd(eA: BN, eB: BN): BN{
        const ctx = BN.red(this.nSqr)
        return eA.toRed(ctx).redMul(eB.toRed(ctx)).fromRed()
    }

    /**
     * Homomorphic add:
     *     E(a+b) = E(a) * g^b mod n^2
     *            = E(a) * (1 + b*n) mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} b: plain num b
     */
    public homomorphicAddPlain(eA: BN, b: BN): BN{
        if(fastPailHandler_AddPlain){
            let str_n = this.n.toString(16)
            let str_g = this.g.toString(16)
            let str_eA = eA.toString(16)
            let str_b = b.toString(16)
            let str_c = fastPailHandler_AddPlain(str_n, str_g, str_eA, str_b)
            return new BN(str_c, 16)
        }
        const ctx = BN.red(this.nSqr)
        //let gRed = this.g.toRed(ctx)
        //let g_b = gRed.redPow(b)
        let g_b = this.n.toRed(ctx).redMul(b.toRed(ctx)).addn(1)
        return eA.toRed(ctx).redMul(g_b).fromRed()
    }

    /**
     * Homomorphic multiple:
     *     E(ka) = E(a) ^ k mod n^2
     * @param {BN} eA: encrypted num a
     * @param {BN} k: plain num to multiple
     */
    public homomorphicMulPlain(eA: BN, k: BN): BN{
        if(fastPailHandler_Mul){
            let str_n = this.n.toString(16)
            let str_g = this.g.toString(16)
            let str_eA = eA.toString(16)
            let str_k = k.toString(16)
            let str_c = fastPailHandler_Mul(str_n, str_g, str_eA, str_k)
            return new BN(str_c, 16)
        }
        const ctx = BN.red(this.nSqr)
        return eA.toRed(ctx).redPow(k).fromRed()
    }
}


export class PailPrivKey {
    public readonly lambda: BN
    public readonly mu: BN
    public readonly n: BN
    public readonly nSqr: BN
    public readonly p: BN
    public readonly q: BN
    public readonly pSqr: BN
    public readonly qSqr: BN
    public readonly pMinus1: BN
    public readonly qMinus1: BN
    public readonly hp: BN
    public readonly hq: BN
    public readonly qInvP: BN
    public readonly pInvQ: BN

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
    public constructor(lambda: BN, mu: BN, n: BN, p: BN, q: BN, pSqr: BN, qSqr: BN, pMinus1: BN, qMinus1: BN, hp: BN, hq: BN, qInvP: BN, pInvQ) {
        this.lambda = lambda
        this.mu = mu
        this.n = n
        this.nSqr = n.sqr()
        this.p = p
        this.q = q
        this.pSqr = pSqr
        this.qSqr = qSqr
        this.pMinus1 = pMinus1
        this.qMinus1 = qMinus1
        this.hp = hp
        this.hq = hq
        this.qInvP = qInvP
        this.pInvQ = pInvQ
    }

    /**
     * Decrypt:
     *     c = L(c^lambda mod n^2) * mu mod n
     *
     * @param {BN} c: encrypted number
     */
    public decrypt(c: BN): BN{
        if(fastPailHandler_Decrypt){
            let str_lambda  = this.lambda.toString(16)
            let str_mu     = this.mu.toString(16)
            let str_n      = this.n.toString(16)
            let str_p      = this.p.toString(16)
            let str_q      = this.q.toString(16)
            let str_pSqr   = this.pSqr.toString(16)
            let str_qSqr   = this.qSqr.toString(16)
            let str_pMinus1 = this.pMinus1.toString(16)
            let str_qMinus1 = this.qMinus1.toString(16)
            let str_hp     = this.hp.toString(16)
            let str_hq     = this.hq.toString(16)
            let str_qInvP  = this.qInvP.toString(16)
            let str_pInvQ  = this.pInvQ.toString(16)
            let str_c = c.toString(16)
            let str_m = fastPailHandler_Decrypt(
                str_lambda,
                str_mu,
                str_n,
                str_p,
                str_q,
                str_pSqr,
                str_qSqr,
                str_pMinus1,
                str_qMinus1,
                str_hp,
                str_hq,
                str_qInvP,
                str_pInvQ,
                str_c)
            return new BN(str_m, 16)
        }
        // reduce context p^2
        const ctxPSqr = BN.red(this.pSqr)
        // reduce context q^2
        const ctxQSqr = BN.red(this.qSqr)
        const cRedPSqr = c.toRed(ctxPSqr)
        const cRedQSqr = c.toRed(ctxQSqr)
        // xp = c^(p-1) mod p^2
        const cPMinus1 = cRedPSqr.redPow(this.pMinus1).fromRed()
        // xq = c^(q-1) mod q^2
        const cQMinus1 = cRedQSqr.redPow(this.qMinus1).fromRed()
        // mp = lp(xp)^(-1) mod p
        const mp = cPMinus1.div(this.p).mul(this.hp).mod(this.p)
        // mq = lp(xq)^(-1) mod q
        const mq = cQMinus1.div(this.q).mul(this.hq).mod(this.q)
        return CRT(mp, mq, this.p, this.q, this.qInvP, this.pInvQ, this.n)
    }
}

/**
 * Create a Paillier Key Pair
 *
 * @param keyByteLength
 * @returns {Promise<(PailPrivKey|PailPubKey)[]>}
 */
export async function createPailKeyPair(keyByteLength: number): Promise<[PailPrivKey, PailPubKey]> {
    let p = await Rand.randomPrimeStrict(keyByteLength/2)
    let q = await Rand.randomPrimeStrict(keyByteLength/2)
    // make p > q
    if(p < q){
        // swap
        const tmp = p
        p = q
        q = tmp
    }
    const n = p.mul(q)
    const g = n.addn(1)
    const pMinus1 = p.subn(1)
    const qMinus1 = q.subn(1)
    const lambda = pMinus1.mul(qMinus1)
    const mu = lambda.invm(n)

    // p^2
    const pSqr = p.mul(p)
    // q^2
    const qSqr = q.mul(q)
    // reduce context p^2
    const ctxPSqr = BN.red(pSqr)
    // reduce context q^2
    const ctxQSqr = BN.red(qSqr)
    const gRedPSqr = g.toRed(ctxPSqr)
    const gRedQSqr = g.toRed(ctxQSqr)
    // xp = g^(p-1) mod p^2
    const gPMinus1 = gRedPSqr.redPow(pMinus1).fromRed()
    // xq = g^(q-1) mod q^2
    const gQMinus1 = gRedQSqr.redPow(qMinus1).fromRed()
    // hp = lp(xp)^(-1) mod p
    const hp = gPMinus1.div(p).invm(p)
    // hq = lp(xq)^(-1) mod q
    const hq = gQMinus1.div(q).invm(q)
    const pInvQ = p.invm(q)
    const qInvP = q.invm(p)
    return [new PailPrivKey(lambda, mu, n, p, q, pSqr, qSqr, pMinus1, qMinus1, hp, hq, qInvP, pInvQ), new PailPubKey(n,g)]
}

