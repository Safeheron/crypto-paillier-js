'use strict'
import * as assert from "assert"
import * as BN from "bn.js"
import {Rand} from '@safeheron/crypto-rand'
import {PailPrivKey, PailPubKey, createPailKeyPair} from ".."

describe('Paillier cryptosystem - functionality test', async function () {
    console.time('KeyGen2048')
    const keyPair = await createPailKeyPair(2048/8)
    const priv = keyPair[0]
    const pub = keyPair[1]
    console.timeEnd('KeyGen2048')

    let m1 = await Rand.randomBNLt(pub.n)
    let m2 = await Rand.randomBNLt(pub.n)
    let r1 = await Rand.randomBNLtGCD(pub.n)
    let r2 = await Rand.randomBNLtGCD(pub.n)

    it('Functionality: 10 * Encrypt!', async function () {
        console.time('10Encrypt')
        for (let i = 0; i < 10; i ++ ){
            let c2 = await pub.encrypt(m1)
        }
        console.timeEnd('10Encrypt')

        this.timeout(20000)
    })

    it('Functionality: 10 * Decrypt!', async function () {
        let c = pub.encryptWithR(m1, r1)
        console.time('10Decrypt')
        for (let i = 0; i < 10; i++){
            let expected = priv.decrypt(c)
            assert(m1.eq(expected), "should equal")
        }
        console.timeEnd('10Decrypt')
    })

    it('Performance: Homomorphic add!', async function () {
        let c1 = pub.encryptWithR(m1, r1)
        let c2 = pub.encryptWithR(m2, r2)

        console.time('10homomorphicAdd')
        let eSum = null
        for(let i = 0; i < 10; i++) {
            eSum = pub.homomorphicAdd(c1, c2)
        }
        console.timeEnd('10homomorphicAdd')
        let sum = priv.decrypt(eSum)
        sum = sum.mod(pub.n)
        let expected = m1.add(m2).mod(pub.n)
        assert(sum.eq(expected), "should equal")
    })

    it('Performance: Homomorphic Add Plain!', async function () {
        let c = pub.encryptWithR(m1, r1)
        console.time('10homomorphicAddPalin')
        let eSum = null
        for(let i = 0; i < 10; i++) {
            eSum = pub.homomorphicAddPlain(c, r2)
        }
        console.timeEnd('10homomorphicAddPalin')
        let sum = priv.decrypt(eSum)
        let expected = m1.add(r2).mod(pub.n)
        assert(sum.eq(expected), "should equal")
    })

    it('Performance: Homomorphic Multiple!', async function () {
        let c = pub.encryptWithR(m1, r1)
        console.time('10homomorphicMultiple')
        let eMK = null
        for(let i = 0; i < 10; i++) {
            eMK = pub.homomorphicMulPlain(c, r2)
        }
        console.timeEnd('10homomorphicMultiple')
        let mk = priv.decrypt(eMK)
        assert(mk.eq(m1.mul(r2).mod(pub.n)), "should equal")

        this.timeout(20000)
    })
})
