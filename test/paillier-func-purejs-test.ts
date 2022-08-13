'use strict'
import * as assert from "assert"
import * as BN from "bn.js"
import {Rand} from '@safeheron/crypto-rand'
import {PailPrivKey, PailPubKey, createPailKeyPair} from ".."

const paillier = require('../lib/paillier')

describe('Paillier cryptosystem - functionality test', async function () {
    const keyPair = await paillier.createPailKeyPair(2048/8)
    const priv = keyPair[0]
    const pub = keyPair[1]

    it('Functionality: Decrypt and encrypt!', async function () {
        console.time('1KenGen+3Rand+2Encrypt+2Decrypt')
        let m = await Rand.randomBNLt(pub.n)
        let r = await Rand.randomBNLtGCD(pub.n)
        let c1 = pub.encryptWithR(m, r)
        let c2 = await pub.encrypt(m)
        let m1 = priv.decrypt(c1)
        let m2 = priv.decrypt(c2)
        //console.log("m:", m.toString(16))
        //console.log("pub.n:", pub.n.toString(16))
        //console.log("m1:", m1.toString(16))
        //console.log("m2:", m2.toString(16))
        assert(m.eq(m1) && m.eq(m2), "should equal")
        console.timeEnd('1KenGen+3Rand+2Encrypt+2Decrypt')
    })

    it('Functionality: Decrypt and encrypt!', async function () {
        let m = await Rand.randomBNLt(pub.n)
        let r = await Rand.randomBNLtGCD(pub.n)

        console.time('1Encrypt+1Decrypt')
        let c = pub.encryptWithR(m, r)
        let expected = priv.decrypt(c)
        console.timeEnd('1Encrypt+1Decrypt')
        assert(m.eq(expected), "should equal")
    })

    it('Functionality: Homomorphic add!', async function () {
        let m1 = await Rand.randomBNLt(pub.n)
        let m2 = await Rand.randomBNLt(pub.n)
        let r1 = await Rand.randomBNLtGCD(pub.n)
        let r2 = await Rand.randomBNLtGCD(pub.n)
        let c1 = pub.encryptWithR(m1, r1)
        let c2 = pub.encryptWithR(m2, r2)
        let eSum = pub.homomorphicAdd(c1, c2)
        let sum = priv.decrypt(eSum)
        sum = sum.mod(pub.n)
        //console.log("pub.n:", pub.n.toString(16))
        //console.log("m1:", m1.toString(16))
        //console.log("m2:", m2.toString(16))
        //console.log("sum:", sum.toString(16))
        let expected = m1.add(m2).mod(pub.n)
        assert(sum.eq(expected), "should equal")

        this.timeout(20000)
    })

    it('Functionality: Homomorphic Add Plain!', async function () {
        let m = await Rand.randomBNLt(pub.n)
        let b = await Rand.randomBNLt(pub.n)
        let r = await Rand.randomBNLtGCD(pub.n)
        let c = pub.encryptWithR(m, r)
        let eSum = pub.homomorphicAddPlain(c, b)
        let sum = priv.decrypt(eSum)
        //console.log("pub.n:", pub.n.toString(16))
        //console.log("m:", m.toString(16))
        //console.log("b:", b.toString(16))
        //console.log("sum:", sum.toString(16))
        let expected = m.add(b).mod(pub.n)
        assert(sum.eq(expected), "should equal")
    })

    it('Functionality: Homomorphic Multiple!', async function () {
        let m = await Rand.randomBNLt(pub.n)
        let k = await Rand.randomBNLt(pub.n)
        let r = await Rand.randomBNLtGCD(pub.n)
        let c = pub.encryptWithR(m, r)
        let eMK = pub.homomorphicMulPlain(c, k)
        let mk = priv.decrypt(eMK)
        //console.log("pub.n:", pub.n.toString(16))
        //console.log("m:", m.toString(16))
        //console.log("k:", k.toString(16))
        //console.log("m*k", mk.toString(16))
        assert(mk.eq(m.mul(k).mod(pub.n)), "should equal")
    })
})

describe('Paillier cryptosystem - performance test', async function () {
    const keyPair = await paillier.createPailKeyPair(2048/8)
    const priv = keyPair[0]
    const pub = keyPair[1]
    let m1 = await Rand.randomBNLt(pub.n)
    let m2 = await Rand.randomBNLt(pub.n)
    let r1 = await Rand.randomBNLtGCD(pub.n)
    let r2 = await Rand.randomBNLtGCD(pub.n)

    it('Performance: Encrypt and decrypt!', async function () {
        console.time('1Encrypt')
        let c1 = await pub.encrypt(m1)
        console.timeEnd('1Encrypt')
        console.time('1Decrypt')
        let expected = priv.decrypt(c1)
        console.timeEnd('1Decrypt')
        assert(m1.eq(expected), "should equal")
    })

    it('Performance: EncryptWithR and decrypt!', async function () {
        console.time('1EncryptWithR')
        let c1 = pub.encryptWithR(m1, r1)
        console.timeEnd('1EncryptWithR')

        console.time('1Decrypt')
        let expected = priv.decrypt(c1)
        console.timeEnd('1Decrypt')

        assert(m1.eq(expected), "should equal")
    })

    it('Performance: Homomorphic add!', async function () {
        for(let i = 0; i < 2; i++) {
            let c1 = pub.encryptWithR(m1, r1)
            let c2 = pub.encryptWithR(m2, r2)

            console.time('1Add')
            let eSum = pub.homomorphicAdd(c1, c2)
            console.timeEnd('1Add')

            let sum = priv.decrypt(eSum)
            sum = sum.mod(pub.n)
            let expected = m1.add(m2).mod(pub.n)
            assert(sum.eq(expected), "should equal")
        }
    })

    it('Performance: Homomorphic Add Plain!', async function () {
        let c = pub.encryptWithR(m1, r1)
        console.time('1homomorphicAddPlain')
        let eSum = pub.homomorphicAddPlain(c, r2)
        console.timeEnd('1homomorphicAddPlain')
        let sum = priv.decrypt(eSum)
        let expected = m1.add(r2).mod(pub.n)
        assert(sum.eq(expected), "should equal")
    })

    it('Performance: Homomorphic Multiple!', async function () {
        let c = pub.encryptWithR(m1, r1)
        console.time('1Multiple')
        let eMK = pub.homomorphicMulPlain(c, r2)
        console.timeEnd('1Multiple')
        let mk = priv.decrypt(eMK)
        assert(mk.eq(m1.mul(r2).mod(pub.n)), "should equal")
    })
})
