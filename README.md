# crypto-paillier-js
# Installation
```shell
npm install @safeheron/crypto-paillier
```

Import the library in code:
```javascript
import * as assert from "assert"
import * as BN from "bn.js"
import {Rand} from '@safeheron/crypto-rand'
import {PailPrivKey, PailPubKey, createPailKeyPair} from "@safeheron/crypto-paillier"
```

# Examples

## Encrypt and Decrypt

```javascript
let m = await Rand.randomBNLt(pub.n)
let r = await Rand.randomBNLtGCD(pub.n)
let c = await pub.encryptWithR(m, r)
let expected = await priv.decrypt(c)
assert(m.eq(expected), "should equal")
```

