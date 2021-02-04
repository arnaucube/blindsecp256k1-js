import * as assert from 'assert'
import * as BigInteger from 'bigi'
// import { Point } from 'ecurve'
import { keccak256 } from "@ethersproject/keccak256"

import { newBigFromString, ecparams, newKeyPair, newRequestParameters, blind, blindSign, unblind, verify } from "../src/index"

describe("keccak256", function () {
	it("keccak256", async () => {
		const m = BigInteger.fromBuffer(Buffer.from("test", 'utf8'))
		const mHex = m.toString(16)
		const hHex = keccak256('0x' + mHex)
		assert.strictEqual('0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658', hHex)
		const h = BigInteger.fromHex(hHex.slice(2))
		assert.strictEqual('70622639689279718371527342103894932928233838121221666359043189029713682937432', h.toString())
	})
})

describe("test blind", function () {
	it("should blind", async () => {
		const { sk, pk } = newKeyPair()

		const { k, signerR } = newRequestParameters()

		const msg = BigInteger.fromBuffer(
			Buffer.from("test", 'utf8')
		)
		assert.strictEqual('1952805748', msg.toString())

		const { mBlinded, userSecretData } = blind(msg, signerR)

		const sBlind = blindSign(sk, mBlinded, k)

		const sig = unblind(sBlind, userSecretData)

		const verified = verify(msg, sig, pk)
		assert(verified)
	})
})
