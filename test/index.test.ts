import * as assert from 'assert'

import {
	bigNumberFromString,
	ecParams,
	newKeyPair,
	newRequestParameters,
	blind,
	blindSign,
	unblind,
	verify,
	hashBigNumber,
	Point,
	BigNumber
} from "../src/index"

describe("keccak256", function () {
	it("keccak256", async () => {
		const msg = Buffer.from("test", 'utf8')
		const m = new BigNumber(msg)
		const hHex = hashBigNumber(m)
		assert.strictEqual(hHex, '9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658')
		const h = new BigNumber(Buffer.from(hHex, "hex"))
		assert.strictEqual(h.toString(), '70622639689279718371527342103894932928233838121221666359043189029713682937432')
	})
})

describe("test blind", function () {
	it("should blind", async () => {
		const { sk, pk } = newKeyPair()

		const { k, signerR } = newRequestParameters()

		const msg = new BigNumber(
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
