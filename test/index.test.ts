import * as assert from 'assert'

import {
	stringToBigNumber,
	messageToBigNumber,
	decodePoint,
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
	it("should hash strings and big numbers", async () => {
		const m = messageToBigNumber("test")
		assert.strictEqual('1952805748', m.toString())

		const hHex = hashBigNumber(m)
		assert.strictEqual(hHex, '9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658')
		const h = new BigNumber(Buffer.from(hHex, "hex"))
		assert.strictEqual(h.toString(), '70622639689279718371527342103894932928233838121221666359043189029713682937432')
	})

	it("should decode points in the secp256k1 curve", () => {
		const tokenR = "7cfe4af054e13b4e7231d876d23205fb5f939ac8185271ca6b64c635a365faae259fb8cabdb06dde39d1ebeada3cb75cb9739621a79c61a8cf1e9a38abaf782a"
		const point = decodePoint("04" + tokenR)
		assert.strictEqual(point.getX().toString(16), tokenR.substr(0, 64))
		assert.strictEqual(point.getY().toString(16), tokenR.substr(64))
	})
})

describe("blind signatures", function () {
	it("should blind, unblind and verify", async () => {
		const { sk, pk } = newKeyPair()

		const { k, signerR } = newRequestParameters()

		const msg = messageToBigNumber("test")

		const { mBlinded, userSecretData } = blind(msg, signerR)

		const sBlind = blindSign(sk, mBlinded, k)

		const sig = unblind(sBlind, userSecretData)

		const verified = verify(msg, sig, pk)
		assert(verified)
	})
})
