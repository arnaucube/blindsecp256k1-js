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
	BigNumber,
	signatureToHex,
	signatureFromHex
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

describe("encoding", () => {
	it("should encode and decode signatures", () => {
		const { sk } = newKeyPair()
		const { k, signerR } = newRequestParameters()
		const msg = messageToBigNumber("test")
		const { mBlinded, userSecretData } = blind(msg, signerR)
		const sBlind = blindSign(sk, mBlinded, k)
		const sig = unblind(sBlind, userSecretData)

		const hexSignature = signatureToHex(sig)
		assert.strictEqual(hexSignature.length, 192)

		const decodedSig = signatureFromHex(hexSignature)
		assert.strictEqual(decodedSig.f.encode("hex", false).length, 130)

		assert.strictEqual(signatureToHex(signatureFromHex(hexSignature)), hexSignature)

		// explicit values
		const hexSignature2 = "089a89f07bd41560454b1640fd30e51ee088d1be8355275a88e38a38f2e7a3af9e80fcc14af9c47c8066c6726e7d3cac9370494d5c67936b2978d6cecf5a4d21bf3ef00b060c47ba874c0764d662eff2d0e9daa8ba766f4aa6a2be8ec3d37523"

		const decodedSig2 = signatureFromHex(hexSignature2)
		assert.strictEqual(decodedSig2.s.toString("hex"), "afa3e7f2388ae3885a275583bed188e01ee530fd40164b456015d47bf0899a08")
		assert.strictEqual(decodedSig2.f.encode("hex", false).substr(2), "9e80fcc14af9c47c8066c6726e7d3cac9370494d5c67936b2978d6cecf5a4d21bf3ef00b060c47ba874c0764d662eff2d0e9daa8ba766f4aa6a2be8ec3d37523")

		assert.strictEqual(signatureToHex(signatureFromHex(hexSignature2)), hexSignature2)

		// swapEndianness(s) starting with 0
		const hexSignature3 = "089a89f07bd41560454b1640fd30e51ee088d1be8355275a88e38a38f2e7a30f9e80fcc14af9c47c8066c6726e7d3cac9370494d5c67936b2978d6cecf5a4d21bf3ef00b060c47ba874c0764d662eff2d0e9daa8ba766f4aa6a2be8ec3d37523"

		const decodedSig3 = signatureFromHex(hexSignature3)
		assert.strictEqual(decodedSig3.s.toString("hex"), /* 0 */ "fa3e7f2388ae3885a275583bed188e01ee530fd40164b456015d47bf0899a08")
		assert.strictEqual(decodedSig3.f.encode("hex", false).substr(2), "9e80fcc14af9c47c8066c6726e7d3cac9370494d5c67936b2978d6cecf5a4d21bf3ef00b060c47ba874c0764d662eff2d0e9daa8ba766f4aa6a2be8ec3d37523")

		assert.strictEqual(signatureToHex(signatureFromHex(hexSignature3)), hexSignature3)
	})
})
