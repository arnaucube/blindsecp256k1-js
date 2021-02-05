import * as assert from 'assert'
import * as BigInteger from 'bigi'
import { Point } from 'ecurve'
import { keccak256 } from '@ethersproject/keccak256'

import { newBigFromString, ecparams, importPointFromHex, newKeyPair, newRequestParameters, blind, blindSign, unblind, verify } from '../src/index'

describe('keccak256', function () {
	it('keccak256', async () => {
		const m = BigInteger.fromBuffer(Buffer.from('test', 'utf8'))
		const mHex = m.toString(16)
		const hHex = keccak256('0x' + mHex)
		assert.strictEqual('0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658', hHex)
		const h = BigInteger.fromHex(hHex.slice(2))
		assert.strictEqual('70622639689279718371527342103894932928233838121221666359043189029713682937432', h.toString())
	})
})

describe('test blind', function () {
	it('should blind', async () => {
		const { sk, pk } = newKeyPair()

		const { k, signerR } = newRequestParameters()

		const msg = BigInteger.fromBuffer(
			Buffer.from('test', 'utf8')
		)
		assert.strictEqual('1952805748', msg.toString())

		const { mBlinded, userSecretData } = blind(msg, signerR)

		const sBlind = blindSign(sk, mBlinded, k)

		const sig = unblind(sBlind, userSecretData)

		const verified = verify(msg, sig, pk)
		assert(verified)
	})
})

describe('import point from hex', function () {
	it('', async () => {
		// pointHex and expected values was generated from
		// go-blindsecp256k1 (Point.Bytes())
		const pointHex = '73a68e845e626a2d7f683dd2ceb57956f755d623c0b729af30a72c7bf4dee7a6932d08955c98cf21edf35f5df218b56c41014db06f513cecc85dc3d8671f9521'
		const p = importPointFromHex(pointHex)
		assert.strictEqual('75493613315673782629634797792529672610524641864826422940379513836118869976691', p.x.toString())
		assert.strictEqual('15189800969738851359449622716277258420468338317311652509571160848111971610003', p.y.toString())
	})
})
