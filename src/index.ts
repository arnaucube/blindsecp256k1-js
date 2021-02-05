import { randomBytes } from 'crypto'
import * as BigNumber from 'bn.js'
import { ec, curve } from 'elliptic'
import { keccak256 } from "@ethersproject/keccak256"

export type Point = curve.base.BasePoint
export { BigNumber }

const secp256k1 = new ec("secp256k1")
const G: Point = secp256k1.g
const n = secp256k1.n // as BigNumber

export const ecParams = { G, n }

export type UserSecretData = { a: BigNumber, b: BigNumber, f: Point }
export type UnblindedSignature = { s: BigNumber, f: Point }

export function messageToBigNumber(message: string) {
    const msg = Buffer.from(message, 'utf8')
    return new BigNumber(msg)
}

export function hashBigNumber(m: BigNumber) {
    const mHex = m.toString(16)

    if (mHex.length % 2 == 0)
        return keccak256('0x' + mHex).slice(2) // Trim 0x
    else
        return keccak256('0x0' + mHex).slice(2) // Trim 0x
}

export function stringToBigNumber(s: string) {
    return new BigNumber(s)
}

export function decodePoint(hexPoint: string): Point {
    return secp256k1.keyFromPublic(Buffer.from(hexPoint, "hex")).getPublic()
}

function random(bytes: number) {
    let k: BigNumber
    do {
        k = new BigNumber(randomBytes(bytes))
    } while (k.toString() == "0" && k.gcd(n).toString() != "1")
    return k
}

export function newKeyPair() {
    const sk = random(32)
    return { sk: sk, pk: G.mul(sk) }
}

export function newRequestParameters() {
    const k = random(32)
    return { k: k, signerR: G.mul(k) }
}

/**
 * Blinds the message for the signer R.
 * @param m The message to blind
 * @param signerR
 * @returns The blinded signature and the user secret data
 */
export function blind(m: BigNumber, signerR: Point): { mBlinded: BigNumber, userSecretData: UserSecretData } {
    const u: UserSecretData = { a: new BigNumber(0), b: new BigNumber(0), f: G }
    u.a = random(32)
    u.b = random(32)

    const aR = signerR.mul(u.a)
    const bG = G.mul(u.b)
    u.f = aR.add(bG)

    const rx = u.f.getX().mod(n)

    const ainv = u.a.invm(n)
    const ainvrx = ainv.mul(rx)

    const hHex = hashBigNumber(m)

    const h = new BigNumber(Buffer.from(hHex, "hex"))
    const mBlinded = ainvrx.mul(h)

    return { mBlinded: mBlinded.mod(n), userSecretData: u }
}

/** Performs a signature on a blinded message */
export function blindSign(sk: BigNumber, mBlinded: BigNumber, k: BigNumber): BigNumber {
    let sBlind = sk.mul(mBlinded)
    sBlind = sBlind.add(k)
    return sBlind.mod(n)
}

/**
 * Unblinds the blinded signature.
 * @param blinded signature
 * @param userSecretData
 * @returns unblinded signature
 */
export function unblind(sBlind: BigNumber, userSecretData: UserSecretData): UnblindedSignature {
    const s = userSecretData.a.mul(sBlind).add(userSecretData.b)
    return { s: s.mod(n), f: userSecretData.f }
}

export function verify(m: BigNumber, s: UnblindedSignature, q: Point) {
    const sG = G.mul(s.s)

    const hHex = hashBigNumber(m)

    const h = new BigNumber(Buffer.from(hHex, "hex"))

    const rx = s.f.getX().mod(n)
    const right = s.f.add(
        q.mul(
            rx.mul(h)
        )
    )

    if ((sG.getX().toString() == right.getX().toString())
        && (sG.getY().toString() == right.getY().toString())) {
        return true
    }
    return false
}

export function signatureToHex(signature: UnblindedSignature): string {
    if (!signature || !signature.f || !signature.s) throw new Error("The signature is empty")
    const { f, s } = signature

    // hex(swapEndiannes(s) ) + hex(f)
    const hexPaddedS = zeroPad(s.toBuffer().toString("hex"), 32)
    const flippedHexS = Buffer.from(hexPaddedS, "hex").reverse().toString("hex")

    return zeroPad(flippedHexS, 32) + zeroPad(f.encode("hex", false).substr(2), 64)  // strip 04
}

export function signatureFromHex(hexSignature: string): UnblindedSignature {
    if (!hexSignature || hexSignature.length != 192) throw new Error("Invalid hex signature (96 bytes expected)")

    const s = new BigNumber(Buffer.from(hexSignature.substr(0, 64), "hex").reverse())
    const f = decodePoint("04" + hexSignature.substr(64))
    return { s, f }
}

function zeroPad(hexString: string, byteLength: number) {
    if (hexString.length > (byteLength * 2)) throw new Error("Out of bounds")
    while (hexString.length < (byteLength * 2)) {
        hexString = "0" + hexString
    }
    return hexString
}
