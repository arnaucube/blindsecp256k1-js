var crypto = require('crypto');
var BigInteger = require('bigi')
var ecurve = require('ecurve')
const {keccak256} = require("@ethersproject/keccak256");

const ecparams = ecurve.getCurveByName('secp256k1');
const G = ecparams.G;
const n = ecparams.n;

function newBigFromString(s) {
    var a = new BigInteger()
    a.fromString(s)
    return a;
}

function random(bytes){
    do {
	var k = BigInteger.fromByteArrayUnsigned(crypto.randomBytes(bytes));
    } while (k.toString() == "0" && k.gcd(n).toString() != "1")
    return k;
}

function newKeyPair() {
    const sk = random(32);
    return {sk: sk, pk: G.multiply(sk)};
}

function newRequestParameters() {
    const k = random(32);
    return {k: k, signerR: G.multiply(k)};
}

/**
 * Blinds the message for the signer R.
 * @param {BigInteger} m
 * @param {Point} signerR
 * @returns {struct} {mBlinded: BigInteger, userSecretData: {a: BigInteger, b: BigInteger, f: Point}}
 */
function blind(m, signerR) {
    let u = {a: BigInteger.ZERO, b: BigInteger.ZERO, f: G};
    u.a = random(32);
    u.b = random(32);

    const aR = signerR.multiply(u.a);
    const bG = G.multiply(u.b);
    u.f = aR.add(bG);

    const rx = u.f.affineX.mod(n);

    const ainv = u.a.modInverse(n);
    const ainvrx = ainv.multiply(rx);

    const mHex = m.toString(16);
    const hHex = keccak256('0x' + mHex);
    const h = BigInteger.fromHex(hHex.slice(2));
    const mBlinded = ainvrx.multiply(h);

    return {mBlinded: mBlinded.mod(n), userSecretData: u};
}

function blindSign(sk, mBlinded, k) {
    let sBlind = sk.multiply(mBlinded);
    sBlind = sBlind.add(k);
    return sBlind.mod(n);
}

/**
 * Unblinds the blinded signature.
 * @param {BigInteger} sBlind - blinded signature
 * @param {a: BigInteger, b: BigInteger, f: Point} - userSecretData
 * @returns {s: BigInteger, f: Point} - unblinded signature
 */
function unblind(sBlind, userSecretData) {
    const s = userSecretData.a.multiply(sBlind).add(userSecretData.b);
    return {s: s.mod(n), f: userSecretData.f};
}

function verify(m, s, q) {
    const sG = G.multiply(s.s);

    const mHex = m.toString(16);
    const hHex = keccak256('0x' + mHex);
    const h = BigInteger.fromHex(hHex.slice(2));

    const rx = s.f.affineX.mod(n);
    const right = s.f.add(
	q.multiply(
	    rx.multiply(h)
	)
    );

    if ((sG.affineX.toString() == right.affineX.toString())
	&& (sG.affineY.toString() == right.affineY.toString())) {
	return true;
    }
    return false;
}


module.exports = {
    newBigFromString: newBigFromString,
    ecparams: ecparams,
    newKeyPair: newKeyPair,
    newRequestParameters: newRequestParameters,
    blind: blind,
    blindSign: blindSign,
    unblind: unblind,
    verify: verify
}
