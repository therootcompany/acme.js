(function(exports) {
	'use strict';

	var x509 = (exports.x509 = {});
	var ASN1 = exports.ASN1;
	var Enc = exports.Enc;

	// 1.2.840.10045.3.1.7
	// prime256v1 (ANSI X9.62 named elliptic curve)
	var OBJ_ID_EC = '06 08 2A8648CE3D030107'.replace(/\s+/g, '').toLowerCase();
	// 1.3.132.0.34
	// secp384r1 (SECG (Certicom) named elliptic curve)
	var OBJ_ID_EC_384 = '06 05 2B81040022'.replace(/\s+/g, '').toLowerCase();
	// 1.2.840.10045.2.1
	// ecPublicKey (ANSI X9.62 public key type)
	var OBJ_ID_EC_PUB = '06 07 2A8648CE3D0201'
		.replace(/\s+/g, '')
		.toLowerCase();

	x509.parseSec1 = function parseEcOnlyPrivkey(u8, jwk) {
		var index = 7;
		var len = 32;
		var olen = OBJ_ID_EC.length / 2;

		if ('P-384' === jwk.crv) {
			olen = OBJ_ID_EC_384.length / 2;
			index = 8;
			len = 48;
		}
		if (len !== u8[index - 1]) {
			throw new Error('Unexpected bitlength ' + len);
		}

		// private part is d
		var d = u8.slice(index, index + len);
		// compression bit index
		var ci = index + len + 2 + olen + 2 + 3;
		var c = u8[ci];
		var x, y;

		if (0x04 === c) {
			y = u8.slice(ci + 1 + len, ci + 1 + len + len);
		} else if (0x02 !== c) {
			throw new Error('not a supported EC private key');
		}
		x = u8.slice(ci + 1, ci + 1 + len);

		return {
			kty: jwk.kty,
			crv: jwk.crv,
			d: Enc.bufToUrlBase64(d),
			//, dh: Enc.bufToHex(d)
			x: Enc.bufToUrlBase64(x),
			//, xh: Enc.bufToHex(x)
			y: Enc.bufToUrlBase64(y)
			//, yh: Enc.bufToHex(y)
		};
	};

	x509.packPkcs1 = function(jwk) {
		var n = ASN1.UInt(Enc.base64ToHex(jwk.n));
		var e = ASN1.UInt(Enc.base64ToHex(jwk.e));

		if (!jwk.d) {
			return Enc.hexToBuf(ASN1('30', n, e));
		}

		return Enc.hexToBuf(
			ASN1(
				'30',
				ASN1.UInt('00'),
				n,
				e,
				ASN1.UInt(Enc.base64ToHex(jwk.d)),
				ASN1.UInt(Enc.base64ToHex(jwk.p)),
				ASN1.UInt(Enc.base64ToHex(jwk.q)),
				ASN1.UInt(Enc.base64ToHex(jwk.dp)),
				ASN1.UInt(Enc.base64ToHex(jwk.dq)),
				ASN1.UInt(Enc.base64ToHex(jwk.qi))
			)
		);
	};

	x509.parsePkcs8 = function parseEcPkcs8(u8, jwk) {
		var index = 24 + OBJ_ID_EC.length / 2;
		var len = 32;
		if ('P-384' === jwk.crv) {
			index = 24 + OBJ_ID_EC_384.length / 2 + 2;
			len = 48;
		}

		//console.log(index, u8.slice(index));
		if (0x04 !== u8[index]) {
			//console.log(jwk);
			throw new Error('privkey not found');
		}
		var d = u8.slice(index + 2, index + 2 + len);
		var ci = index + 2 + len + 5;
		var xi = ci + 1;
		var x = u8.slice(xi, xi + len);
		var yi = xi + len;
		var y;
		if (0x04 === u8[ci]) {
			y = u8.slice(yi, yi + len);
		} else if (0x02 !== u8[ci]) {
			throw new Error('invalid compression bit (expected 0x04 or 0x02)');
		}

		return {
			kty: jwk.kty,
			crv: jwk.crv,
			d: Enc.bufToUrlBase64(d),
			//, dh: Enc.bufToHex(d)
			x: Enc.bufToUrlBase64(x),
			//, xh: Enc.bufToHex(x)
			y: Enc.bufToUrlBase64(y)
			//, yh: Enc.bufToHex(y)
		};
	};

	x509.parseSpki = function parsePem(u8, jwk) {
		var ci = 16 + OBJ_ID_EC.length / 2;
		var len = 32;

		if ('P-384' === jwk.crv) {
			ci = 16 + OBJ_ID_EC_384.length / 2;
			len = 48;
		}

		var c = u8[ci];
		var xi = ci + 1;
		var x = u8.slice(xi, xi + len);
		var yi = xi + len;
		var y;
		if (0x04 === c) {
			y = u8.slice(yi, yi + len);
		} else if (0x02 !== c) {
			throw new Error('not a supported EC private key');
		}

		return {
			kty: jwk.kty,
			crv: jwk.crv,
			x: Enc.bufToUrlBase64(x),
			//, xh: Enc.bufToHex(x)
			y: Enc.bufToUrlBase64(y)
			//, yh: Enc.bufToHex(y)
		};
	};
	x509.parsePkix = x509.parseSpki;

	x509.packSec1 = function(jwk) {
		var d = Enc.base64ToHex(jwk.d);
		var x = Enc.base64ToHex(jwk.x);
		var y = Enc.base64ToHex(jwk.y);
		var objId = 'P-256' === jwk.crv ? OBJ_ID_EC : OBJ_ID_EC_384;
		return Enc.hexToBuf(
			ASN1(
				'30',
				ASN1.UInt('01'),
				ASN1('04', d),
				ASN1('A0', objId),
				ASN1('A1', ASN1.BitStr('04' + x + y))
			)
		);
	};
	/**
	 * take a private jwk and creates a der from it
	 * @param {*} jwk
	 */
	x509.packPkcs8 = function(jwk) {
		if ('RSA' === jwk.kty) {
			if (!jwk.d) {
				// Public RSA
				return Enc.hexToBuf(
					ASN1(
						'30',
						ASN1(
							'30',
							ASN1('06', '2a864886f70d010101'),
							ASN1('05')
						),
						ASN1.BitStr(
							ASN1(
								'30',
								ASN1.UInt(Enc.base64ToHex(jwk.n)),
								ASN1.UInt(Enc.base64ToHex(jwk.e))
							)
						)
					)
				);
			}

			// Private RSA
			return Enc.hexToBuf(
				ASN1(
					'30',
					ASN1.UInt('00'),
					ASN1('30', ASN1('06', '2a864886f70d010101'), ASN1('05')),
					ASN1(
						'04',
						ASN1(
							'30',
							ASN1.UInt('00'),
							ASN1.UInt(Enc.base64ToHex(jwk.n)),
							ASN1.UInt(Enc.base64ToHex(jwk.e)),
							ASN1.UInt(Enc.base64ToHex(jwk.d)),
							ASN1.UInt(Enc.base64ToHex(jwk.p)),
							ASN1.UInt(Enc.base64ToHex(jwk.q)),
							ASN1.UInt(Enc.base64ToHex(jwk.dp)),
							ASN1.UInt(Enc.base64ToHex(jwk.dq)),
							ASN1.UInt(Enc.base64ToHex(jwk.qi))
						)
					)
				)
			);
		}

		var d = Enc.base64ToHex(jwk.d);
		var x = Enc.base64ToHex(jwk.x);
		var y = Enc.base64ToHex(jwk.y);
		var objId = 'P-256' === jwk.crv ? OBJ_ID_EC : OBJ_ID_EC_384;
		return Enc.hexToBuf(
			ASN1(
				'30',
				ASN1.UInt('00'),
				ASN1('30', OBJ_ID_EC_PUB, objId),
				ASN1(
					'04',
					ASN1(
						'30',
						ASN1.UInt('01'),
						ASN1('04', d),
						ASN1('A1', ASN1.BitStr('04' + x + y))
					)
				)
			)
		);
	};
	x509.packSpki = function(jwk) {
		if (/EC/i.test(jwk.kty)) {
			return x509.packSpkiEc(jwk);
		}
		return x509.packSpkiRsa(jwk);
	};
	x509.packSpkiRsa = function(jwk) {
		if (!jwk.d) {
			// Public RSA
			return Enc.hexToBuf(
				ASN1(
					'30',
					ASN1('30', ASN1('06', '2a864886f70d010101'), ASN1('05')),
					ASN1.BitStr(
						ASN1(
							'30',
							ASN1.UInt(Enc.base64ToHex(jwk.n)),
							ASN1.UInt(Enc.base64ToHex(jwk.e))
						)
					)
				)
			);
		}

		// Private RSA
		return Enc.hexToBuf(
			ASN1(
				'30',
				ASN1.UInt('00'),
				ASN1('30', ASN1('06', '2a864886f70d010101'), ASN1('05')),
				ASN1(
					'04',
					ASN1(
						'30',
						ASN1.UInt('00'),
						ASN1.UInt(Enc.base64ToHex(jwk.n)),
						ASN1.UInt(Enc.base64ToHex(jwk.e)),
						ASN1.UInt(Enc.base64ToHex(jwk.d)),
						ASN1.UInt(Enc.base64ToHex(jwk.p)),
						ASN1.UInt(Enc.base64ToHex(jwk.q)),
						ASN1.UInt(Enc.base64ToHex(jwk.dp)),
						ASN1.UInt(Enc.base64ToHex(jwk.dq)),
						ASN1.UInt(Enc.base64ToHex(jwk.qi))
					)
				)
			)
		);
	};
	x509.packSpkiEc = function(jwk) {
		var x = Enc.base64ToHex(jwk.x);
		var y = Enc.base64ToHex(jwk.y);
		var objId = 'P-256' === jwk.crv ? OBJ_ID_EC : OBJ_ID_EC_384;
		return Enc.hexToBuf(
			ASN1(
				'30',
				ASN1('30', OBJ_ID_EC_PUB, objId),
				ASN1.BitStr('04' + x + y)
			)
		);
	};
	x509.packPkix = x509.packSpki;
})('undefined' !== typeof module ? module.exports : window);
