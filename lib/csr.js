// Copyright 2018-present AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
(function(exports) {
	'use strict';
	/*global Promise*/

	var ASN1 = exports.ASN1;
	var Enc = exports.Enc;
	var PEM = exports.PEM;
	var X509 = exports.x509;
	var Keypairs = exports.Keypairs;

	// TODO find a way that the prior node-ish way of `module.exports = function () {}` isn't broken
	var CSR = (exports.CSR = function(opts) {
		// We're using a Promise here to be compatible with the browser version
		// which will probably use the webcrypto API for some of the conversions
		return CSR._prepare(opts).then(function(opts) {
			return CSR.create(opts).then(function(bytes) {
				return CSR._encode(opts, bytes);
			});
		});
	});

	CSR._prepare = function(opts) {
		return Promise.resolve().then(function() {
			var Keypairs;
			opts = JSON.parse(JSON.stringify(opts));

			// We do a bit of extra error checking for user convenience
			if (!opts) {
				throw new Error(
					'You must pass options with key and domains to rsacsr'
				);
			}
			if (!Array.isArray(opts.domains) || 0 === opts.domains.length) {
				new Error('You must pass options.domains as a non-empty array');
			}

			// I need to check that 例.中国 is a valid domain name
			if (
				!opts.domains.every(function(d) {
					// allow punycode? xn--
					if (
						'string' ===
						typeof d /*&& /\./.test(d) && !/--/.test(d)*/
					) {
						return true;
					}
				})
			) {
				throw new Error('You must pass options.domains as strings');
			}

			if (opts.jwk) {
				return opts;
			}
			if (opts.key && opts.key.kty) {
				opts.jwk = opts.key;
				return opts;
			}
			if (!opts.pem && !opts.key) {
				throw new Error('You must pass options.key as a JSON web key');
			}

			Keypairs = exports.Keypairs;
			if (!exports.Keypairs) {
				throw new Error(
					'Keypairs.js is an optional dependency for PEM-to-JWK.\n' +
						"Install it if you'd like to use it:\n" +
						'\tnpm install --save rasha\n' +
						'Otherwise supply a jwk as the private key.'
				);
			}

			return Keypairs.import({ pem: opts.pem || opts.key }).then(function(
				pair
			) {
				opts.jwk = pair.private;
				return opts;
			});
		});
	};

	CSR._encode = function(opts, bytes) {
		if ('der' === (opts.encoding || '').toLowerCase()) {
			return bytes;
		}
		return PEM.packBlock({
			type: 'CERTIFICATE REQUEST',
			bytes: bytes /* { jwk: jwk, domains: opts.domains } */
		});
	};

	CSR.create = function createCsr(opts) {
		var hex = CSR.request(opts.jwk, opts.domains);
		return CSR._sign(opts.jwk, hex).then(function(csr) {
			return Enc.hexToBuf(csr);
		});
	};

	//
	// EC / RSA
	//
	CSR.request = function createCsrBodyEc(jwk, domains) {
		var asn1pub;
		if (/^EC/i.test(jwk.kty)) {
			asn1pub = X509.packCsrEcPublicKey(jwk);
		} else {
			asn1pub = X509.packCsrRsaPublicKey(jwk);
		}
		return X509.packCsr(asn1pub, domains);
	};

	CSR._sign = function csrEcSig(jwk, request) {
		// Took some tips from https://gist.github.com/codermapuche/da4f96cdb6d5ff53b7ebc156ec46a10a
		// TODO will have to convert web ECDSA signatures to PEM ECDSA signatures (but RSA should be the same)
		// TODO have a consistent non-private way to sign
		return Keypairs._sign(
			{ jwk: jwk, format: 'x509' },
			Enc.hexToBuf(request)
		).then(function(sig) {
			return CSR._toDer({
				request: request,
				signature: sig,
				kty: jwk.kty
			});
		});
	};

	CSR._toDer = function encode(opts) {
		var sty;
		if (/^EC/i.test(opts.kty)) {
			// 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
			sty = ASN1('30', ASN1('06', '2a8648ce3d040302'));
		} else {
			// 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
			sty = ASN1('30', ASN1('06', '2a864886f70d01010b'), ASN1('05'));
		}
		return ASN1(
			'30',
			// The Full CSR Request Body
			opts.request,
			// The Signature Type
			sty,
			// The Signature
			ASN1.BitStr(Enc.bufToHex(opts.signature))
		);
	};

	X509.packCsr = function(asn1pubkey, domains) {
		return ASN1(
			'30',
			// Version (0)
			ASN1.UInt('00'),

			// 2.5.4.3 commonName (X.520 DN component)
			ASN1(
				'30',
				ASN1(
					'31',
					ASN1(
						'30',
						ASN1('06', '550403'),
						ASN1('0c', Enc.utf8ToHex(domains[0]))
					)
				)
			),

			// Public Key (RSA or EC)
			asn1pubkey,

			// Request Body
			ASN1(
				'a0',
				ASN1(
					'30',
					// 1.2.840.113549.1.9.14 extensionRequest (PKCS #9 via CRMF)
					ASN1('06', '2a864886f70d01090e'),
					ASN1(
						'31',
						ASN1(
							'30',
							ASN1(
								'30',
								// 2.5.29.17 subjectAltName (X.509 extension)
								ASN1('06', '551d11'),
								ASN1(
									'04',
									ASN1(
										'30',
										domains
											.map(function(d) {
												return ASN1(
													'82',
													Enc.utf8ToHex(d)
												);
											})
											.join('')
									)
								)
							)
						)
					)
				)
			)
		);
	};

	// TODO finish this later
	// we want to parse the domains, the public key, and verify the signature
	CSR._info = function(der) {
		// standard base64 PEM
		if ('string' === typeof der && '-' === der[0]) {
			der = PEM.parseBlock(der).bytes;
		}
		// jose urlBase64 not-PEM
		if ('string' === typeof der) {
			der = Enc.base64ToBuf(der);
		}
		// not supporting binary-encoded bas64
		var c = ASN1.parse(der);
		var kty;
		// A cert has 3 parts: cert, signature meta, signature
		if (c.children.length !== 3) {
			throw new Error(
				"doesn't look like a certificate request: expected 3 parts of header"
			);
		}
		var sig = c.children[2];
		if (sig.children.length) {
			// ASN1/X509 EC
			sig = sig.children[0];
			sig = ASN1(
				'30',
				ASN1.UInt(Enc.bufToHex(sig.children[0].value)),
				ASN1.UInt(Enc.bufToHex(sig.children[1].value))
			);
			sig = Enc.hexToBuf(sig);
			kty = 'EC';
		} else {
			// Raw RSA Sig
			sig = sig.value;
			kty = 'RSA';
		}
		//c.children[1]; // signature type
		var req = c.children[0];
		// TODO utf8
		if (4 !== req.children.length) {
			throw new Error(
				"doesn't look like a certificate request: expected 4 parts to request"
			);
		}
		// 0 null
		// 1 commonName / subject
		var sub = Enc.bufToBin(
			req.children[1].children[0].children[0].children[1].value
		);
		// 3 public key (type, key)
		//console.log('oid', Enc.bufToHex(req.children[2].children[0].children[0].value));
		var pub;
		// TODO reuse ASN1 parser for these?
		if ('EC' === kty) {
			// throw away compression byte
			pub = req.children[2].children[1].value.slice(1);
			pub = { kty: kty, x: pub.slice(0, 32), y: pub.slice(32) };
			while (0 === pub.x[0]) {
				pub.x = pub.x.slice(1);
			}
			while (0 === pub.y[0]) {
				pub.y = pub.y.slice(1);
			}
			if ((pub.x.length || pub.x.byteLength) > 48) {
				pub.crv = 'P-521';
			} else if ((pub.x.length || pub.x.byteLength) > 32) {
				pub.crv = 'P-384';
			} else {
				pub.crv = 'P-256';
			}
			pub.x = Enc.bufToUrlBase64(pub.x);
			pub.y = Enc.bufToUrlBase64(pub.y);
		} else {
			pub = req.children[2].children[1].children[0];
			pub = {
				kty: kty,
				n: pub.children[0].value,
				e: pub.children[1].value
			};
			while (0 === pub.n[0]) {
				pub.n = pub.n.slice(1);
			}
			while (0 === pub.e[0]) {
				pub.e = pub.e.slice(1);
			}
			pub.n = Enc.bufToUrlBase64(pub.n);
			pub.e = Enc.bufToUrlBase64(pub.e);
		}
		// 4 extensions
		var domains = req.children[3].children
			.filter(function(seq) {
				//  1.2.840.113549.1.9.14 extensionRequest (PKCS #9 via CRMF)
				if (
					'2a864886f70d01090e' === Enc.bufToHex(seq.children[0].value)
				) {
					return true;
				}
			})
			.map(function(seq) {
				return seq.children[1].children[0].children
					.filter(function(seq2) {
						// subjectAltName (X.509 extension)
						if ('551d11' === Enc.bufToHex(seq2.children[0].value)) {
							return true;
						}
					})
					.map(function(seq2) {
						return seq2.children[1].children[0].children.map(
							function(name) {
								// TODO utf8
								return Enc.bufToBin(name.value);
							}
						);
					})[0];
			})[0];

		return {
			subject: sub,
			altnames: domains,
			jwk: pub,
			signature: sig
		};
	};

	X509.packCsrRsaPublicKey = function(jwk) {
		// Sequence the key
		var n = ASN1.UInt(Enc.base64ToHex(jwk.n));
		var e = ASN1.UInt(Enc.base64ToHex(jwk.e));
		var asn1pub = ASN1('30', n, e);

		// Add the CSR pub key header
		return ASN1(
			'30',
			ASN1('30', ASN1('06', '2a864886f70d010101'), ASN1('05')),
			ASN1.BitStr(asn1pub)
		);
	};

	X509.packCsrEcPublicKey = function(jwk) {
		var ecOid = X509._oids[jwk.crv];
		if (!ecOid) {
			throw new Error(
				"Unsupported namedCurve '" +
					jwk.crv +
					"'. Supported types are " +
					Object.keys(X509._oids)
			);
		}
		var cmp = '04'; // 04 == x+y, 02 == x-only
		var hxy = '';
		// Placeholder. I'm not even sure if compression should be supported.
		if (!jwk.y) {
			cmp = '02';
		}
		hxy += Enc.base64ToHex(jwk.x);
		if (jwk.y) {
			hxy += Enc.base64ToHex(jwk.y);
		}

		// 1.2.840.10045.2.1 ecPublicKey
		return ASN1(
			'30',
			ASN1('30', ASN1('06', '2a8648ce3d0201'), ASN1('06', ecOid)),
			ASN1.BitStr(cmp + hxy)
		);
	};
	X509._oids = {
		// 1.2.840.10045.3.1.7 prime256v1
		// (ANSI X9.62 named elliptic curve) (06 08 - 2A 86 48 CE 3D 03 01 07)
		'P-256': '2a8648ce3d030107',
		// 1.3.132.0.34 P-384 (06 05 - 2B 81 04 00 22)
		// (SEC 2 recommended EC domain secp256r1)
		'P-384': '2b81040022'
		// requires more logic and isn't a recommended standard
		// 1.3.132.0.35 P-521 (06 05 - 2B 81 04 00 23)
		// (SEC 2 alternate P-521)
		//, 'P-521': '2B 81 04 00 23'
	};

	// don't replace the full parseBlock, if it exists
	PEM.parseBlock =
		PEM.parseBlock ||
		function(str) {
			var der = str
				.split(/\n/)
				.filter(function(line) {
					return !/-----/.test(line);
				})
				.join('');
			return { bytes: Enc.base64ToBuf(der) };
		};
})('undefined' === typeof window ? module.exports : window);
