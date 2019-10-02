/*global Promise*/
(function(exports) {
	'use strict';

	var Keypairs = (exports.Keypairs = {});
	var Rasha = exports.Rasha;
	var Eckles = exports.Eckles;
	var Enc = exports.Enc || {};

	Keypairs._stance =
		"We take the stance that if you're knowledgeable enough to" +
		" properly and securely use non-standard crypto then you shouldn't need Bluecrypt anyway.";
	Keypairs._universal =
		'Bluecrypt only supports crypto with standard cross-browser and cross-platform support.';
	Keypairs.generate = function(opts) {
		opts = opts || {};
		var p;
		if (!opts.kty) {
			opts.kty = opts.type;
		}
		if (!opts.kty) {
			opts.kty = 'EC';
		}
		if (/^EC/i.test(opts.kty)) {
			p = Eckles.generate(opts);
		} else if (/^RSA$/i.test(opts.kty)) {
			p = Rasha.generate(opts);
		} else {
			return Promise.Reject(
				new Error(
					"'" +
						opts.kty +
						"' is not a well-supported key type." +
						Keypairs._universal +
						" Please choose 'EC', or 'RSA' if you have good reason to."
				)
			);
		}
		return p.then(function(pair) {
			return Keypairs.thumbprint({ jwk: pair.public }).then(function(
				thumb
			) {
				pair.private.kid = thumb; // maybe not the same id on the private key?
				pair.public.kid = thumb;
				return pair;
			});
		});
	};

	Keypairs.export = function(opts) {
		return Eckles.export(opts).catch(function(err) {
			return Rasha.export(opts).catch(function() {
				return Promise.reject(err);
			});
		});
	};

	/**
	 * Chopping off the private parts is now part of the public API.
	 * I thought it sounded a little too crude at first, but it really is the best name in every possible way.
	 */
	Keypairs.neuter = function(opts) {
		/** trying to find the best balance of an immutable copy with custom attributes */
		var jwk = {};
		Object.keys(opts.jwk).forEach(function(k) {
			if ('undefined' === typeof opts.jwk[k]) {
				return;
			}
			// ignore RSA and EC private parts
			if (-1 !== ['d', 'p', 'q', 'dp', 'dq', 'qi'].indexOf(k)) {
				return;
			}
			jwk[k] = JSON.parse(JSON.stringify(opts.jwk[k]));
		});
		return jwk;
	};

	Keypairs.thumbprint = function(opts) {
		return Promise.resolve().then(function() {
			if (/EC/i.test(opts.jwk.kty)) {
				return Eckles.thumbprint(opts);
			} else {
				return Rasha.thumbprint(opts);
			}
		});
	};

	Keypairs.publish = function(opts) {
		if ('object' !== typeof opts.jwk || !opts.jwk.kty) {
			throw new Error('invalid jwk: ' + JSON.stringify(opts.jwk));
		}

		/** returns a copy */
		var jwk = Keypairs.neuter(opts);

		if (jwk.exp) {
			jwk.exp = setTime(jwk.exp);
		} else {
			if (opts.exp) {
				jwk.exp = setTime(opts.exp);
			} else if (opts.expiresIn) {
				jwk.exp = Math.round(Date.now() / 1000) + opts.expiresIn;
			} else if (opts.expiresAt) {
				jwk.exp = opts.expiresAt;
			}
		}
		if (!jwk.use && false !== jwk.use) {
			jwk.use = 'sig';
		}

		if (jwk.kid) {
			return Promise.resolve(jwk);
		}
		return Keypairs.thumbprint({ jwk: jwk }).then(function(thumb) {
			jwk.kid = thumb;
			return jwk;
		});
	};

	// JWT a.k.a. JWS with Claims using Compact Serialization
	Keypairs.signJwt = function(opts) {
		return Keypairs.thumbprint({ jwk: opts.jwk }).then(function(thumb) {
			var header = opts.header || {};
			var claims = JSON.parse(JSON.stringify(opts.claims || {}));
			header.typ = 'JWT';

			if (!header.kid) {
				header.kid = thumb;
			}
			if (!header.alg && opts.alg) {
				header.alg = opts.alg;
			}
			if (!claims.iat && (false === claims.iat || false === opts.iat)) {
				claims.iat = undefined;
			} else if (!claims.iat) {
				claims.iat = Math.round(Date.now() / 1000);
			}

			if (opts.exp) {
				claims.exp = setTime(opts.exp);
			} else if (
				!claims.exp &&
				(false === claims.exp || false === opts.exp)
			) {
				claims.exp = undefined;
			} else if (!claims.exp) {
				throw new Error(
					"opts.claims.exp should be the expiration date as seconds, human form (i.e. '1h' or '15m') or false"
				);
			}

			if (opts.iss) {
				claims.iss = opts.iss;
			}
			if (!claims.iss && (false === claims.iss || false === opts.iss)) {
				claims.iss = undefined;
			} else if (!claims.iss) {
				throw new Error(
					'opts.claims.iss should be in the form of https://example.com/, a secure OIDC base url'
				);
			}

			return Keypairs.signJws({
				jwk: opts.jwk,
				pem: opts.pem,
				protected: header,
				header: undefined,
				payload: claims
			}).then(function(jws) {
				return [jws.protected, jws.payload, jws.signature].join('.');
			});
		});
	};

	Keypairs.signJws = function(opts) {
		return Keypairs.thumbprint(opts).then(function(thumb) {
			function alg() {
				if (!opts.jwk) {
					throw new Error(
						"opts.jwk must exist and must declare 'typ'"
					);
				}
				if (opts.jwk.alg) {
					return opts.jwk.alg;
				}
				var typ = 'RSA' === opts.jwk.kty ? 'RS' : 'ES';
				return typ + Keypairs._getBits(opts);
			}

			function sign() {
				var protect = opts.protected;
				var payload = opts.payload;

				// Compute JWS signature
				var protectedHeader = '';
				// Because unprotected headers are allowed, regrettably...
				// https://stackoverflow.com/a/46288694
				if (false !== protect) {
					if (!protect) {
						protect = {};
					}
					if (!protect.alg) {
						protect.alg = alg();
					}
					// There's a particular request where ACME / Let's Encrypt explicitly doesn't use a kid
					if (false === protect.kid) {
						protect.kid = undefined;
					} else if (!protect.kid) {
						protect.kid = thumb;
					}
					protectedHeader = JSON.stringify(protect);
				}

				// Not sure how to handle the empty case since ACME POST-as-GET must be empty
				//if (!payload) {
				//  throw new Error("opts.payload should be JSON, string, or ArrayBuffer (it may be empty, but that must be explicit)");
				//}
				// Trying to detect if it's a plain object (not Buffer, ArrayBuffer, Array, Uint8Array, etc)
				if (
					payload &&
					'string' !== typeof payload &&
					'undefined' === typeof payload.byteLength &&
					'undefined' === typeof payload.buffer
				) {
					payload = JSON.stringify(payload);
				}
				// Converting to a buffer, even if it was just converted to a string
				if ('string' === typeof payload) {
					payload = Enc.binToBuf(payload);
				}

				// node specifies RSA-SHAxxx even when it's actually ecdsa (it's all encoded x509 shasums anyway)
				var protected64 = Enc.strToUrlBase64(protectedHeader);
				var payload64 = Enc.bufToUrlBase64(payload);
				var msg = protected64 + '.' + payload64;

				return Keypairs._sign(opts, msg).then(function(buf) {
					var signedMsg = {
						protected: protected64,
						payload: payload64,
						signature: Enc.bufToUrlBase64(buf)
					};

					return signedMsg;
				});
			}

			if (opts.jwk) {
				return sign();
			} else {
				return Keypairs.import({ pem: opts.pem }).then(function(pair) {
					opts.jwk = pair.private;
					return sign();
				});
			}
		});
	};

	Keypairs._sign = function(opts, payload) {
		return Keypairs._import(opts).then(function(privkey) {
			if ('string' === typeof payload) {
				payload = new TextEncoder().encode(payload);
			}
			return window.crypto.subtle
				.sign(
					{
						name: Keypairs._getName(opts),
						hash: { name: 'SHA-' + Keypairs._getBits(opts) }
					},
					privkey,
					payload
				)
				.then(function(signature) {
					signature = new Uint8Array(signature); // ArrayBuffer -> u8
					// This will come back into play for CSRs, but not for JOSE
					if (
						'EC' === opts.jwk.kty &&
						/x509|asn1/i.test(opts.format)
					) {
						return Keypairs._ecdsaJoseSigToAsn1Sig(signature);
					} else {
						// jose/jws/jwt
						return signature;
					}
				});
		});
	};
	Keypairs._getBits = function(opts) {
		if (opts.alg) {
			return opts.alg.replace(/[a-z\-]/gi, '');
		}
		// base64 len to byte len
		var len = Math.floor((opts.jwk.n || '').length * 0.75);

		// TODO this may be a bug
		// need to confirm that the padding is no more or less than 1 byte
		if (/521/.test(opts.jwk.crv) || len >= 511) {
			return '512';
		} else if (/384/.test(opts.jwk.crv) || len >= 383) {
			return '384';
		}

		return '256';
	};
	Keypairs._getName = function(opts) {
		if (/EC/i.test(opts.jwk.kty)) {
			return 'ECDSA';
		} else {
			return 'RSASSA-PKCS1-v1_5';
		}
	};
	Keypairs._import = function(opts) {
		return Promise.resolve().then(function() {
			var ops;
			// all private keys just happen to have a 'd'
			if (opts.jwk.d) {
				ops = ['sign'];
			} else {
				ops = ['verify'];
			}
			// gotta mark it as extractable, as if it matters
			opts.jwk.ext = true;
			opts.jwk.key_ops = ops;

			return window.crypto.subtle
				.importKey(
					'jwk',
					opts.jwk,
					{
						name: Keypairs._getName(opts),
						namedCurve: opts.jwk.crv,
						hash: { name: 'SHA-' + Keypairs._getBits(opts) }
					},
					true,
					ops
				)
				.then(function(privkey) {
					delete opts.jwk.ext;
					return privkey;
				});
		});
	};
	// ECDSA JOSE / JWS / JWT signatures differ from "normal" ASN1/X509 ECDSA signatures
	// https://tools.ietf.org/html/rfc7518#section-3.4
	Keypairs._ecdsaJoseSigToAsn1Sig = function(bufsig) {
		// it's easier to do the manipulation in the browser with an array
		bufsig = Array.from(bufsig);
		var hlen = bufsig.length / 2; // should be even
		var r = bufsig.slice(0, hlen);
		var s = bufsig.slice(hlen);
		// unpad positive ints less than 32 bytes wide
		while (!r[0]) {
			r = r.slice(1);
		}
		while (!s[0]) {
			s = s.slice(1);
		}
		// pad (or re-pad) ambiguously non-negative BigInts, up to 33 bytes wide
		if (0x80 & r[0]) {
			r.unshift(0);
		}
		if (0x80 & s[0]) {
			s.unshift(0);
		}

		var len = 2 + r.length + 2 + s.length;
		var head = [0x30];
		// hard code 0x80 + 1 because it won't be longer than
		// two SHA512 plus two pad bytes (130 bytes <= 256)
		if (len >= 0x80) {
			head.push(0x81);
		}
		head.push(len);

		return Uint8Array.from(
			head.concat([0x02, r.length], r, [0x02, s.length], s)
		);
	};

	function setTime(time) {
		if ('number' === typeof time) {
			return time;
		}

		var t = time.match(/^(\-?\d+)([dhms])$/i);
		if (!t || !t[0]) {
			throw new Error(
				"'" +
					time +
					"' should be datetime in seconds or human-readable format (i.e. 3d, 1h, 15m, 30s"
			);
		}

		var now = Math.round(Date.now() / 1000);
		var num = parseInt(t[1], 10);
		var unit = t[2];
		var mult = 1;
		switch (unit) {
			// fancy fallthrough, what fun!
			case 'd':
				mult *= 24;
			/*falls through*/
			case 'h':
				mult *= 60;
			/*falls through*/
			case 'm':
				mult *= 60;
			/*falls through*/
			case 's':
				mult *= 1;
		}

		return now + mult * num;
	}

	Enc.hexToBuf = function(hex) {
		var arr = [];
		hex.match(/.{2}/g).forEach(function(h) {
			arr.push(parseInt(h, 16));
		});
		return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
	};
	Enc.strToUrlBase64 = function(str) {
		return Enc.bufToUrlBase64(Enc.binToBuf(str));
	};
	Enc.binToBuf = function(bin) {
		var arr = bin.split('').map(function(ch) {
			return ch.charCodeAt(0);
		});
		return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
	};
})('undefined' !== typeof module ? module.exports : window);
