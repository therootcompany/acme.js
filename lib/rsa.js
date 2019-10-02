/*global Promise*/
(function(exports) {
	'use strict';

	var RSA = (exports.Rasha = {});
	var x509 = exports.x509;
	if ('undefined' !== typeof module) {
		module.exports = RSA;
	}
	var PEM = exports.PEM;
	var SSH = exports.SSH;
	var Enc = {};
	var textEncoder = new TextEncoder();

	RSA._stance =
		"We take the stance that if you're knowledgeable enough to" +
		" properly and securely use non-standard crypto then you shouldn't need Bluecrypt anyway.";
	RSA._universal =
		'Bluecrypt only supports crypto with standard cross-browser and cross-platform support.';
	RSA.generate = function(opts) {
		var wcOpts = {};
		if (!opts) {
			opts = {};
		}
		if (!opts.kty) {
			opts.kty = 'RSA';
		}

		// Support PSS? I don't think it's used for Let's Encrypt
		wcOpts.name = 'RSASSA-PKCS1-v1_5';
		if (!opts.modulusLength) {
			opts.modulusLength = 2048;
		}
		wcOpts.modulusLength = opts.modulusLength;
		if (wcOpts.modulusLength >= 2048 && wcOpts.modulusLength < 3072) {
			// erring on the small side... for no good reason
			wcOpts.hash = { name: 'SHA-256' };
		} else if (
			wcOpts.modulusLength >= 3072 &&
			wcOpts.modulusLength < 4096
		) {
			wcOpts.hash = { name: 'SHA-384' };
		} else if (wcOpts.modulusLength < 4097) {
			wcOpts.hash = { name: 'SHA-512' };
		} else {
			// Public key thumbprints should be paired with a hash of similar length,
			// so anything above SHA-512's keyspace would be left under-represented anyway.
			return Promise.Reject(
				new Error(
					"'" +
						wcOpts.modulusLength +
						"' is not within the safe and universally" +
						' acceptable range of 2048-4096. Typically you should pick 2048, 3072, or 4096, though other values' +
						' divisible by 8 are allowed. ' +
						RSA._stance
				)
			);
		}
		// TODO maybe allow this to be set to any of the standard values?
		wcOpts.publicExponent = new Uint8Array([0x01, 0x00, 0x01]);

		var extractable = true;
		return window.crypto.subtle
			.generateKey(wcOpts, extractable, ['sign', 'verify'])
			.then(function(result) {
				return window.crypto.subtle
					.exportKey('jwk', result.privateKey)
					.then(function(privJwk) {
						return {
							private: privJwk,
							public: RSA.neuter({ jwk: privJwk })
						};
					});
			});
	};

	// Chopping off the private parts is now part of the public API.
	// I thought it sounded a little too crude at first, but it really is the best name in every possible way.
	RSA.neuter = function(opts) {
		// trying to find the best balance of an immutable copy with custom attributes
		var jwk = {};
		Object.keys(opts.jwk).forEach(function(k) {
			if ('undefined' === typeof opts.jwk[k]) {
				return;
			}
			// ignore RSA private parts
			if (-1 !== ['d', 'p', 'q', 'dp', 'dq', 'qi'].indexOf(k)) {
				return;
			}
			jwk[k] = JSON.parse(JSON.stringify(opts.jwk[k]));
		});
		return jwk;
	};

	// https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk
	RSA.__thumbprint = function(jwk) {
		// Use the same entropy for SHA as for key
		var len = Math.floor(jwk.n.length * 0.75);
		var alg = 'SHA-256';
		// TODO this may be a bug
		// need to confirm that the padding is no more or less than 1 byte
		if (len >= 511) {
			alg = 'SHA-512';
		} else if (len >= 383) {
			alg = 'SHA-384';
		}
		return window.crypto.subtle
			.digest(
				{ name: alg },
				textEncoder.encode(
					'{"e":"' + jwk.e + '","kty":"RSA","n":"' + jwk.n + '"}'
				)
			)
			.then(function(hash) {
				return Enc.bufToUrlBase64(new Uint8Array(hash));
			});
	};

	RSA.thumbprint = function(opts) {
		return Promise.resolve().then(function() {
			var jwk;
			if ('EC' === opts.kty) {
				jwk = opts;
			} else if (opts.jwk) {
				jwk = opts.jwk;
			} else {
				return RSA.import(opts).then(function(jwk) {
					return RSA.__thumbprint(jwk);
				});
			}
			return RSA.__thumbprint(jwk);
		});
	};

	RSA.export = function(opts) {
		return Promise.resolve().then(function() {
			if (!opts || !opts.jwk || 'object' !== typeof opts.jwk) {
				throw new Error('must pass { jwk: jwk }');
			}
			var jwk = JSON.parse(JSON.stringify(opts.jwk));
			var format = opts.format;
			var pub = opts.public;
			if (
				pub ||
				-1 !== ['spki', 'pkix', 'ssh', 'rfc4716'].indexOf(format)
			) {
				jwk = RSA.neuter({ jwk: jwk });
			}
			if ('RSA' !== jwk.kty) {
				throw new Error("options.jwk.kty must be 'RSA' for RSA keys");
			}
			if (!jwk.p) {
				// TODO test for n and e
				pub = true;
				if (!format || 'pkcs1' === format) {
					format = 'pkcs1';
				} else if (-1 !== ['spki', 'pkix'].indexOf(format)) {
					format = 'spki';
				} else if (-1 !== ['ssh', 'rfc4716'].indexOf(format)) {
					format = 'ssh';
				} else {
					throw new Error(
						"options.format must be 'spki', 'pkcs1', or 'ssh' for public RSA keys, not (" +
							typeof format +
							') ' +
							format
					);
				}
			} else {
				// TODO test for all necessary keys (d, p, q ...)
				if (!format || 'pkcs1' === format) {
					format = 'pkcs1';
				} else if ('pkcs8' !== format) {
					throw new Error(
						"options.format must be 'pkcs1' or 'pkcs8' for private RSA keys"
					);
				}
			}

			if ('pkcs1' === format) {
				if (jwk.d) {
					return PEM.packBlock({
						type: 'RSA PRIVATE KEY',
						bytes: x509.packPkcs1(jwk)
					});
				} else {
					return PEM.packBlock({
						type: 'RSA PUBLIC KEY',
						bytes: x509.packPkcs1(jwk)
					});
				}
			} else if ('pkcs8' === format) {
				return PEM.packBlock({
					type: 'PRIVATE KEY',
					bytes: x509.packPkcs8(jwk)
				});
			} else if (-1 !== ['spki', 'pkix'].indexOf(format)) {
				return PEM.packBlock({
					type: 'PUBLIC KEY',
					bytes: x509.packSpki(jwk)
				});
			} else if (-1 !== ['ssh', 'rfc4716'].indexOf(format)) {
				return SSH.pack({ jwk: jwk, comment: opts.comment });
			} else {
				throw new Error(
					'Sanity Error: reached unreachable code block with format: ' +
						format
				);
			}
		});
	};
	RSA.pack = function(opts) {
		// wrapped in a promise for API compatibility
		// with the forthcoming browser version
		// (and potential future native node capability)
		return Promise.resolve().then(function() {
			return RSA.export(opts);
		});
	};

	Enc.bufToUrlBase64 = function(u8) {
		return Enc.bufToBase64(u8)
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	};

	Enc.bufToBase64 = function(u8) {
		var bin = '';
		u8.forEach(function(i) {
			bin += String.fromCharCode(i);
		});
		return btoa(bin);
	};
})('undefined' !== typeof module ? module.exports : window);
