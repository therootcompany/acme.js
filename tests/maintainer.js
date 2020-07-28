'use strict';

var native = require('../lib/native.js');
var crypto = require('crypto');

native
	._hashcash({
		alg: 'SHA-256',
		nonce: '00',
		needle: '0000',
		start: 0,
		end: 2
	})
	.then(function (hashcash) {
		if ('00:76de' !== hashcash) {
			throw new Error('hashcash algorthim changed');
		}
		console.info('PASS: known hash solves correctly');

		return native
			._hashcash({
				alg: 'SHA-256',
				nonce: '10',
				needle: '',
				start: 0,
				end: 2
			})
			.then(function (hashcash) {
				if ('10:00' !== hashcash) {
					throw new Error('hashcash algorthim changed');
				}
				console.info('PASS: empty hash solves correctly');

				var now = Date.now();
				var nonce = '20';
				var needle = crypto.randomBytes(3).toString('hex').slice(0, 5);
				native
					._hashcash({
						alg: 'SHA-256',
						nonce: nonce,
						needle: needle,
						start: 0,
						end: Math.ceil(needle.length / 2)
					})
					.then(function (hashcash) {
						var later = Date.now();
						var parts = hashcash.split(':');
						var answer = parts[1];
						if (parts[0] !== nonce) {
							throw new Error('incorrect nonce');
						}
						var haystack = crypto
							.createHash('sha256')
							.update(Buffer.from(nonce + answer, 'hex'))
							.digest()
							.slice(0, Math.ceil(needle.length / 2));
						if (
							-1 === haystack.indexOf(Buffer.from(needle, 'hex'))
						) {
							throw new Error('incorrect solution');
						}
						if (later - now > 2000) {
							throw new Error('took too long to solve');
						}
						console.info(
							'PASS: rando hash solves correctly (and in good time - %dms)',
							later - now
						);
					});
			});
	});
