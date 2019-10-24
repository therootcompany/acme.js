'use strict';

var ACME = require('../');
var accountKey = require('../fixtures/account.jwk.json').private;

var authorization = {
	identifier: {
		type: 'dns',
		value: 'example.com'
	},
	status: 'pending',
	expires: '2018-04-25T00:23:57Z',
	challenges: [
		{
			type: 'dns-01',
			status: 'pending',
			url:
				'https://acme-staging-v02.api.letsencrypt.org/acme/challenge/cMkwXI8pIeKN04Ynfem8ErHK3GeqAPdSt2x6q7PvVGU/118755342',
			token: 'LZdlUiZ-kWPs6q5WTmQFYQHZKpz9szn2vxEUu0XhyyM'
		},
		{
			type: 'http-01',
			status: 'pending',
			url:
				'https://acme-staging-v02.api.letsencrypt.org/acme/challenge/cMkwXI8pIeKN04Ynfem8ErHK3GeqAPdSt2x6q7PvVGU/118755343',
			token: '1S4zBG5YVhwSBaIY4ksI_KNMRrSmH0DZfNM9v7PYjDU'
		}
	]
};
var expectedChallengeUrl =
	'http://example.com/.well-known/acme-challenge/1S4zBG5YVhwSBaIY4ksI_KNMRrSmH0DZfNM9v7PYjDU';
var expectedKeyAuth =
	'1S4zBG5YVhwSBaIY4ksI_KNMRrSmH0DZfNM9v7PYjDU.UuuZa_56jCM2douUq1riGyRphPtRvCPkxtkg0bP-pNs';
var expectedKeyAuthDigest = 'iQiMcQUDiAeD0TJV1RHJuGnI5D2-PuSpxKz9JqUaZ2M';
var expectedDnsHost = '_test-challenge.example.com';

async function main() {
	console.info('\n[Test] computing challenge authorizatin responses');
	var challenges = authorization.challenges.slice(0);

	function next() {
		var ch = challenges.shift();
		if (!ch) {
			return null;
		}

		var hostname = authorization.identifier.value;
		return ACME.computeChallenge({
			accountKey: accountKey,
			hostname: hostname,
			challenge: ch,
			dnsPrefix: '_test-challenge'
		})
			.then(function(auth) {
				if ('dns-01' === ch.type) {
					if (auth.keyAuthorizationDigest !== expectedKeyAuthDigest) {
						console.error('[keyAuthorizationDigest]');
						console.error(auth.keyAuthorizationDigest);
						console.error(expectedKeyAuthDigest);
						throw new Error('bad keyAuthDigest');
					}
					if (auth.dnsHost !== expectedDnsHost) {
						console.error('[dnsHost]');
						console.error(auth.dnsHost);
						console.error(expectedDnsHost);
						throw new Error('bad dnsHost');
					}
				} else if ('http-01' === ch.type) {
					if (auth.challengeUrl !== expectedChallengeUrl) {
						console.error('[challengeUrl]');
						console.error(auth.challengeUrl);
						console.error(expectedChallengeUrl);
						throw new Error('bad challengeUrl');
					}
					if (auth.challengeUrl !== expectedChallengeUrl) {
						console.error('[keyAuthorization]');
						console.error(auth.keyAuthorization);
						console.error(expectedKeyAuth);
						throw new Error('bad keyAuth');
					}
				} else {
					throw new Error('bad authorization inputs');
				}
				console.info('PASS', hostname, ch.type);
				return next();
			})
			.catch(function(err) {
				err.message =
					'Error computing ' +
					ch.type +
					' for ' +
					hostname +
					':' +
					err.message;
				throw err;
			});
	}

	return next();
}

module.exports = function() {
	return main(authorization)
		.then(function() {
			console.info('PASS');
		})
		.catch(function(err) {
			console.error(err.stack);
			process.exit(1);
		});
};
