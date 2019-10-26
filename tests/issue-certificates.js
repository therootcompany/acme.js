'use strict';

require('dotenv').config();

var pkg = require('../package.json');
var CSR = require('@root/csr');
var Enc = require('@root/encoding/base64');
var PEM = require('@root/pem');
var punycode = require('punycode');
var ACME = require('../acme.js');
var Keypairs = require('@root/keypairs');
var ecJwk = require('../fixtures/account.jwk.json');

// TODO exec npm install --save-dev CHALLENGE_MODULE
if (!process.env.CHALLENGE_OPTIONS) {
	console.error(
		'Please create a .env in the format of examples/example.env to run the tests'
	);
	process.exit(1);
}

var config = {
	env: process.env.ENV,
	email: process.env.SUBSCRIBER_EMAIL,
	domain: process.env.BASE_DOMAIN,
	challengeType: process.env.CHALLENGE_TYPE,
	challengeModule: process.env.CHALLENGE_PLUGIN,
	challengeOptions: JSON.parse(process.env.CHALLENGE_OPTIONS)
};
//config.debug = !/^PROD/i.test(config.env);
var pluginPrefix = 'acme-' + config.challengeType + '-';
var pluginName = config.challengeModule;
var plugin;

module.exports = function() {
	console.info('\n[Test] end-to-end issue certificates');

	var acme = ACME.create({
		// debug: true
		maintainerEmail: config.email,
		packageAgent: 'test-' + pkg.name + '/' + pkg.version,
		notify: function(ev, params) {
			console.info(
				'\t' + ev,
				params.subject || params.altname || params.domain || '',
				params.status || ''
			);
			if ('error' === ev) {
				console.error(params.action || params.type || '');
				console.error(params);
			}
		}
	});

	function badPlugin(err) {
		if ('MODULE_NOT_FOUND' !== err.code) {
			console.error(err);
			return;
		}
		console.error("Couldn't find '" + pluginName + "'. Is it installed?");
		console.error("\tnpm install --save-dev '" + pluginName + "'");
	}
	try {
		plugin = require(pluginName);
	} catch (err) {
		if (
			'MODULE_NOT_FOUND' !== err.code ||
			0 === pluginName.indexOf(pluginPrefix)
		) {
			badPlugin(err);
			process.exit(1);
		}
		try {
			pluginName = pluginPrefix + pluginName;
			plugin = require(pluginName);
		} catch (e) {
			badPlugin(e);
			process.exit(1);
		}
	}

	config.challenger = plugin.create(config.challengeOptions);
	if (!config.challengeType || !config.domain) {
		console.error(
			new Error('Missing config variables. Check you .env and the docs')
				.message
		);
		console.error(config);
		process.exit(1);
	}

	var challenges = {};
	challenges[config.challengeType] = config.challenger;

	async function happyPath(accKty, srvKty, rnd) {
		var agreed = false;
		var metadata = await acme.init(
			'https://acme-staging-v02.api.letsencrypt.org/directory'
		);

		// Ready to use, show page
		if (config.debug) {
			console.info('ACME.js initialized');
			console.info(metadata);
			console.info();
			console.info();
		}

		var accountKeypair = await Keypairs.generate({ kty: accKty });
		if (/EC/i.test(accKty)) {
			// to test that an existing account gets back data
			accountKeypair = ecJwk;
		}
		var accountKey = accountKeypair.private;
		if (config.debug) {
			console.info('Account Key Created');
			console.info(JSON.stringify(accountKey, null, 2));
			console.info();
			console.info();
		}

		var account = await acme.accounts.create({
			agreeToTerms: agree,
			// TODO detect jwk/pem/der?
			accountKey: accountKey,
			subscriberEmail: config.email
		});

		// TODO top-level agree
		function agree(tos) {
			if (config.debug) {
				console.info('Agreeing to Terms of Service:');
				console.info(tos);
				console.info();
				console.info();
			}
			agreed = true;
			return Promise.resolve(agreed);
		}
		if (config.debug) {
			console.info('New Subscriber Account');
			console.info(JSON.stringify(account, null, 2));
			console.info();
			console.info();
		}
		if (!agreed) {
			throw new Error('Failed to ask the user to agree to terms');
		}

		var certKeypair = await Keypairs.generate({ kty: srvKty });
		var pem = await Keypairs.export({
			jwk: certKeypair.private,
			encoding: 'pem'
		});
		if (config.debug) {
			console.info('Server Key Created');
			console.info('privkey.jwk.json');
			console.info(JSON.stringify(certKeypair, null, 2));
			// This should be saved as `privkey.pem`
			console.info();
			console.info('privkey.' + srvKty.toLowerCase() + '.pem:');
			console.info(pem);
			console.info();
		}

		// 'subject' should be first in list
		var domains = randomDomains(rnd);
		if (config.debug) {
			console.info('Get certificates for random domains:');
			console.info(
				domains
					.map(function(puny) {
						var uni = punycode.toUnicode(puny);
						if (puny !== uni) {
							return puny + ' (' + uni + ')';
						}
						return puny;
					})
					.join('\n')
			);
			console.info();
		}

		// Create CSR
		var csrDer = await CSR.csr({
			jwk: certKeypair.private,
			domains: domains,
			encoding: 'der'
		});
		var csr = Enc.bufToUrlBase64(csrDer);
		var csrPem = PEM.packBlock({
			type: 'CERTIFICATE REQUEST',
			bytes: csrDer /* { jwk: jwk, domains: opts.domains } */
		});
		if (config.debug) {
			console.info('Certificate Signing Request');
			console.info(csrPem);
			console.info();
		}

		var results = await acme.certificates.create({
			account: account,
			accountKey: accountKey,
			csr: csr,
			domains: domains,
			challenges: challenges, // must be implemented
			customerEmail: null
		});

		if (config.debug) {
			console.info('Got SSL Certificate:');
			console.info(Object.keys(results));
			console.info(results.expires);
			console.info(results.cert);
			console.info(results.chain);
			console.info();
			console.info();
		}
	}

	// Try EC + RSA
	var rnd = random();
	happyPath('EC', 'RSA', rnd)
		.then(function() {
			console.info('PASS: ECDSA account key with RSA server key');
			// Now try RSA + EC
			rnd = random();
			return happyPath('RSA', 'EC', rnd).then(function() {
				console.info('PASS: RSA account key with ECDSA server key');
			});
		})
		.then(function() {
			console.info('PASS');
		})
		.catch(function(err) {
			console.error('Error:');
			console.error(err.stack);
		});

	function randomDomains(rnd) {
		return ['foo-acmejs', 'bar-acmejs', '*.baz-acmejs', 'baz-acmejs'].map(
			function(pre) {
				return punycode.toASCII(pre + '-' + rnd + '.' + config.domain);
			}
		);
	}

	function random() {
		return (
			parseInt(
				Math.random()
					.toString()
					.slice(2, 99),
				10
			)
				.toString(16)
				.slice(0, 4) + '例'
		);
	}
};
