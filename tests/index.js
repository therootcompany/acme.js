'use strict';

var ACME = require('../');
var Keypairs = require('../lib/keypairs.js');
var acme = ACME.create({});

var config = {
	env: process.env.ENV,
	email: process.env.SUBSCRIBER_EMAIL,
	domain: process.env.BASE_DOMAIN
};
config.debug = !/^PROD/i.test(config.env);

async function happyPath() {
	var domains = randomDomains();
	var agreed = false;
	var metadata = await acme.init(
		'https://acme-staging-v02.api.letsencrypt.org/directory'
	);

	// Ready to use, show page
	if (config.debug) {
		console.info('ACME.js initialized');
		console.info(metadata);
		console.info('');
		console.info();
	}

	// EC for account (but RSA for cert, for testing both)
	var accountKeypair = await Keypairs.generate({ kty: 'EC' });
	if (config.debug) {
		console.info('Account Key Created');
		console.info(JSON.stringify(accountKeypair, null, 2));
		console.info('');
		console.info();
	}

	var account = await acme.accounts.create({
		agreeToTerms: agree,
		// TODO detect jwk/pem/der?
		accountKeypair: { privateKeyJwk: accountKeypair.private },
		email: config.email
	});
	// TODO top-level agree
	function agree(tos) {
		if (config.debug) {
			console.info('Agreeing to Terms of Service:');
			console.info(tos);
			console.info('');
			console.info();
		}
		agreed = true;
		return Promise.resolve(tos);
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

	var serverKeypair = await Keypairs.generate({ kty: 'RSA' });
	if (config.debug) {
		console.info('Server Key Created');
		console.info(JSON.stringify(serverKeypair, null, 2));
		console.info('');
		console.info();
	}
}

happyPath()
	.then(function() {
		console.info('success');
	})
	.catch(function(err) {
		console.error('Error:');
		console.error(err.stack);
	});

function randomDomains() {
	var rnd = random();
	return ['foo-acmejs', 'bar-acmejs', '*.baz-acmejs', 'baz-acmejs'].map(
		function(pre) {
			return pre + '-' + rnd + '.' + config.domain;
		}
	);
}

function random() {
	return parseInt(
		Math.random()
			.toString()
			.slice(2, 99),
		10
	)
		.toString(16)
		.slice(0, 4);
}
