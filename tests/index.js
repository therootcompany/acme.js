'use strict';

require('dotenv').config();

var ACME = require('../');
var Keypairs = require('../lib/keypairs.js');
var acme = ACME.create({ debug: true });

// TODO exec npm install --save-dev CHALLENGE_MODULE

var config = {
	env: process.env.ENV,
	email: process.env.SUBSCRIBER_EMAIL,
	domain: process.env.BASE_DOMAIN,
	challengeType: process.env.CHALLENGE_TYPE,
	challengeModule: process.env.CHALLENGE_MODULE,
	challengeOptions: JSON.parse(process.env.CHALLENGE_OPTIONS)
};
config.debug = !/^PROD/i.test(config.env);
config.challenger = require('acme-' +
	config.challengeType +
	'-' +
	config.challengeModule).create(config.challengeOptions);
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

async function happyPath() {
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
		console.info();
		console.info();
	}

	var domains = randomDomains();
	if (config.debug) {
		console.info('Get certificates for random domains:');
		console.info(domains);
	}
	var results = await acme.certificates.create({
		account: account,
		accountKeypair: { privateKeyJwk: accountKeypair.private },
		serverKeypair: { privateKeyJwk: serverKeypair.private },
		domains: domains,
		challenges: challenges, // must be implemented
		skipDryRun: true
	});

	if (config.debug) {
		console.info('Got SSL Certificate:');
		console.info(results.expires);
		console.info(results.cert);
		console.info(results.chain);
		console.info('');
		console.info('');
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
