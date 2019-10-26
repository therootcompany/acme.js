async function main() {
	'use strict';

	require('dotenv').config();

	var fs = require('fs');
	// just to trigger the warning message out of the way
	await fs.promises.readFile().catch(function() {});
	console.warn('\n');
	var MY_DOMAINS = process.env.DOMAINS.split(/[,\s]+/);

	// In many cases all three of these are the same (your email)
	// However, this is what they may look like when different:

	var maintainerEmail = process.env.MAINTAINER_EMAIL;
	var subscriberEmail = process.env.SUBSCRIBER_EMAIL;
	//var customerEmail = 'jane.doe@gmail.com';

	var pkg = require('../package.json');
	var packageAgent = 'test-' + pkg.name + '/' + pkg.version;

	// Choose either the production or staging URL

	var directoryUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
	//var directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory'

	// This is intended to get at important messages without
	// having to use even lower-level APIs in the code

	var errors = [];
	function notify(ev, msg) {
		if ('error' === ev || 'warning' === ev) {
			errors.push(ev.toUpperCase() + ' ' + msg.message);
			return;
		}
		// ignore all for now
		console.log(ev, msg.altname || '', msg.status || '');
	}

	var Keypairs = require('@root/keypairs');

	var ACME = require('../');
	var acme = ACME.create({ maintainerEmail, packageAgent, notify });
	await acme.init(directoryUrl);

	// You only need ONE account key, ever, in most cases
	// save this and keep it safe. ECDSA is preferred.

	var accountKeypair = await Keypairs.generate({ kty: 'EC', format: 'jwk' });
	var accountKey = accountKeypair.private;

	// This can be `true` or an async function which presents the terms of use

	var agreeToTerms = true;

	// If you are multi-tenanted or white-labled and need to present the terms of
	// use to the Subscriber running the service, you can do so with a function.
	var agreeToTerms = async function() {
		return true;
	};

	console.info('registering new ACME account...');
	var account = await acme.accounts.create({
		subscriberEmail,
		agreeToTerms,
		accountKey
	});
	console.info('created account with id', account.key.kid);

	// This is the key used by your WEBSERVER, typically named `privkey.pem`,
	// `key.crt`, or `bundle.pem`. RSA may be preferrable for legacy compatibility.

	// You can generate it fresh
	var serverKeypair = await Keypairs.generate({ kty: 'RSA', format: 'jwk' });
	var serverKey = serverKeypair.private;
	var serverPem = await Keypairs.export({ jwk: serverKey });
	await fs.promises.writeFile('./privkey.pem', serverPem, 'ascii');
	console.info('wrote ./privkey.pem');

	// Or you can load it from a file
	var serverPem = await fs.promises.readFile('./privkey.pem', 'ascii');

	var serverKey = await Keypairs.import({ pem: serverPem });

	var CSR = require('@root/csr');
	var PEM = require('@root/pem');
	var Enc = require('@root/encoding/base64');

	var encoding = 'der';
	var typ = 'CERTIFICATE REQUEST';

	var domains = MY_DOMAINS;
	var csrDer = await CSR.csr({ jwk: serverKey, domains, encoding });
	//var csr64 = Enc.bufToBase64(csrDer);
	var csr = PEM.packBlock({ type: typ, bytes: csrDer });

	// You can pick from existing challenge modules
	// which integrate with a variety of popular services
	// or you can create your own.
	//
	// The order of priority will be http-01, tls-alpn-01, dns-01
	// dns-01 will always be used for wildcards
	// dns-01 should be the only option given for local/private domains

	var challenges = {
		'dns-01': loadDns01()
	};

	console.info('validating domain authorization for ' + domains.join(' '));
	var pems = await acme.certificates.create({
		account,
		accountKey,
		csr,
		domains,
		challenges
	});
	var fullchain = pems.cert + '\n' + pems.chain + '\n';

	await fs.promises.writeFile('fullchain.pem', fullchain, 'ascii');
	console.info('wrote ./fullchain.pem');
	if (errors.length) {
		console.warn();
		console.warn('[Warning]');
		console.warn('The following warnings and/or errors were encountered:');
		console.warn(errors.join('\n'));
	}
}

main().catch(function(e) {
	console.error(e.stack);
});

function loadDns01() {
	var pluginName = process.env.CHALLENGE_PLUGIN;
	var pluginOptions = process.env.CHALLENGE_OPTIONS;
	var plugin;
	if (!pluginOptions) {
		console.error(
			'Please create a .env in the format of examples/example.env to run the tests'
		);
		process.exit(1);
	}
	try {
		plugin = require(pluginName);
	} catch (err) {
		console.error("Couldn't find '" + pluginName + "'. Is it installed?");
		console.error("\tnpm install --save-dev '" + pluginName + "'");
		process.exit(1);
	}
	return plugin.create(JSON.parse(pluginOptions));
}
