(function(exports) {
	'use strict';

	// node[0] ./test.js[1] jon.doe@gmail.com[2] example.com,*.example.com[3] xxxxxx[4]
	var email = process.argv[2] || process.env.ACME_EMAIL;
	var domains = (process.argv[3] || process.env.ACME_DOMAINS).split(/[,\s]+/);
	var token = process.argv[4] || process.env.DIGITALOCEAN_API_KEY;

	// git clone https://git.rootprojects.org/root/acme-dns-01-digitalocean.js node_modules/acme-dns-01-digitalocean
	var dns01 = require('acme-dns-01-digitalocean').create({
		//baseUrl: 'https://api.digitalocean.com/v2/domains',
		token: token
	});

	// This will be replaced with Keypairs.js in the next version
	var promisify = require('util').promisify;
	var generateKeypair = promisify(require('rsa-compat').RSA.generateKeypair);

	//var ACME = exports.ACME || require('acme').ACME;
	var ACME = exports.ACME || require('../').ACME;
	var acme = ACME.create({});
	acme
		.init({
			//directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory'
		})
		.then(function() {
			return generateKeypair(null).then(function(accountPair) {
				return generateKeypair(null).then(function(serverPair) {
					return acme.accounts
						.create({
							// valid email (server checks MX records)
							email: email,
							accountKeypair: accountPair,
							agreeToTerms: function(tosUrl) {
								// ask user (if user is the host)
								return tosUrl;
							}
						})
						.then(function(account) {
							console.info('Created Account:');
							console.info(account);

							return acme.certificates
								.create({
									domains: domains,
									challenges: { 'dns-01': dns01 },
									domainKeypair: serverPair,
									accountKeypair: accountPair,

									// v2 will be directly compatible with the new ACME modules,
									// whereas this version needs a shim
									getZones: dns01.zones,
									setChallenge: dns01.set,
									removeChallenge: dns01.remove
								})
								.then(function(certs) {
									console.info('Secured SSL Certificates');
									console.info(certs);
								});
						});
				});
			});
		})
		.catch(function(e) {
			console.error('Something went wrong:');
			console.error(e);
			process.exit(500);
		});
})('undefined' === typeof module ? window : module.exports);
