/*global Promise*/
(function() {
	'use strict';

	var Keypairs = require('@root/keypairs');
	var Rasha = require('@root/acme/rsa');
	var Eckles = require('@root/acme/ecdsa');
	var x509 = require('@root/acme/x509');
	var CSR = require('@root/csr');
	var ACME = require('@root/acme');
	var accountStuff = {};

	function $(sel) {
		return document.querySelector(sel);
	}
	function $$(sel) {
		return Array.prototype.slice.call(document.querySelectorAll(sel));
	}

	function checkTos(tos) {
		if ($('input[name="tos"]:checked')) {
			return tos;
		} else {
			return '';
		}
	}

	function run() {
		console.log('hello');

		// Show different options for ECDSA vs RSA
		$$('input[name="kty"]').forEach(function($el) {
			$el.addEventListener('change', function(ev) {
				console.log(this);
				console.log(ev);
				if ('RSA' === ev.target.value) {
					$('.js-rsa-opts').hidden = false;
					$('.js-ec-opts').hidden = true;
				} else {
					$('.js-rsa-opts').hidden = true;
					$('.js-ec-opts').hidden = false;
				}
			});
		});

		// Generate a key on submit
		$('form.js-keygen').addEventListener('submit', function(ev) {
			ev.preventDefault();
			ev.stopPropagation();
			$('.js-loading').hidden = false;
			$('.js-jwk').hidden = true;
			$('.js-toc-der-public').hidden = true;
			$('.js-toc-der-private').hidden = true;
			$$('.js-toc-pem').forEach(function($el) {
				$el.hidden = true;
			});
			$$('input').map(function($el) {
				$el.disabled = true;
			});
			$$('button').map(function($el) {
				$el.disabled = true;
			});
			var opts = {
				kty: $('input[name="kty"]:checked').value,
				namedCurve: $('input[name="ec-crv"]:checked').value,
				modulusLength: $('input[name="rsa-len"]:checked').value
			};
			var then = Date.now();
			console.log('opts', opts);
			Keypairs.generate(opts).then(function(results) {
				console.log('Key generation time:', Date.now() - then + 'ms');
				var pubDer;
				var privDer;
				if (/EC/i.test(opts.kty)) {
					privDer = x509.packPkcs8(results.private);
					pubDer = x509.packSpki(results.public);
					Eckles.export({
						jwk: results.private,
						format: 'sec1'
					}).then(function(pem) {
						$('.js-input-pem-sec1-private').innerText = pem;
						$('.js-toc-pem-sec1-private').hidden = false;
					});
					Eckles.export({
						jwk: results.private,
						format: 'pkcs8'
					}).then(function(pem) {
						$('.js-input-pem-pkcs8-private').innerText = pem;
						$('.js-toc-pem-pkcs8-private').hidden = false;
					});
					Eckles.export({ jwk: results.public, public: true }).then(
						function(pem) {
							$('.js-input-pem-spki-public').innerText = pem;
							$('.js-toc-pem-spki-public').hidden = false;
						}
					);
				} else {
					privDer = x509.packPkcs8(results.private);
					pubDer = x509.packSpki(results.public);
					Rasha.export({
						jwk: results.private,
						format: 'pkcs1'
					}).then(function(pem) {
						$('.js-input-pem-pkcs1-private').innerText = pem;
						$('.js-toc-pem-pkcs1-private').hidden = false;
					});
					Rasha.export({
						jwk: results.private,
						format: 'pkcs8'
					}).then(function(pem) {
						$('.js-input-pem-pkcs8-private').innerText = pem;
						$('.js-toc-pem-pkcs8-private').hidden = false;
					});
					Rasha.export({ jwk: results.public, format: 'pkcs1' }).then(
						function(pem) {
							$('.js-input-pem-pkcs1-public').innerText = pem;
							$('.js-toc-pem-pkcs1-public').hidden = false;
						}
					);
					Rasha.export({ jwk: results.public, format: 'spki' }).then(
						function(pem) {
							$('.js-input-pem-spki-public').innerText = pem;
							$('.js-toc-pem-spki-public').hidden = false;
						}
					);
				}

				$('.js-der-public').innerText = pubDer;
				$('.js-toc-der-public').hidden = false;
				$('.js-der-private').innerText = privDer;
				$('.js-toc-der-private').hidden = false;
				$('.js-jwk').innerText = JSON.stringify(results, null, 2);
				$('.js-loading').hidden = true;
				$('.js-jwk').hidden = false;
				$$('input').map(function($el) {
					$el.disabled = false;
				});
				$$('button').map(function($el) {
					$el.disabled = false;
				});
				$('.js-toc-jwk').hidden = false;

				$('.js-create-account').hidden = false;
				$('.js-create-csr').hidden = false;
			});
		});

		$('form.js-acme-account').addEventListener('submit', function(ev) {
			ev.preventDefault();
			ev.stopPropagation();
			$('.js-loading').hidden = false;
			var acme = ACME.create({
				Keypairs: Keypairs,
				CSR: CSR
			});
			acme.init(
				'https://acme-staging-v02.api.letsencrypt.org/directory'
			).then(function(result) {
				console.log('acme result', result);
				var privJwk = JSON.parse($('.js-jwk').innerText).private;
				var email = $('.js-email').value;
				return acme.accounts
					.create({
						email: email,
						agreeToTerms: checkTos,
						accountKeypair: { privateKeyJwk: privJwk }
					})
					.then(function(account) {
						console.log('account created result:', account);
						accountStuff.account = account;
						accountStuff.privateJwk = privJwk;
						accountStuff.email = email;
						accountStuff.acme = acme;
						$('.js-create-order').hidden = false;
						$('.js-toc-acme-account-response').hidden = false;
						$(
							'.js-acme-account-response'
						).innerText = JSON.stringify(account, null, 2);
					})
					.catch(function(err) {
						console.error('A bad thing happened:');
						console.error(err);
						window.alert(
							err.message || JSON.stringify(err, null, 2)
						);
					});
			});
		});

		$('form.js-csr').addEventListener('submit', function(ev) {
			ev.preventDefault();
			ev.stopPropagation();
			generateCsr();
		});

		$('form.js-acme-order').addEventListener('submit', function(ev) {
			ev.preventDefault();
			ev.stopPropagation();
			var account = accountStuff.account;
			var privJwk = accountStuff.privateJwk;
			var email = accountStuff.email;
			var acme = accountStuff.acme;

			var domains = ($('.js-domains').value || 'example.com').split(
				/[, ]+/g
			);
			return getDomainPrivkey().then(function(domainPrivJwk) {
				console.log('Has CSR already?');
				console.log(accountStuff.csr);
				return acme.certificates
					.create({
						accountKeypair: { privateKeyJwk: privJwk },
						account: account,
						serverKeypair: { privateKeyJwk: domainPrivJwk },
						csr: accountStuff.csr,
						domains: domains,
						skipDryRun:
							$('input[name="skip-dryrun"]:checked') && true,
						agreeToTerms: checkTos,
						challenges: {
							'dns-01': {
								set: function(opts) {
									console.info('dns-01 set challenge:');
									console.info('TXT', opts.dnsHost);
									console.info(opts.dnsAuthorization);
									return new Promise(function(resolve) {
										while (
											!window.confirm(
												'Did you set the challenge?'
											)
										) {}
										resolve();
									});
								},
								remove: function(opts) {
									console.log('dns-01 remove challenge:');
									console.info('TXT', opts.dnsHost);
									console.info(opts.dnsAuthorization);
									return new Promise(function(resolve) {
										while (
											!window.confirm(
												'Did you delete the challenge?'
											)
										) {}
										resolve();
									});
								}
							},
							'http-01': {
								set: function(opts) {
									console.info('http-01 set challenge:');
									console.info(opts.challengeUrl);
									console.info(opts.keyAuthorization);
									return new Promise(function(resolve) {
										while (
											!window.confirm(
												'Did you set the challenge?'
											)
										) {}
										resolve();
									});
								},
								remove: function(opts) {
									console.log('http-01 remove challenge:');
									console.info(opts.challengeUrl);
									console.info(opts.keyAuthorization);
									return new Promise(function(resolve) {
										while (
											!window.confirm(
												'Did you delete the challenge?'
											)
										) {}
										resolve();
									});
								}
							}
						},
						challengeTypes: [
							$('input[name="acme-challenge-type"]:checked').value
						]
					})
					.then(function(results) {
						console.log('Got Certificates:');
						console.log(results);
						$('.js-toc-acme-order-response').hidden = false;
						$('.js-acme-order-response').innerText = JSON.stringify(
							results,
							null,
							2
						);
					})
					.catch(function(err) {
						console.error('challenge failed:');
						console.error(err);
						window.alert(
							'failed! ' + err.message || JSON.stringify(err)
						);
					});
			});
		});

		$('.js-generate').hidden = false;
	}

	function getDomainPrivkey() {
		if (accountStuff.domainPrivateJwk) {
			return Promise.resolve(accountStuff.domainPrivateJwk);
		}
		return Keypairs.generate({
			kty: $('input[name="kty"]:checked').value,
			namedCurve: $('input[name="ec-crv"]:checked').value,
			modulusLength: $('input[name="rsa-len"]:checked').value
		}).then(function(pair) {
			console.log('domain keypair:', pair);
			accountStuff.domainPrivateJwk = pair.private;
			return pair.private;
		});
	}

	function generateCsr() {
		var domains = ($('.js-domains').value || 'example.com').split(/[, ]+/g);
		//var privJwk = JSON.parse($('.js-jwk').innerText).private;
		return getDomainPrivkey().then(function(privJwk) {
			accountStuff.domainPrivateJwk = privJwk;
			return CSR({ jwk: privJwk, domains: domains }).then(function(pem) {
				// Verify with https://www.sslshopper.com/csr-decoder.html
				accountStuff.csr = pem;
				console.log('Created CSR:');
				console.log(pem);

				console.log('CSR info:');
				console.log(CSR._info(pem));

				return pem;
			});
		});
	}

	window.addEventListener('load', run);
})();
