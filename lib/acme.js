// Copyright 2018-present AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
(function(exports) {
	'use strict';
	/* globals Promise */

	var ACME = (exports.ACME = {});
	//var Keypairs = exports.Keypairs || {};
	//var CSR = exports.CSR;
	var Enc = exports.Enc || {};
	var Crypto = exports.Crypto || {};

	ACME.formatPemChain = function formatPemChain(str) {
		return (
			str
				.trim()
				.replace(/[\r\n]+/g, '\n')
				.replace(/\-\n\-/g, '-\n\n-') + '\n'
		);
	};
	ACME.splitPemChain = function splitPemChain(str) {
		return str
			.trim()
			.split(/[\r\n]{2,}/g)
			.map(function(str) {
				return str + '\n';
			});
	};

	// http-01: GET https://example.org/.well-known/acme-challenge/{{token}} => {{keyAuth}}
	// dns-01: TXT _acme-challenge.example.org. => "{{urlSafeBase64(sha256(keyAuth))}}"
	ACME.challengePrefixes = {
		'http-01': '/.well-known/acme-challenge',
		'dns-01': '_acme-challenge'
	};
	ACME.challengeTests = {
		'http-01': function(me, auth) {
			return me.http01(auth).then(function(keyAuth) {
				var err;

				// TODO limit the number of bytes that are allowed to be downloaded
				if (auth.keyAuthorization === (keyAuth || '').trim()) {
					return true;
				}

				err = new Error(
					'Error: Failed HTTP-01 Pre-Flight / Dry Run.\n' +
						"curl '" +
						auth.challengeUrl +
						"'\n" +
						"Expected: '" +
						auth.keyAuthorization +
						"'\n" +
						"Got: '" +
						keyAuth +
						"'\n" +
						'See https://git.coolaj86.com/coolaj86/acme-v2.js/issues/4'
				);
				err.code = 'E_FAIL_DRY_CHALLENGE';
				return Promise.reject(err);
			});
		},
		'dns-01': function(me, auth) {
			// remove leading *. on wildcard domains
			return me.dns01(auth).then(function(ans) {
				var err;

				if (
					ans.answer.some(function(txt) {
						return auth.dnsAuthorization === txt.data[0];
					})
				) {
					return true;
				}

				err = new Error(
					'Error: Failed DNS-01 Pre-Flight Dry Run.\n' +
						"dig TXT '" +
						auth.dnsHost +
						"' does not return '" +
						auth.dnsAuthorization +
						"'\n" +
						'See https://git.coolaj86.com/coolaj86/acme-v2.js/issues/4'
				);
				err.code = 'E_FAIL_DRY_CHALLENGE';
				return Promise.reject(err);
			});
		}
	};

	ACME._directory = function(me) {
		// GET-as-GET ok
		return me.request({ method: 'GET', url: me.directoryUrl, json: true });
	};
	ACME._getNonce = function(me) {
		// GET-as-GET, HEAD-as-HEAD ok
		var nonce;
		while (true) {
			nonce = me._nonces.shift();
			if (!nonce) {
				break;
			}
			if (Date.now() - nonce.createdAt > 15 * 60 * 1000) {
				nonce = null;
			} else {
				break;
			}
		}
		if (nonce) {
			return Promise.resolve(nonce.nonce);
		}
		return me
			.request({ method: 'HEAD', url: me._directoryUrls.newNonce })
			.then(function(resp) {
				return resp.headers['replay-nonce'];
			});
	};
	ACME._setNonce = function(me, nonce) {
		me._nonces.unshift({ nonce: nonce, createdAt: Date.now() });
	};
	// ACME RFC Section 7.3 Account Creation
	/*
 {
   "protected": base64url({
     "alg": "ES256",
     "jwk": {...},
     "nonce": "6S8IqOGY7eL2lsGoTZYifg",
     "url": "https://example.com/acme/new-account"
   }),
   "payload": base64url({
     "termsOfServiceAgreed": true,
     "onlyReturnExisting": false,
     "contact": [
       "mailto:cert-admin@example.com",
       "mailto:admin@example.com"
     ]
   }),
   "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
 }
*/
	ACME._registerAccount = function(me, options) {
		if (me.debug) {
			console.debug('[acme-v2] accounts.create');
		}

		return new Promise(function(resolve, reject) {
			function agree(tosUrl) {
				var err;
				if (me._tos !== tosUrl) {
					err = new Error(
						"You must agree to the ToS at '" + me._tos + "'"
					);
					err.code = 'E_AGREE_TOS';
					reject(err);
					return;
				}

				return ACME._importKeypair(me, options.accountKeypair).then(
					function(pair) {
						var contact;
						if (options.contact) {
							contact = options.contact.slice(0);
						} else if (options.email) {
							contact = ['mailto:' + options.email];
						}
						var body = {
							termsOfServiceAgreed: tosUrl === me._tos,
							onlyReturnExisting: false,
							contact: contact
						};
						var pExt;
						if (options.externalAccount) {
							pExt = me.Keypairs.signJws({
								// TODO is HMAC the standard, or is this arbitrary?
								secret: options.externalAccount.secret,
								protected: {
									alg: options.externalAccount.alg || 'HS256',
									kid: options.externalAccount.id,
									url: me._directoryUrls.newAccount
								},
								payload: Enc.binToBuf(
									JSON.stringify(pair.public)
								)
							}).then(function(jws) {
								body.externalAccountBinding = jws;
								return body;
							});
						} else {
							pExt = Promise.resolve(body);
						}
						return pExt.then(function(body) {
							var payload = JSON.stringify(body);
							return ACME._jwsRequest(me, {
								options: options,
								url: me._directoryUrls.newAccount,
								protected: { kid: false, jwk: pair.public },
								payload: Enc.binToBuf(payload)
							})
								.then(function(resp) {
									var account = resp.body;

									if (
										2 !== Math.floor(resp.statusCode / 100)
									) {
										throw new Error(
											'account error: ' +
												JSON.stringify(resp.body)
										);
									}

									var location = resp.headers.location;
									// the account id url
									options._kid = location;
									if (me.debug) {
										console.debug(
											'[DEBUG] new account location:'
										);
									}
									if (me.debug) {
										console.debug(location);
									}
									if (me.debug) {
										console.debug(resp);
									}

									/*
            {
              contact: ["mailto:jon@example.com"],
              orders: "https://some-url",
              status: 'valid'
            }
            */
									if (!account) {
										account = { _emptyResponse: true };
									}
									// https://git.coolaj86.com/coolaj86/acme-v2.js/issues/8
									if (!account.key) {
										account.key = {};
									}
									account.key.kid = options._kid;
									return account;
								})
								.then(resolve, reject);
						});
					}
				);
			}

			if (me.debug) {
				console.debug('[acme-v2] agreeToTerms');
			}
			if (1 === options.agreeToTerms.length) {
				// newer promise API
				return Promise.resolve(options.agreeToTerms(me._tos)).then(
					agree,
					reject
				);
			} else if (2 === options.agreeToTerms.length) {
				// backwards compat cb API
				return options.agreeToTerms(me._tos, function(err, tosUrl) {
					if (!err) {
						agree(tosUrl);
						return;
					}
					reject(err);
				});
			} else {
				reject(
					new Error(
						'agreeToTerms has incorrect function signature.' +
							' Should be fn(tos) { return Promise<tos>; }'
					)
				);
			}
		});
	};
	/*
 POST /acme/new-order HTTP/1.1
 Host: example.com
 Content-Type: application/jose+json

 {
   "protected": base64url({
     "alg": "ES256",
     "kid": "https://example.com/acme/acct/1",
     "nonce": "5XJ1L3lEkMG7tR6pA00clA",
     "url": "https://example.com/acme/new-order"
   }),
   "payload": base64url({
     "identifiers": [{"type:"dns","value":"example.com"}],
     "notBefore": "2016-01-01T00:00:00Z",
     "notAfter": "2016-01-08T00:00:00Z"
   }),
   "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
 }
*/
	ACME._getChallenges = function(me, options, authUrl) {
		if (me.debug) {
			console.debug('\n[DEBUG] getChallenges\n');
		}
		// TODO POST-as-GET

		return ACME._jwsRequest(me, {
			options: options,
			protected: {},
			payload: '',
			url: authUrl
		}).then(function(resp) {
			return resp.body;
		});
	};
	ACME._wait = function wait(ms) {
		return new Promise(function(resolve) {
			setTimeout(resolve, ms || 1100);
		});
	};

	ACME._testChallengeOptions = function() {
		var chToken = ACME._prnd(16);
		return [
			{
				type: 'http-01',
				status: 'pending',
				url: 'https://acme-staging-v02.example.com/0',
				token: 'test-' + chToken + '-0'
			},
			{
				type: 'dns-01',
				status: 'pending',
				url: 'https://acme-staging-v02.example.com/1',
				token: 'test-' + chToken + '-1',
				_wildcard: true
			},
			{
				type: 'tls-sni-01',
				status: 'pending',
				url: 'https://acme-staging-v02.example.com/2',
				token: 'test-' + chToken + '-2'
			},
			{
				type: 'tls-alpn-01',
				status: 'pending',
				url: 'https://acme-staging-v02.example.com/3',
				token: 'test-' + chToken + '-3'
			}
		];
	};
	ACME._testChallenges = function(me, options) {
		var CHECK_DELAY = 0;
		return Promise.all(
			options.domains.map(function(identifierValue) {
				// TODO we really only need one to pass, not all to pass
				var challenges = ACME._testChallengeOptions();
				if (identifierValue.includes('*')) {
					challenges = challenges.filter(function(ch) {
						return ch._wildcard;
					});
				}

				var challenge = ACME._chooseChallenge(options, {
					challenges: challenges
				});
				if (!challenge) {
					// For example, wildcards require dns-01 and, if we don't have that, we have to bail
					var enabled = options.challengeTypes.join(', ') || 'none';
					var suitable =
						challenges
							.map(function(r) {
								return r.type;
							})
							.join(', ') || 'none';
					return Promise.reject(
						new Error(
							"None of the challenge types that you've enabled ( " +
								enabled +
								' )' +
								" are suitable for validating the domain you've selected (" +
								identifierValue +
								').' +
								' You must enable one of ( ' +
								suitable +
								' ).'
						)
					);
				}

				// TODO remove skipChallengeTest
				if (me.skipDryRun || me.skipChallengeTest) {
					return null;
				}

				if ('dns-01' === challenge.type) {
					// Give the nameservers a moment to propagate
					CHECK_DELAY = 1.5 * 1000;
				}

				return Promise.resolve().then(function() {
					var results = {
						identifier: {
							type: 'dns',
							value: identifierValue.replace(/^\*\./, '')
						},
						challenges: [challenge],
						expires: new Date(Date.now() + 60 * 1000).toISOString(),
						wildcard: identifierValue.includes('*.') || undefined
					};

					// The dry-run comes first in the spirit of "fail fast"
					// (and protecting against challenge failure rate limits)
					var dryrun = true;
					return ACME._challengeToAuth(
						me,
						options,
						results,
						challenge,
						dryrun
					).then(function(auth) {
						if (!me._canUse[auth.type]) {
							return;
						}
						return ACME._setChallenge(me, options, auth).then(
							function() {
								return auth;
							}
						);
					});
				});
			})
		).then(function(auths) {
			auths = auths.filter(Boolean);
			if (!auths.length) {
				/*skip actual test*/ return;
			}
			return ACME._wait(CHECK_DELAY).then(function() {
				return Promise.all(
					auths.map(function(auth) {
						return ACME.challengeTests[auth.type](me, auth).then(
							function(result) {
								// not a blocker
								ACME._removeChallenge(me, options, auth);
								return result;
							}
						);
					})
				);
			});
		});
	};
	ACME._chooseChallenge = function(options, results) {
		// For each of the challenge types that we support
		var challenge;
		options.challengeTypes.some(function(chType) {
			// And for each of the challenge types that are allowed
			return results.challenges.some(function(ch) {
				// Check to see if there are any matches
				if (ch.type === chType) {
					challenge = ch;
					return true;
				}
			});
		});

		return challenge;
	};
	ACME._challengeToAuth = function(me, options, request, challenge, dryrun) {
		// we don't poison the dns cache with our dummy request
		var dnsPrefix = ACME.challengePrefixes['dns-01'];
		if (dryrun) {
			dnsPrefix = dnsPrefix.replace(
				'acme-challenge',
				'greenlock-dryrun-' + ACME._prnd(4)
			);
		}

		var auth = {};

		// straight copy from the new order response
		// { identifier, status, expires, challenges, wildcard }
		Object.keys(request).forEach(function(key) {
			auth[key] = request[key];
		});

		// copy from the challenge we've chosen
		// { type, status, url, token }
		// (note the duplicate status overwrites the one above, but they should be the same)
		Object.keys(challenge).forEach(function(key) {
			// don't confused devs with the id url
			auth[key] = challenge[key];
		});

		// batteries-included helpers
		auth.hostname = auth.identifier.value;
		// because I'm not 100% clear if the wildcard identifier does or doesn't have the leading *. in all cases
		auth.altname = ACME._untame(auth.identifier.value, auth.wildcard);
		return ACME._importKeypair(me, options.accountKeypair).then(function(
			pair
		) {
			return me.Keypairs.thumbprint({ jwk: pair.public }).then(function(
				thumb
			) {
				auth.thumbprint = thumb;
				//   keyAuthorization = token || '.' || base64url(JWK_Thumbprint(accountKey))
				auth.keyAuthorization = challenge.token + '.' + auth.thumbprint;
				// conflicts with ACME challenge id url is already in use, so we call this challengeUrl instead
				// TODO auth.http01Url ?
				auth.challengeUrl =
					'http://' +
					auth.identifier.value +
					ACME.challengePrefixes['http-01'] +
					'/' +
					auth.token;
				auth.dnsHost =
					dnsPrefix + '.' + auth.hostname.replace('*.', '');

				return Crypto._sha('sha256', auth.keyAuthorization).then(
					function(hash) {
						auth.dnsAuthorization = hash;
						return auth;
					}
				);
			});
		});
	};

	ACME._untame = function(name, wild) {
		if (wild) {
			name = '*.' + name.replace('*.', '');
		}
		return name;
	};

	// https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
	ACME._postChallenge = function(me, options, auth) {
		var RETRY_INTERVAL = me.retryInterval || 1000;
		var DEAUTH_INTERVAL = me.deauthWait || 10 * 1000;
		var MAX_POLL = me.retryPoll || 8;
		var MAX_PEND = me.retryPending || 4;
		var count = 0;

		var altname = ACME._untame(auth.identifier.value, auth.wildcard);

		/*
   POST /acme/authz/1234 HTTP/1.1
   Host: example.com
   Content-Type: application/jose+json

   {
     "protected": base64url({
       "alg": "ES256",
       "kid": "https://example.com/acme/acct/1",
       "nonce": "xWCM9lGbIyCgue8di6ueWQ",
       "url": "https://example.com/acme/authz/1234"
     }),
     "payload": base64url({
       "status": "deactivated"
     }),
     "signature": "srX9Ji7Le9bjszhu...WTFdtujObzMtZcx4"
   }
   */
		function deactivate() {
			if (me.debug) {
				console.debug('[acme-v2.js] deactivate:');
			}
			return ACME._jwsRequest(me, {
				options: options,
				url: auth.url,
				protected: { kid: options._kid },
				payload: Enc.binToBuf(JSON.stringify({ status: 'deactivated' }))
			}).then(function(resp) {
				if (me.debug) {
					console.debug('deactivate challenge: resp.body:');
				}
				if (me.debug) {
					console.debug(resp.body);
				}
				return ACME._wait(DEAUTH_INTERVAL);
			});
		}

		function pollStatus() {
			if (count >= MAX_POLL) {
				return Promise.reject(
					new Error(
						"[acme-v2] stuck in bad pending/processing state for '" +
							altname +
							"'"
					)
				);
			}

			count += 1;

			if (me.debug) {
				console.debug('\n[DEBUG] statusChallenge\n');
			}
			// TODO POST-as-GET
			return me
				.request({ method: 'GET', url: auth.url, json: true })
				.then(function(resp) {
					if ('processing' === resp.body.status) {
						if (me.debug) {
							console.debug('poll: again');
						}
						return ACME._wait(RETRY_INTERVAL).then(pollStatus);
					}

					// This state should never occur
					if ('pending' === resp.body.status) {
						if (count >= MAX_PEND) {
							return ACME._wait(RETRY_INTERVAL)
								.then(deactivate)
								.then(respondToChallenge);
						}
						if (me.debug) {
							console.debug('poll: again');
						}
						return ACME._wait(RETRY_INTERVAL).then(
							respondToChallenge
						);
					}

					if ('valid' === resp.body.status) {
						if (me.debug) {
							console.debug('poll: valid');
						}

						try {
							ACME._removeChallenge(me, options, auth);
						} catch (e) {}
						return resp.body;
					}

					var errmsg;
					if (!resp.body.status) {
						errmsg =
							"[acme-v2] (E_STATE_EMPTY) empty challenge state for '" +
							altname +
							"':";
					} else if ('invalid' === resp.body.status) {
						errmsg =
							"[acme-v2] (E_STATE_INVALID) challenge state for '" +
							altname +
							"': '" +
							resp.body.status +
							"'";
					} else {
						errmsg =
							"[acme-v2] (E_STATE_UKN) challenge state for '" +
							altname +
							"': '" +
							resp.body.status +
							"'";
					}

					return Promise.reject(new Error(errmsg));
				});
		}

		function respondToChallenge() {
			if (me.debug) {
				console.debug('[acme-v2.js] responding to accept challenge:');
			}
			return ACME._jwsRequest(me, {
				options: options,
				url: auth.url,
				protected: { kid: options._kid },
				payload: Enc.binToBuf(JSON.stringify({}))
			}).then(function(resp) {
				if (me.debug) {
					console.debug('respond to challenge: resp.body:');
				}
				if (me.debug) {
					console.debug(resp.body);
				}
				return ACME._wait(RETRY_INTERVAL).then(pollStatus);
			});
		}

		return respondToChallenge();
	};
	ACME._setChallenge = function(me, options, auth) {
		return new Promise(function(resolve, reject) {
			var challengers = options.challenges || {};
			var challenger =
				(challengers[auth.type] && challengers[auth.type].set) ||
				options.setChallenge;
			try {
				if (1 === challenger.length) {
					challenger(auth)
						.then(resolve)
						.catch(reject);
				} else if (2 === challenger.length) {
					challenger(auth, function(err) {
						if (err) {
							reject(err);
						} else {
							resolve();
						}
					});
				} else {
					// TODO remove this old backwards-compat
					var challengeCb = function(err) {
						if (err) {
							reject(err);
						} else {
							resolve();
						}
					};
					// for backwards compat adding extra keys without changing params length
					Object.keys(auth).forEach(function(key) {
						challengeCb[key] = auth[key];
					});
					if (!ACME._setChallengeWarn) {
						console.warn(
							'Please update to acme-v2 setChallenge(options) <Promise> or setChallenge(options, cb).'
						);
						console.warn(
							"The API has been changed for compatibility with all ACME / Let's Encrypt challenge types."
						);
						ACME._setChallengeWarn = true;
					}
					challenger(
						auth.identifier.value,
						auth.token,
						auth.keyAuthorization,
						challengeCb
					);
				}
			} catch (e) {
				reject(e);
			}
		}).then(function() {
			// TODO: Do we still need this delay? Or shall we leave it to plugins to account for themselves?
			var DELAY = me.setChallengeWait || 500;
			if (me.debug) {
				console.debug('\n[DEBUG] waitChallengeDelay %s\n', DELAY);
			}
			return ACME._wait(DELAY);
		});
	};
	ACME._finalizeOrder = function(me, options, validatedDomains) {
		if (me.debug) {
			console.debug('finalizeOrder:');
		}
		return ACME._generateCsrWeb64(me, options, validatedDomains).then(
			function(csr) {
				var body = { csr: csr };
				var payload = JSON.stringify(body);

				function pollCert() {
					if (me.debug) {
						console.debug('[acme-v2.js] pollCert:');
					}
					return ACME._jwsRequest(me, {
						options: options,
						url: options._finalize,
						protected: { kid: options._kid },
						payload: Enc.binToBuf(payload)
					}).then(function(resp) {
						if (me.debug) {
							console.debug('order finalized: resp.body:');
						}
						if (me.debug) {
							console.debug(resp.body);
						}

						// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
						// Possible values are: "pending" => ("invalid" || "ready") => "processing" => "valid"
						if ('valid' === resp.body.status) {
							options._expires = resp.body.expires;
							options._certificate = resp.body.certificate;

							return resp.body; // return order
						}

						if ('processing' === resp.body.status) {
							return ACME._wait().then(pollCert);
						}

						if (me.debug) {
							console.debug(
								'Error: bad status:\n' +
									JSON.stringify(resp.body, null, 2)
							);
						}

						if ('pending' === resp.body.status) {
							return Promise.reject(
								new Error(
									"Did not finalize order: status 'pending'." +
										' Best guess: You have not accepted at least one challenge for each domain:\n' +
										"Requested: '" +
										options.domains.join(', ') +
										"'\n" +
										"Validated: '" +
										validatedDomains.join(', ') +
										"'\n" +
										JSON.stringify(resp.body, null, 2)
								)
							);
						}

						if ('invalid' === resp.body.status) {
							return Promise.reject(
								new Error(
									"Did not finalize order: status 'invalid'." +
										' Best guess: One or more of the domain challenges could not be verified' +
										' (or the order was canceled).\n' +
										"Requested: '" +
										options.domains.join(', ') +
										"'\n" +
										"Validated: '" +
										validatedDomains.join(', ') +
										"'\n" +
										JSON.stringify(resp.body, null, 2)
								)
							);
						}

						if ('ready' === resp.body.status) {
							return Promise.reject(
								new Error(
									"Did not finalize order: status 'ready'." +
										" Hmmm... this state shouldn't be possible here. That was the last state." +
										" This one should at least be 'processing'.\n" +
										"Requested: '" +
										options.domains.join(', ') +
										"'\n" +
										"Validated: '" +
										validatedDomains.join(', ') +
										"'\n" +
										JSON.stringify(resp.body, null, 2) +
										'\n\n' +
										'Please open an issue at https://git.coolaj86.com/coolaj86/acme-v2.js'
								)
							);
						}

						return Promise.reject(
							new Error(
								"Didn't finalize order: Unhandled status '" +
									resp.body.status +
									"'." +
									' This is not one of the known statuses...\n' +
									"Requested: '" +
									options.domains.join(', ') +
									"'\n" +
									"Validated: '" +
									validatedDomains.join(', ') +
									"'\n" +
									JSON.stringify(resp.body, null, 2) +
									'\n\n' +
									'Please open an issue at https://git.coolaj86.com/coolaj86/acme-v2.js'
							)
						);
					});
				}

				return pollCert();
			}
		);
	};
	// _kid
	// registerAccount
	// postChallenge
	// finalizeOrder
	// getCertificate
	ACME._getCertificate = function(me, options) {
		if (me.debug) {
			console.debug('[acme-v2] DEBUG get cert 1');
		}

		// Lot's of error checking to inform the user of mistakes
		if (!(options.challengeTypes || []).length) {
			options.challengeTypes = Object.keys(options.challenges || {});
		}
		if (!options.challengeTypes.length) {
			options.challengeTypes = [options.challengeType].filter(Boolean);
		}
		if (options.challengeType) {
			options.challengeTypes.sort(function(a, b) {
				if (a === options.challengeType) {
					return -1;
				}
				if (b === options.challengeType) {
					return 1;
				}
				return 0;
			});
			if (options.challengeType !== options.challengeTypes[0]) {
				return Promise.reject(
					new Error(
						"options.challengeType is '" +
							options.challengeType +
							"'," +
							" which does not exist in the supplied types '" +
							options.challengeTypes.join(',') +
							"'"
					)
				);
			}
		}
		// TODO check that all challengeTypes are represented in challenges
		if (!options.challengeTypes.length) {
			return Promise.reject(
				new Error(
					'options.challengeTypes (string array) must be specified' +
						' (and in order of preferential priority).'
				)
			);
		}
		if (options.csr) {
			// TODO validate csr signature
			options._csr = me.CSR._info(options.csr);
			options.domains = options._csr.altnames;
			if (options._csr.subject !== options.domains[0]) {
				return Promise.reject(
					new Error(
						'certificate subject (commonName) does not match first altname (SAN)'
					)
				);
			}
		}
		if (!(options.domains && options.domains.length)) {
			return Promise.reject(
				new Error(
					'options.domains must be a list of string domain names,' +
						' with the first being the subject of the certificate (or options.subject must specified).'
				)
			);
		}

		// It's just fine if there's no account, we'll go get the key id we need via the existing key
		options._kid =
			options._kid ||
			options.accountKid ||
			(options.account &&
				(options.account.kid ||
					(options.account.key && options.account.key.kid)));
		if (!options._kid) {
			//return Promise.reject(new Error("must include KeyID"));
			// This is an idempotent request. It'll return the same account for the same public key.
			return ACME._registerAccount(me, options).then(function(account) {
				options._kid = account.key.kid;
				// start back from the top
				return ACME._getCertificate(me, options);
			});
		}

		// Do a little dry-run / self-test
		return ACME._testChallenges(me, options).then(function() {
			if (me.debug) {
				console.debug('[acme-v2] certificates.create');
			}
			var body = {
				// raw wildcard syntax MUST be used here
				identifiers: options.domains
					.sort(function(a, b) {
						// the first in the list will be the subject of the certificate, I believe (and hope)
						if (!options.subject) {
							return 0;
						}
						if (options.subject === a) {
							return -1;
						}
						if (options.subject === b) {
							return 1;
						}
						return 0;
					})
					.map(function(hostname) {
						return { type: 'dns', value: hostname };
					})
				//, "notBefore": "2016-01-01T00:00:00Z"
				//, "notAfter": "2016-01-08T00:00:00Z"
			};

			var payload = JSON.stringify(body);
			if (me.debug) {
				console.debug('\n[DEBUG] newOrder\n');
			}
			return ACME._jwsRequest(me, {
				options: options,
				url: me._directoryUrls.newOrder,
				protected: { kid: options._kid },
				payload: Enc.binToBuf(payload)
			}).then(function(resp) {
				var location = resp.headers.location;
				var setAuths;
				var validAuths = [];
				var auths = [];
				if (me.debug) {
					console.debug('[ordered]', location);
				} // the account id url
				if (me.debug) {
					console.debug(resp);
				}
				options._authorizations = resp.body.authorizations;
				options._order = location;
				options._finalize = resp.body.finalize;
				//if (me.debug) console.debug('[DEBUG] finalize:', options._finalize); return;

				if (!options._authorizations) {
					return Promise.reject(
						new Error(
							"[acme-v2.js] authorizations were not fetched for '" +
								options.domains.join() +
								"':\n" +
								JSON.stringify(resp.body)
						)
					);
				}
				if (me.debug) {
					console.debug('[acme-v2] POST newOrder has authorizations');
				}
				setAuths = options._authorizations.slice(0);

				function setNext() {
					var authUrl = setAuths.shift();
					if (!authUrl) {
						return;
					}

					return ACME._getChallenges(me, options, authUrl).then(
						function(results) {
							// var domain = options.domains[i]; // results.identifier.value

							// If it's already valid, we're golden it regardless
							if (
								results.challenges.some(function(ch) {
									return 'valid' === ch.status;
								})
							) {
								return setNext();
							}

							var challenge = ACME._chooseChallenge(
								options,
								results
							);
							if (!challenge) {
								// For example, wildcards require dns-01 and, if we don't have that, we have to bail
								return Promise.reject(
									new Error(
										"Server didn't offer any challenge we can handle for '" +
											options.domains.join() +
											"'."
									)
								);
							}

							return ACME._challengeToAuth(
								me,
								options,
								results,
								challenge,
								false
							).then(function(auth) {
								auths.push(auth);
								return ACME._setChallenge(
									me,
									options,
									auth
								).then(setNext);
							});
						}
					);
				}

				function checkNext() {
					var auth = auths.shift();
					if (!auth) {
						return;
					}

					if (!me._canUse[auth.type] || me.skipChallengeTest) {
						// not so much "valid" as "not invalid"
						// but in this case we can't confirm either way
						validAuths.push(auth);
						return Promise.resolve();
					}

					return ACME.challengeTests[auth.type](me, auth)
						.then(function() {
							validAuths.push(auth);
						})
						.then(checkNext);
				}

				function challengeNext() {
					var auth = validAuths.shift();
					if (!auth) {
						return;
					}
					return ACME._postChallenge(me, options, auth).then(
						challengeNext
					);
				}

				// First we set every challenge
				// Then we ask for each challenge to be checked
				// Doing otherwise would potentially cause us to poison our own DNS cache with misses
				return setNext()
					.then(checkNext)
					.then(challengeNext)
					.then(function() {
						if (me.debug) {
							console.debug('[getCertificate] next.then');
						}
						var validatedDomains = body.identifiers.map(function(
							ident
						) {
							return ident.value;
						});

						return ACME._finalizeOrder(
							me,
							options,
							validatedDomains
						);
					})
					.then(function(order) {
						if (me.debug) {
							console.debug('acme-v2: order was finalized');
						}
						// TODO POST-as-GET
						return me
							.request({
								method: 'GET',
								url: options._certificate,
								json: true
							})
							.then(function(resp) {
								if (me.debug) {
									console.debug(
										'acme-v2: csr submitted and cert received:'
									);
								}
								// https://github.com/certbot/certbot/issues/5721
								var certsarr = ACME.splitPemChain(
									ACME.formatPemChain(resp.body || '')
								);
								//  cert, chain, fullchain, privkey, /*TODO, subject, altnames, issuedAt, expiresAt */
								var certs = {
									expires: order.expires,
									identifiers: order.identifiers,
									//, authorizations: order.authorizations
									cert: certsarr.shift(),
									//, privkey: privkeyPem
									chain: certsarr.join('\n')
								};
								if (me.debug) {
									console.debug(certs);
								}
								return certs;
							});
					});
			});
		});
	};
	ACME._generateCsrWeb64 = function(me, options, validatedDomains) {
		var csr;
		if (options.csr) {
			csr = options.csr;
			// if der, convert to base64
			if ('string' !== typeof csr) {
				csr = Enc.bufToUrlBase64(csr);
			}
			// nix PEM headers, if any
			if ('-' === csr[0]) {
				csr = csr
					.split(/\n+/)
					.slice(1, -1)
					.join('');
			}
			csr = Enc.base64ToUrlBase64(csr.trim().replace(/\s+/g, ''));
			return Promise.resolve(csr);
		}

		return ACME._importKeypair(
			me,
			options.serverKeypair || options.domainKeypair
		).then(function(pair) {
			return me
				.CSR({
					jwk: pair.private,
					domains: validatedDomains,
					encoding: 'der'
				})
				.then(function(der) {
					return Enc.bufToUrlBase64(der);
				});
		});
	};

	ACME.create = function create(me) {
		if (!me) {
			me = {};
		}
		// me.debug = true;
		me.challengePrefixes = ACME.challengePrefixes;
		me.Keypairs =
			me.Keypairs || exports.Keypairs || require('keypairs').Keypairs;
		me.CSR = me.CSR || exports.CSR || require('CSR').CSR;
		me._nonces = [];
		me._canUse = {};
		if (!me._baseUrl) {
			me._baseUrl = '';
		}
		//me.Keypairs = me.Keypairs || require('keypairs');
		//me.request = me.request || require('@root/request');
		if (!me.dns01) {
			me.dns01 = function(auth) {
				return ACME._dns01(me, auth);
			};
		}
		// backwards compat
		if (!me.dig) {
			me.dig = me.dns01;
		}
		if (!me.http01) {
			me.http01 = function(auth) {
				return ACME._http01(me, auth);
			};
		}

		if ('function' !== typeof me.request) {
			me.request = ACME._defaultRequest;
		}

		me.init = function(opts) {
			function fin(dir) {
				me._directoryUrls = dir;
				me._tos = dir.meta.termsOfService;
				return dir;
			}
			if (opts && opts.meta && opts.termsOfService) {
				return Promise.resolve(fin(opts));
			}
			if (!me.directoryUrl) {
				me.directoryUrl = opts;
			}
			if ('string' !== typeof me.directoryUrl) {
				throw new Error(
					'you must supply either the ACME directory url as a string or an object of the ACME urls'
				);
			}
			var p = Promise.resolve();
			if (!me.skipChallengeTest) {
				p = me
					.request({ url: me._baseUrl + '/api/_acme_api_/' })
					.then(function(resp) {
						if (resp.body.success) {
							me._canCheck['http-01'] = true;
							me._canCheck['dns-01'] = true;
						}
					})
					.catch(function() {
						// ignore
					});
			}
			return p.then(function() {
				return ACME._directory(me).then(function(resp) {
					return fin(resp.body);
				});
			});
		};
		me.accounts = {
			create: function(options) {
				return ACME._registerAccount(me, options);
			}
		};
		me.certificates = {
			create: function(options) {
				return ACME._getCertificate(me, options);
			}
		};
		return me;
	};

	// Handle nonce, signing, and request altogether
	ACME._jwsRequest = function(me, bigopts) {
		return ACME._getNonce(me).then(function(nonce) {
			bigopts.protected.nonce = nonce;
			bigopts.protected.url = bigopts.url;
			// protected.alg: added by Keypairs.signJws
			if (!bigopts.protected.jwk) {
				// protected.kid must be overwritten due to ACME's interpretation of the spec
				if (!bigopts.protected.kid) {
					bigopts.protected.kid = bigopts.options._kid;
				}
			}
			return me.Keypairs.signJws({
				jwk: bigopts.options.accountKeypair.privateKeyJwk,
				protected: bigopts.protected,
				payload: bigopts.payload
			}).then(function(jws) {
				if (me.debug) {
					console.debug('[acme-v2] ' + bigopts.url + ':');
				}
				if (me.debug) {
					console.debug(jws);
				}
				return ACME._request(me, { url: bigopts.url, json: jws });
			});
		});
	};
	// Handle some ACME-specific defaults
	ACME._request = function(me, opts) {
		if (!opts.headers) {
			opts.headers = {};
		}
		if (opts.json && true !== opts.json) {
			opts.headers['Content-Type'] = 'application/jose+json';
			opts.body = JSON.stringify(opts.json);
			if (!opts.method) {
				opts.method = 'POST';
			}
		}
		return me.request(opts).then(function(resp) {
			resp = resp.toJSON();
			if (resp.headers['replay-nonce']) {
				ACME._setNonce(me, resp.headers['replay-nonce']);
			}
			return resp;
		});
	};
	// A very generic, swappable request lib
	ACME._defaultRequest = function(opts) {
		// Note: normally we'd have to supply a User-Agent string, but not here in a browser
		if (!opts.headers) {
			opts.headers = {};
		}
		if (opts.json) {
			opts.headers.Accept = 'application/json';
			if (true !== opts.json) {
				opts.body = JSON.stringify(opts.json);
			}
		}
		if (!opts.method) {
			opts.method = 'GET';
			if (opts.body) {
				opts.method = 'POST';
			}
		}
		opts.cors = true;
		return window.fetch(opts.url, opts).then(function(resp) {
			var headers = {};
			var result = {
				statusCode: resp.status,
				headers: headers,
				toJSON: function() {
					return this;
				}
			};
			Array.from(resp.headers.entries()).forEach(function(h) {
				headers[h[0]] = h[1];
			});
			if (!headers['content-type']) {
				return result;
			}
			if (/json/.test(headers['content-type'])) {
				return resp.json().then(function(json) {
					result.body = json;
					return result;
				});
			}
			return resp.text().then(function(txt) {
				result.body = txt;
				return result;
			});
		});
	};

	ACME._importKeypair = function(me, kp) {
		var jwk = kp.privateKeyJwk;
		var p;
		if (jwk) {
			// nix the browser jwk extras
			jwk.key_ops = undefined;
			jwk.ext = undefined;
			p = Promise.resolve({
				private: jwk,
				public: me.Keypairs.neuter({ jwk: jwk })
			});
		} else {
			p = me.Keypairs.import({ pem: kp.privateKeyPem });
		}
		return p.then(function(pair) {
			kp.privateKeyJwk = pair.private;
			kp.publicKeyJwk = pair.public;
			if (pair.public.kid) {
				pair = JSON.parse(JSON.stringify(pair));
				delete pair.public.kid;
				delete pair.private.kid;
			}
			return pair;
		});
	};

	/*
TODO
Per-Order State Params
      _kty
      _alg
      _finalize
      _expires
      _certificate
      _order
      _authorizations
*/

	ACME._toWebsafeBase64 = function(b64) {
		return b64
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	};

	// In v8 this is crypto random, but we're just using it for pseudorandom
	ACME._prnd = function(n) {
		var rnd = '';
		while (rnd.length / 2 < n) {
			var num = Math.random()
				.toString()
				.substr(2);
			if (num.length % 2) {
				num = '0' + num;
			}
			var pairs = num.match(/(..?)/g);
			rnd += pairs.map(ACME._toHex).join('');
		}
		return rnd.substr(0, n * 2);
	};
	ACME._toHex = function(pair) {
		return parseInt(pair, 10).toString(16);
	};
	ACME._dns01 = function(me, auth) {
		return new me.request({
			url: me._baseUrl + '/api/dns/' + auth.dnsHost + '?type=TXT'
		}).then(function(resp) {
			var err;
			if (!resp.body || !Array.isArray(resp.body.answer)) {
				err = new Error('failed to get DNS response');
				console.error(err);
				throw err;
			}
			if (!resp.body.answer.length) {
				err = new Error('failed to get DNS answer record in response');
				console.error(err);
				throw err;
			}
			return {
				answer: resp.body.answer.map(function(ans) {
					return { data: ans.data, ttl: ans.ttl };
				})
			};
		});
	};
	ACME._http01 = function(me, auth) {
		var url = encodeURIComponent(auth.challengeUrl);
		return new me.request({
			url: me._baseUrl + '/api/http?url=' + url
		}).then(function(resp) {
			return resp.body;
		});
	};
	ACME._removeChallenge = function(me, options, auth) {
		var challengers = options.challenges || {};
		var removeChallenge =
			(challengers[auth.type] && challengers[auth.type].remove) ||
			options.removeChallenge;
		if (1 === removeChallenge.length) {
			removeChallenge(auth).then(function() {}, function() {});
		} else if (2 === removeChallenge.length) {
			removeChallenge(auth, function(err) {
				return err;
			});
		} else {
			if (!ACME._removeChallengeWarn) {
				console.warn(
					'Please update to acme-v2 removeChallenge(options) <Promise> or removeChallenge(options, cb).'
				);
				console.warn(
					"The API has been changed for compatibility with all ACME / Let's Encrypt challenge types."
				);
				ACME._removeChallengeWarn = true;
			}
			removeChallenge(auth.request.identifier, auth.token, function() {});
		}
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

	Crypto._sha = function(sha, str) {
		var encoder = new TextEncoder();
		var data = encoder.encode(str);
		sha = 'SHA-' + sha.replace(/^sha-?/i, '');
		return window.crypto.subtle.digest(sha, data).then(function(hash) {
			return Enc.bufToUrlBase64(new Uint8Array(hash));
		});
	};
})('undefined' === typeof window ? module.exports : window);
