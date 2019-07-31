// Copyright 2018 AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
'use strict';
/* globals Promise */

var ACME = (module.exports.ACME = {});

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
		var url =
			'http://' +
			auth.hostname +
			ACME.challengePrefixes['http-01'] +
			'/' +
			auth.token;
		return me._request({ url: url }).then(function(resp) {
			var err;

			// TODO limit the number of bytes that are allowed to be downloaded
			if (auth.keyAuthorization === resp.body.toString('utf8').trim()) {
				return true;
			}

			err = new Error(
				'Error: Failed HTTP-01 Pre-Flight / Dry Run.\n' +
					"curl '" +
					url +
					"'\n" +
					"Expected: '" +
					auth.keyAuthorization +
					"'\n" +
					"Got: '" +
					resp.body +
					"'\n" +
					'See https://git.coolaj86.com/coolaj86/acme-v2.js/issues/4'
			);
			err.code = 'E_FAIL_DRY_CHALLENGE';
			return Promise.reject(err);
		});
	},
	'dns-01': function(me, auth) {
		// remove leading *. on wildcard domains
		return me
			._dig({
				type: 'TXT',
				name: auth.dnsHost
			})
			.then(function(ans) {
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

ACME._getUserAgentString = function(deps) {
	var uaDefaults = {
		pkg: 'Greenlock/' + deps.pkg.version,
		os:
			'(' +
			deps.os.type() +
			'; ' +
			deps.process.arch +
			' ' +
			deps.os.platform() +
			' ' +
			deps.os.release() +
			')',
		node: 'Node.js/' + deps.process.version,
		user: ''
	};

	var userAgent = [];

	//Object.keys(currentUAProps)
	Object.keys(uaDefaults).forEach(function(key) {
		if (uaDefaults[key]) {
			userAgent.push(uaDefaults[key]);
		}
	});

	return userAgent.join(' ').trim();
};
ACME._directory = function(me) {
	return me._request({ url: me.directoryUrl, json: true });
};
ACME._getNonce = function(me) {
	if (me._nonce) {
		return new Promise(function(resolve) {
			resolve(me._nonce);
			return;
		});
	}
	return me
		._request({ method: 'HEAD', url: me._directoryUrls.newNonce })
		.then(function(resp) {
			me._nonce = resp.toJSON().headers['replay-nonce'];
			return me._nonce;
		});
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

	return ACME._getNonce(me).then(function() {
		return new Promise(function(resolve, reject) {
			function agree(tosUrl) {
				var err;
				if (me._tos !== tosUrl) {
					err = new Error("You must agree to the ToS at '" + me._tos + "'");
					err.code = 'E_AGREE_TOS';
					reject(err);
					return;
				}

				var jwk = me.RSA.exportPublicJwk(options.accountKeypair);
				var contact;
				if (options.contact) {
					contact = options.contact.slice(0);
				} else if (options.email) {
					contact = ['mailto:' + options.email];
				}
				var req = {
					termsOfServiceAgreed: tosUrl === me._tos,
					onlyReturnExisting: false,
					contact: contact
				};
				if (options.externalAccount) {
					// TODO is this really done by HMAC or is it arbitrary?
					req.externalAccountBinding = me.RSA.signJws(
						options.externalAccount.secret,
						undefined,
						{
							alg: 'HS256',
							kid: options.externalAccount.id,
							url: me._directoryUrls.newAccount
						},
						Buffer.from(JSON.stringify(jwk))
					);
				}
				var payload = JSON.stringify(req);
				var jws = me.RSA.signJws(
					options.accountKeypair,
					undefined,
					{
						nonce: me._nonce,
						alg: me._alg || 'RS256',
						url: me._directoryUrls.newAccount,
						jwk: jwk
					},
					Buffer.from(payload)
				);

				delete jws.header;
				if (me.debug) {
					console.debug('[acme-v2] accounts.create JSON body:');
				}
				if (me.debug) {
					console.debug(jws);
				}
				me._nonce = null;
				return me
					._request({
						method: 'POST',
						url: me._directoryUrls.newAccount,
						headers: { 'Content-Type': 'application/jose+json' },
						json: jws
					})
					.then(function(resp) {
						var account = resp.body;

						if (2 !== Math.floor(resp.statusCode / 100)) {
							if ('string' !== typeof account) {
								account = JSON.stringify(account);
							}
							throw new Error(
								'account error: ' +
									resp.statusCode +
									' ' +
									account +
									'\n' +
									JSON.stringify(req)
							);
						}

						me._nonce = resp.toJSON().headers['replay-nonce'];
						var location = resp.toJSON().headers.location;
						// the account id url
						me._kid = location;
						if (me.debug) {
							console.debug('[DEBUG] new account location:');
						}
						if (me.debug) {
							console.debug(location);
						}
						if (me.debug) {
							console.debug(resp.toJSON());
						}

						/*
          {
            contact: ["mailto:jon@example.com"],
            orders: "https://some-url",
            status: 'valid'
          }
          */
						if (!account) {
							account = { _emptyResponse: true, key: {} };
						}
						// https://git.coolaj86.com/coolaj86/acme-v2.js/issues/8
						if (!account.key) {
							account.key = {};
						}
						account.key.kid = me._kid;
						return account;
					})
					.then(resolve, reject);
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
ACME._getChallenges = function(me, options, auth) {
	if (me.debug) {
		console.debug('\n[DEBUG] getChallenges\n');
	}
	return me
		._request({ method: 'GET', url: auth, json: true })
		.then(function(resp) {
			return resp.body;
		});
};
ACME._wait = function wait(ms) {
	return new Promise(function(resolve) {
		setTimeout(resolve, ms || 1100);
	});
};

ACME._testChallengeOptions = function() {
	var chToken = require('crypto')
		.randomBytes(16)
		.toString('hex');
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
	if (me.skipChallengeTest) {
		return Promise.resolve();
	}

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
				var dryrun = true;
				var auth = ACME._challengeToAuth(
					me,
					options,
					results,
					challenge,
					dryrun
				);
				return ACME._setChallenge(me, options, auth).then(function() {
					return auth;
				});
			});
		})
	).then(function(auths) {
		return ACME._wait(CHECK_DELAY).then(function() {
			return Promise.all(
				auths.map(function(auth) {
					return ACME.challengeTests[auth.type](me, auth);
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
ACME._depInit = function(me, options) {
	if ('function' !== typeof options.init) {
		options.init = function() {
			return Promise.resolve(null);
		};
	}
	// back/forwards-compat
	return ACME._wrapCb(
		me,
		options,
		'init',
		{ type: '*', request: me._request },
		'null'
	);
};
ACME._getZones = function(me, options, dnsHosts) {
	if ('function' !== typeof options.getZones) {
		options.getZones = function() {
			return Promise.resolve([]);
		};
	}
	var challenge = { type: 'dns-01', dnsHosts: dnsHosts, request: me._request };
	// back/forwards-compat
	challenge.challenge = challenge;
	return ACME._wrapCb(
		me,
		options,
		'getZones',
		challenge,
		'an array of zone names'
	);
};

ACME._wrapCb = function(me, options, _name, stuff, _desc) {
	return new Promise(function(resolve, reject) {
		try {
			if (options[_name].length <= 1) {
				return Promise.resolve(options[_name](stuff))
					.then(resolve)
					.catch(reject);
			} else if (2 === options[_name].length) {
				options[_name](stuff, function(err, zonenames) {
					if (err) {
						reject(err);
					} else {
						resolve(zonenames);
					}
				});
			} else {
				throw new Error(
					'options.' + _name + ' should accept opts and Promise ' + _desc
				);
			}
		} catch (e) {
			reject(e);
		}
	});
};

function newZoneRegExp(zonename) {
	// (^|\.)example\.com$
	// which matches:
	//  foo.example.com
	//  example.com
	// but not:
	//  fooexample.com
	return new RegExp('(^|\\.)' + zonename.replace(/\./g, '\\.') + '$');
}
function pluckZone(zonenames, dnsHost) {
	return zonenames
		.filter(function(zonename) {
			// the only character that needs to be escaped for regex
			// and is allowed in a domain name is '.'
			return newZoneRegExp(zonename).test(dnsHost);
		})
		.sort(function(a, b) {
			// longest match first
			return b.length - a.length;
		})[0];
}
ACME._challengeToAuth = function(me, options, request, challenge, dryrun) {
	// we don't poison the dns cache with our dummy request
	var dnsPrefix = ACME.challengePrefixes['dns-01'];
	if (dryrun) {
		dnsPrefix = dnsPrefix.replace(
			'acme-challenge',
			'greenlock-dryrun-' +
				Math.random()
					.toString()
					.slice(2, 6)
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

	var zone = pluckZone(options.zonenames || [], auth.identifier.value);
	// batteries-included helpers
	auth.hostname = auth.identifier.value;
	// because I'm not 100% clear if the wildcard identifier does or doesn't have the leading *. in all cases
	auth.altname = ACME._untame(auth.identifier.value, auth.wildcard);
	auth.thumbprint = me.RSA.thumbprint(options.accountKeypair);
	//   keyAuthorization = token || '.' || base64url(JWK_Thumbprint(accountKey))
	auth.keyAuthorization = challenge.token + '.' + auth.thumbprint;
	// conflicts with ACME challenge id url is already in use, so we call this challengeUrl instead
	auth.challengeUrl =
		'http://' +
		auth.identifier.value +
		ACME.challengePrefixes['http-01'] +
		'/' +
		auth.token;
	auth.dnsHost = dnsPrefix + '.' + auth.hostname.replace('*.', '');
	auth.dnsAuthorization = ACME._toWebsafeBase64(
		require('crypto')
			.createHash('sha256')
			.update(auth.keyAuthorization)
			.digest('base64')
	);
	if (zone) {
		auth.dnsZone = zone;
		auth.dnsPrefix = auth.dnsHost
			.replace(newZoneRegExp(zone), '')
			.replace(/\.$/, '');
	}

	// for backwards/forwards compat
	auth.challenge = auth;
	auth.request = me._request;
	return auth;
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
		var jws = me.RSA.signJws(
			options.accountKeypair,
			undefined,
			{
				nonce: me._nonce,
				alg: me._alg || 'RS256',
				url: auth.url,
				kid: me._kid
			},
			Buffer.from(JSON.stringify({ status: 'deactivated' }))
		);
		me._nonce = null;
		return me
			._request({
				method: 'POST',
				url: auth.url,
				headers: { 'Content-Type': 'application/jose+json' },
				json: jws
			})
			.then(function(resp) {
				if (me.debug) {
					console.debug('[acme-v2.js] deactivate:');
				}
				if (me.debug) {
					console.debug(resp.headers);
				}
				if (me.debug) {
					console.debug(resp.body);
				}
				if (me.debug) {
					console.debug();
				}

				me._nonce = resp.toJSON().headers['replay-nonce'];
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
		return me
			._request({ method: 'GET', url: auth.url, json: true })
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
					return ACME._wait(RETRY_INTERVAL).then(respondToChallenge);
				}

				if ('valid' === resp.body.status) {
					if (me.debug) {
						console.debug('poll: valid');
					}

					try {
						if (1 === options.removeChallenge.length) {
							options.removeChallenge(auth).then(function() {}, function() {});
						} else if (2 === options.removeChallenge.length) {
							options.removeChallenge(auth, function(err) {
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
							options.removeChallenge(
								auth.request.identifier,
								auth.token,
								function() {}
							);
						}
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
		var jws = me.RSA.signJws(
			options.accountKeypair,
			undefined,
			{
				nonce: me._nonce,
				alg: me._alg || 'RS256',
				url: auth.url,
				kid: me._kid
			},
			Buffer.from(JSON.stringify({}))
		);
		me._nonce = null;
		return me
			._request({
				method: 'POST',
				url: auth.url,
				headers: { 'Content-Type': 'application/jose+json' },
				json: jws
			})
			.then(function(resp) {
				if (me.debug) {
					console.debug('[acme-v2.js] challenge accepted!');
				}
				if (me.debug) {
					console.debug(resp.headers);
				}
				if (me.debug) {
					console.debug(resp.body);
				}
				if (me.debug) {
					console.debug();
				}

				me._nonce = resp.toJSON().headers['replay-nonce'];
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
		try {
			if (1 === options.setChallenge.length) {
				options
					.setChallenge(auth)
					.then(resolve)
					.catch(reject);
			} else if (2 === options.setChallenge.length) {
				options.setChallenge(auth, function(err) {
					if (err) {
						reject(err);
					} else {
						resolve();
					}
				});
			} else {
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
				options.setChallenge(
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
	var csr = me.RSA.generateCsrWeb64(options.domainKeypair, validatedDomains);
	var body = { csr: csr };
	var payload = JSON.stringify(body);

	function pollCert() {
		var jws = me.RSA.signJws(
			options.accountKeypair,
			undefined,
			{
				nonce: me._nonce,
				alg: me._alg || 'RS256',
				url: me._finalize,
				kid: me._kid
			},
			Buffer.from(payload)
		);

		if (me.debug) {
			console.debug('finalize:', me._finalize);
		}
		me._nonce = null;
		return me
			._request({
				method: 'POST',
				url: me._finalize,
				headers: { 'Content-Type': 'application/jose+json' },
				json: jws
			})
			.then(function(resp) {
				// https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
				// Possible values are: "pending" => ("invalid" || "ready") => "processing" => "valid"
				me._nonce = resp.toJSON().headers['replay-nonce'];

				if (me.debug) {
					console.debug('order finalized: resp.body:');
				}
				if (me.debug) {
					console.debug(resp.body);
				}

				if ('valid' === resp.body.status) {
					me._expires = resp.body.expires;
					me._certificate = resp.body.certificate;

					return resp.body; // return order
				}

				if ('processing' === resp.body.status) {
					return ACME._wait().then(pollCert);
				}

				if (me.debug) {
					console.debug(
						'Error: bad status:\n' + JSON.stringify(resp.body, null, 2)
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
};
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
	if (!(options.domains && options.domains.length)) {
		return Promise.reject(
			new Error(
				'options.domains must be a list of string domain names,' +
					' with the first being the subject of the domain (or options.subject must specified).'
			)
		);
	}

	// It's just fine if there's no account, we'll go get the key id we need via the public key
	if (!me._kid) {
		if (options.accountKid || (options.account && options.account.kid)) {
			me._kid = options.accountKid || options.account.kid;
		} else {
			//return Promise.reject(new Error("must include KeyID"));
			// This is an idempotent request. It'll return the same account for the same public key.
			return ACME._registerAccount(me, options).then(function() {
				// start back from the top
				return ACME._getCertificate(me, options);
			});
		}
	}

	var dnsHosts = options.domains.map(function(d) {
		return (
			require('crypto')
				.randomBytes(2)
				.toString('hex') + d
		);
	});
	return ACME._depInit(me, options, dnsHosts).then(function(nada) {
		if (nada) {
			// fake use of nada to make both _wrapCb and jshint happy
		}
		return ACME._getZones(me, options, dnsHosts).then(function(zonenames) {
			options.zonenames = zonenames;
			// Do a little dry-run / self-test
			return ACME._testChallenges(me, options).then(function() {
				if (me.debug) {
					console.debug('[acme-v2] certificates.create');
				}
				return ACME._getNonce(me).then(function() {
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
					// determine the signing algorithm to use in protected header // TODO isn't that handled by the signer?
					me._kty =
						(options.accountKeypair.privateKeyJwk &&
							options.accountKeypair.privateKeyJwk.kty) ||
						'RSA';
					me._alg = 'EC' === me._kty ? 'ES256' : 'RS256'; // TODO vary with bitwidth of key (if not handled)
					var jws = me.RSA.signJws(
						options.accountKeypair,
						undefined,
						{
							nonce: me._nonce,
							alg: me._alg,
							url: me._directoryUrls.newOrder,
							kid: me._kid
						},
						Buffer.from(payload, 'utf8')
					);

					if (me.debug) {
						console.debug('\n[DEBUG] newOrder\n');
					}
					me._nonce = null;
					return me
						._request({
							method: 'POST',
							url: me._directoryUrls.newOrder,
							headers: { 'Content-Type': 'application/jose+json' },
							json: jws
						})
						.then(function(resp) {
							me._nonce = resp.toJSON().headers['replay-nonce'];
							var location = resp.toJSON().headers.location;
							var setAuths;
							var auths = [];
							if (me.debug) {
								console.debug(location);
							} // the account id url
							if (me.debug) {
								console.debug(resp.toJSON());
							}
							me._authorizations = resp.body.authorizations;
							me._order = location;
							me._finalize = resp.body.finalize;
							//if (me.debug) console.debug('[DEBUG] finalize:', me._finalize); return;

							if (!me._authorizations) {
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
							setAuths = me._authorizations.slice(0);

							function setNext() {
								var authUrl = setAuths.shift();
								if (!authUrl) {
									return;
								}

								return ACME._getChallenges(me, options, authUrl).then(function(
									results
								) {
									// var domain = options.domains[i]; // results.identifier.value

									// If it's already valid, we're golden it regardless
									if (
										results.challenges.some(function(ch) {
											return 'valid' === ch.status;
										})
									) {
										return setNext();
									}

									var challenge = ACME._chooseChallenge(options, results);
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

									var auth = ACME._challengeToAuth(
										me,
										options,
										results,
										challenge
									);
									auths.push(auth);
									return ACME._setChallenge(me, options, auth).then(setNext);
								});
							}

							function challengeNext() {
								var auth = auths.shift();
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
								.then(challengeNext)
								.then(function() {
									if (me.debug) {
										console.debug('[getCertificate] next.then');
									}
									var validatedDomains = body.identifiers.map(function(ident) {
										return ident.value;
									});

									return ACME._finalizeOrder(me, options, validatedDomains);
								})
								.then(function(order) {
									if (me.debug) {
										console.debug('acme-v2: order was finalized');
									}
									return me
										._request({
											method: 'GET',
											url: me._certificate,
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
			});
		});
	});
};

ACME.create = function create(me) {
	if (!me) {
		me = {};
	}
	// me.debug = true;
	me.challengePrefixes = ACME.challengePrefixes;
	me.RSA = me.RSA || require('rsa-compat').RSA;
	//me.Keypairs = me.Keypairs || require('keypairs');
	me.request = me.request || require('@root/request');
	me._dig = function(query) {
		// TODO use digd.js
		return new Promise(function(resolve, reject) {
			var dns = require('dns');
			dns.resolveTxt(query.name, function(err, records) {
				if (err) {
					reject(err);
					return;
				}

				resolve({
					answer: records.map(function(rr) {
						return {
							data: rr
						};
					})
				});
			});
		});
	};
	me.promisify =
		me.promisify ||
		require('util').promisify /*node v8+*/ ||
		require('bluebird').promisify /*node v6*/;

	if ('function' !== typeof me.getUserAgentString) {
		me.pkg = me.pkg || require('./package.json');
		me.os = me.os || require('os');
		me.process = me.process || require('process');
		me.userAgent = ACME._getUserAgentString(me);
	}

	function getRequest(opts) {
		if (!opts) {
			opts = {};
		}

		return me.request.defaults({
			headers: {
				'User-Agent':
					opts.userAgent || me.userAgent || me.getUserAgentString(me)
			}
		});
	}

	if ('function' !== typeof me._request) {
		me._request = me.promisify(getRequest({}));
	}

	me.init = function(_directoryUrl) {
		if (_directoryUrl) {
			_directoryUrl = _directoryUrl.directoryUrl || _directoryUrl;
		}
		if ('string' === typeof _directoryUrl) {
			me.directoryUrl = _directoryUrl;
		}
		if (!me.directoryUrl) {
			me.directoryUrl =
				'https://acme-staging-v02.api.letsencrypt.org/directory';
			console.warn();
			console.warn(
				"No ACME `directoryUrl` was specified. Using Let's Encrypt's staging environment as the default, which will issue invalid certs."
			);
			console.warn('\t' + me.directoryUrl);
			console.warn();
			console.warn(
				"To get valid certificates you will need to switch to a production URL. You might like Let's Encrypt v2:"
			);
			console.warn('\t' + me.directoryUrl.replace('-staging', ''));
			console.warn();
		}
		return ACME._directory(me).then(function(resp) {
			me._directoryUrls = resp.body;
			me._tos = me._directoryUrls.meta.termsOfService;
			return me._directoryUrls;
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

ACME._toWebsafeBase64 = function(b64) {
	return b64
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '');
};
