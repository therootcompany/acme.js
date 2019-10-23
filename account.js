'use strict';

var A = module.exports;
var U = require('./utils.js');

var Keypairs = require('@root/keypairs');
var Enc = require('@root/encoding/bytes');

A._getAccountKid = function(me, options) {
	// It's just fine if there's no account, we'll go get the key id we need via the existing key
	options._kid =
		options._kid ||
		options.accountKid ||
		(options.account &&
			(options.account.kid ||
				(options.account.key && options.account.key.kid)));

	if (options._kid) {
		return Promise.resolve(options._kid);
	}

	//return Promise.reject(new Error("must include KeyID"));
	// This is an idempotent request. It'll return the same account for the same public key.
	return A._registerAccount(me, options).then(function(account) {
		options._kid = account.key.kid;
		// start back from the top
		return options._kid;
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
A._registerAccount = function(me, options) {
	//#console.debug('[ACME.js] accounts.create');

	function agree(tosUrl) {
		var err;
		if (me._tos !== tosUrl) {
			err = new Error("You must agree to the ToS at '" + me._tos + "'");
			err.code = 'E_AGREE_TOS';
			throw err;
		}

		return U._importKeypair(
			me,
			options.accountKey || options.accountKeypair
		).then(function(pair) {
			var contact;
			if (options.contact) {
				contact = options.contact.slice(0);
			} else if (options.subscriberEmail || options.email) {
				contact = [
					'mailto:' + (options.subscriberEmail || options.email)
				];
			}
			var accountRequest = {
				termsOfServiceAgreed: tosUrl === me._tos,
				onlyReturnExisting: false,
				contact: contact
			};
			var pExt;
			if (options.externalAccount) {
				pExt = Keypairs.signJws({
					// TODO is HMAC the standard, or is this arbitrary?
					secret: options.externalAccount.secret,
					protected: {
						alg: options.externalAccount.alg || 'HS256',
						kid: options.externalAccount.id,
						url: me._directoryUrls.newAccount
					},
					payload: Enc.strToBuf(JSON.stringify(pair.public))
				}).then(function(jws) {
					accountRequest.externalAccountBinding = jws;
					return accountRequest;
				});
			} else {
				pExt = Promise.resolve(accountRequest);
			}
			return pExt.then(function(accountRequest) {
				var payload = JSON.stringify(accountRequest);
				return U._jwsRequest(me, {
					options: options,
					url: me._directoryUrls.newAccount,
					protected: { kid: false, jwk: pair.public },
					payload: Enc.strToBuf(payload)
				}).then(function(resp) {
					var account = resp.body;

					if (resp.statusCode < 200 || resp.statusCode >= 300) {
						if ('string' !== typeof account) {
							account = JSON.stringify(account);
						}
						throw new Error(
							'account error: ' +
								resp.statusCode +
								' ' +
								account +
								'\n' +
								payload
						);
					}

					var location = resp.headers.location;
					// the account id url
					options._kid = location;
					//#console.debug('[DEBUG] new account location:');
					//#console.debug(location);
					//#console.debug(resp);

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
					// https://git.rootprojects.org/root/acme.js/issues/8
					if (!account.key) {
						account.key = {};
					}
					account.key.kid = options._kid;
					return account;
				});
			});
		});
	}

	return Promise.resolve()
		.then(function() {
			//#console.debug('[ACME.js] agreeToTerms');
			var agreeToTerms = options.agreeToTerms;
			if (true === agreeToTerms) {
				agreeToTerms = function(tos) {
					return tos;
				};
			}
			return agreeToTerms(me._tos);
		})
		.then(agree);
};
