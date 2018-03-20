/*!
 * acme-v2.js
 * Copyright(c) 2018 AJ ONeal <aj@ppl.family> https://ppl.family
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

var defaults = {
  productionServerUrl:    'https://acme-v02.api.letsencrypt.org/directory'
, stagingServerUrl:       'https://acme-staging-v02.api.letsencrypt.org/directory'
, acmeChallengePrefix:    '/.well-known/acme-challenge/'
, knownEndpoints:         [ 'keyChange', 'meta', 'newAccount', 'newNonce', 'newOrder', 'revokeCert' ]
, challengeType:          'http-01' // dns-01
, keyType:                'rsa' // ecdsa
, keySize:                2048 // 256
};

function create(deps) {
  if (!deps) { deps = {}; }
  deps.LeCore = {};
  deps.pkg = deps.pkg || require('./package.json');
  deps.os = deps.os || require('os');
  deps.process = deps.process || require('process');

  var uaDefaults = {
      pkg: "Greenlock/" + deps.pkg.version
    , os: " (" + deps.os.type() + "; " + deps.process.arch + " " + deps.os.platform() + " " + deps.os.release() + ")"
    , node: " Node.js/" + deps.process.version
    , user: ''
  };
  //var currentUAProps;

  function getUaString() {
    var userAgent = '';

    //Object.keys(currentUAProps)
    Object.keys(uaDefaults).forEach(function (key) {
      userAgent += uaDefaults[key];
      //userAgent += currentUAProps[key];
    });

    return userAgent.trim();
  }

  function getRequest(opts) {
    if (!opts) { opts = {}; }

    return deps.request.defaults({
      headers: {
        'User-Agent': opts.userAgent || getUaString()
      }
    });
  }

  deps.request = deps.request || require('request');
  deps.promisify = deps.promisify || require('util').promisify;

  var directoryUrl = deps.directoryUrl || defaults.stagingServerUrl;
  var request = deps.promisify(getRequest({}));

			var crypto = require('crypto');
			RSA.signJws = RSA.generateJws = RSA.generateSignatureJws = RSA.generateSignatureJwk =
			function (keypair, payload, nonce) {
        var prot = {};
        if (nonce) {
          if ('string' === typeof nonce) {
            prot.nonce = nonce;
          } else {
            prot = nonce;
          }
        }
				keypair = RSA._internal.import(keypair);
				keypair = RSA._internal.importForge(keypair);
				keypair.publicKeyJwk = RSA.exportPublicJwk(keypair);

				// Compute JWS signature
				var protectedHeader = "";
				if (Object.keys(prot).length) {
					protectedHeader = JSON.stringify(prot); // { alg: prot.alg, nonce: prot.nonce, url: prot.url });
				}
				var protected64 = RSA.utils.toWebsafeBase64(new Buffer(protectedHeader).toString('base64'));
				var payload64 = RSA.utils.toWebsafeBase64(payload.toString('base64'));
				var raw = protected64 + "." + payload64;
				var sha256Buf = crypto.createHash('sha256').update(raw).digest();
				var sig64;

				if (RSA._URSA) {
					sig64 = RSA._ursaGenerateSig(keypair, sha256Buf);
				} else {
					sig64 = RSA._forgeGenerateSig(keypair, sha256Buf);
				}

				return {
          /*
					header: {
						alg: "RS256"
					, jwk: keypair.publicKeyJwk
					}
          */
				  protected: protected64
				, payload: payload64
				, signature: sig64
				};
			};

  var acme2 = {
    getAcmeUrls: function () {
      var me = this;
      return request({ url: directoryUrl }).then(function (resp) {
        me._directoryUrls = JSON.parse(resp.body);
        me._tos = me._directoryUrls.meta.termsOfService;
        return me._directoryUrls;
      });
    }
  , getNonce: function () {
      var me = this;
      return request({ method: 'HEAD', url: me._directoryUrls.newNonce }).then(function (resp) {
        me._nonce = resp.toJSON().headers['replay-nonce'];
        return me._nonce;
      });
    }
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
  , registerNewAccount: function (options) {
      var me = this;

      var body = {
        termsOfServiceAgreed: true
      , onlyReturnExisting: false
      , contact: [ 'mailto:' + options.email ]
      /*
       "externalAccountBinding": {
         "protected": base64url({
           "alg": "HS256",
           "kid": /* key identifier from CA *//*,
           "url": "https://example.com/acme/new-account"
         }),
         "payload": base64url(/* same as in "jwk" above *//*),
         "signature": /* MAC using MAC key from CA *//*
       }
      */
      };
			var payload = JSON.stringify(body, null, 2);
			var jws = RSA.signJws(
        options.keypair
      , new Buffer(payload)
      , { nonce: me._nonce, alg: 'RS256', url: me._directoryUrls.newAccount, jwk: RSA.exportPublicJwk(options.keypair) }
			);

      console.log('jws:');
      console.log(jws);
      return request({
        method: 'POST'
      , url: me._directoryUrls.newAccount
      , headers: { 'Content-Type': 'application/jose+json' }
      , json: jws
      }).then(function (resp) {
        me._nonce = resp.toJSON().headers['replay-nonce'];
        var location = resp.toJSON().headers['location'];
        console.log(location); // the account id url
        console.log(resp.toJSON());
				me._kid = location;
        return resp.body;
      });
    }
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
  , _getChallenges: function (options, auth) {
      console.log('\n[DEBUG] getChallenges\n');
      return request({ method: 'GET', url: auth, json: true }).then(function (resp) {
        console.log('Authorization:');
        console.log(resp.body.challenges);
        return resp.body.challenges;
      });
    }
    // https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
  , _postChallenge: function (options, ch) {
			var me = this;

      var body = { };

			var payload = JSON.stringify(body);
			//var payload = JSON.stringify(body, null, 2);
			var jws = RSA.signJws(
        options.keypair
      , new Buffer(payload)
      , { nonce: me._nonce, alg: 'RS256', url: ch.url, kid: me._kid }
			);

      var thumbprint = RSA.thumbprint(options.keypair);
      var keyAuthorization = ch.token + '.' + thumbprint;
      //   keyAuthorization = token || '.' || base64url(JWK_Thumbprint(accountKey))
      //   /.well-known/acme-challenge/:token
      console.log('type:');
      console.log(ch.type);
      console.log('ch.token:');
      console.log(ch.token);
      console.log('thumbprint:');
      console.log(thumbprint);
      console.log('keyAuthorization:');
      console.log(keyAuthorization);
      /*
      options.setChallenge(ch.token, thumbprint, keyAuthorization, function (err) {
      });
      */
      function wait(ms) {
        return new Promise(function (resolve) {
          setTimeout(resolve, (ms || 1100));
        });
      }
      function pollStatus() {
        console.log('\n[DEBUG] statusChallenge\n');
        return request({ method: 'GET', url: ch.url, json: true }).then(function (resp) {
          console.error('poll: resp.body:');
          console.error(resp.body);

          if ('pending' === resp.body.status) {
            console.log('poll: again');
            return wait().then(pollStatus);
          }

          if ('valid' === resp.body.status) {
            console.log('poll: valid');
            return resp.body;
          }

          if (!resp.body.status) {
            console.error("[acme-v2] (y) bad challenge state:");
          }
          else if ('invalid' === resp.body.status) {
            console.error("[acme-v2] (x) invalid challenge state:");
          }
          else {
            console.error("[acme-v2] (z) bad challenge state:");
          }
        });
      }

      console.log('\n[DEBUG] postChallenge\n');
      //console.log('\n[DEBUG] stop to fix things\n'); return;

      function post() {
        return request({
          method: 'POST'
        , url: ch.url
        , headers: { 'Content-Type': 'application/jose+json' }
        , json: jws
        }).then(function (resp) {
          me._nonce = resp.toJSON().headers['replay-nonce'];
          console.log('respond to challenge: resp.body:');
          console.log(resp.body);
          return wait().then(pollStatus);
        });
      }

      return wait(20 * 1000).then(post);
    }
  , _finalizeOrder: function (options, validatedDomains) {
      console.log('finalizeOrder:');
			var me = this;

      var csr = RSA.generateCsrWeb64(options.certificateKeypair, validatedDomains);
      var body = { csr: csr };
      var payload = JSON.stringify(body);

      function wait(ms) {
        return new Promise(function (resolve) {
          setTimeout(resolve, (ms || 1100));
        });
      }

      function pollCert() {
        //var payload = JSON.stringify(body, null, 2);
        var jws = RSA.signJws(
          options.keypair
        , new Buffer(payload)
        , { nonce: me._nonce, alg: 'RS256', url: me._finalize, kid: me._kid }
        );

        console.log('finalize:', me._finalize);
        return request({
          method: 'POST'
        , url: me._finalize
        , headers: { 'Content-Type': 'application/jose+json' }
        , json: jws
        }).then(function (resp) {
          me._nonce = resp.toJSON().headers['replay-nonce'];

          console.log('order finalized: resp.body:');
          console.log(resp.body);

          if ('processing' === resp.body.status) {
            return wait().then(pollCert);
          }

          if ('valid' === resp.body.status) {
            me._expires = resp.body.expires;
            me._certificate = resp.body.certificate;

            return resp.body;
          }

          if ('invalid' === resp.body.status) {
            console.error('cannot finalize: badness');
            return;
          }

          console.error('(x) cannot finalize: badness');
          return;
        });
      }

      return pollCert();
    }
  , _getCertificate: function (auth) {
      var me = this;
      return request({ method: 'GET', url: me._certificate, json: true }).then(function (resp) {
        console.log('Certificate:');
        console.log(resp.body);
        return resp.body;
      });
    }
  , getCertificate: function (options, cb) {
			var me = this;

      var body = {
				identifiers: [
          { type: "dns" , value: "test.ppl.family" }
				/*
        , {	type: "dns" , value: "example.net" }
				*/
        ]
        //, "notBefore": "2016-01-01T00:00:00Z"
       //, "notAfter": "2016-01-08T00:00:00Z"
      };

			var payload = JSON.stringify(body);
			//var payload = JSON.stringify(body, null, 2);
			var jws = RSA.signJws(
        options.keypair
      , new Buffer(payload)
      , { nonce: me._nonce, alg: 'RS256', url: me._directoryUrls.newOrder, kid: me._kid }
			);

      console.log('\n[DEBUG] newOrder\n');
      return request({
        method: 'POST'
      , url: me._directoryUrls.newOrder
      , headers: { 'Content-Type': 'application/jose+json' }
      , json: jws
      }).then(function (resp) {
        me._nonce = resp.toJSON().headers['replay-nonce'];
        var location = resp.toJSON().headers['location'];
        console.log(location); // the account id url
        console.log(resp.toJSON());
        //var body = JSON.parse(resp.body);
        me._authorizations = resp.body.authorizations;
        me._order = location;
        me._finalize = resp.body.finalize;
        //console.log('[DEBUG] finalize:', me._finalize); return;

        //return resp.body;
        return Promise.all(me._authorizations.map(function (auth) {
          console.log('authz', auth);
          return me._getChallenges(options, auth).then(function (challenges) {
            var chp;

            challenges.forEach(function (ch) {
              if ('http-01' !== ch.type) {
                return;
              }
              chp = me._postChallenge(options, ch);
            });

            return chp;
          });
        })).then(function () {
          var validatedDomains = body.identifiers.map(function (ident) {
            return ident.value;
          });

          return me._finalizeOrder(options, validatedDomains);
        }).then(function () {
          return me._getCertificate();
        });
      });
		}
  };
  return acme2;
}

var RSA = require('rsa-compat').RSA;
var acme2 = create();
acme2.getAcmeUrls().then(function (body) {
  console.log(body);
  acme2.getNonce().then(function (nonce) {
    console.log(nonce);

		var options = {
			email: 'coolaj86@gmail.com'
		, keypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/account.privkey.pem') })
		, certificateKeypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/privkey.pem') })
		};
    acme2.registerNewAccount(options).then(function (account) {
      console.log(account);
    	acme2.getCertificate(options, function () {
				console.log('got cert');
      });
    });
  });
});
