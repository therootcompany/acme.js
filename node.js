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
  , registerNewAccount: function () {
      var me = this;
			var RSA = require('rsa-compat').RSA;
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

      var options = {
        email: 'coolaj86@gmail.com'
      , keypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/privkey.pem') })
      };
      var body = {
        termsOfServiceAgreed: true
      , onlyReturnExisting: false
      , contact: [ 'mailto:' + options.email ]
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
        console.log(resp.toJSON());
        return resp.body;
      });
    }
  };
  return acme2;
}

var acme2 = create();
acme2.getAcmeUrls().then(function (body) {
  console.log(body);
  acme2.getNonce().then(function (nonce) {
    console.log(nonce);
    acme2.registerNewAccount().then(function (account) {
      console.log(account);
    });
  });
});
