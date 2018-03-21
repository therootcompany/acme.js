/*!
 * acme-v2.js
 * Copyright(c) 2018 AJ ONeal <aj@ppl.family> https://ppl.family
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';
/* globals Promise */

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

  var RSA = deps.RSA || require('rsa-compat').RSA;
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
      if (me._nonce) { return new Promise(function (resolve) { resolve(me._nonce); return; }); }
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

      console.log('[acme-v2] registerNewAccount');

      return me.getNonce().then(function () {
        return new Promise(function (resolve, reject) {

          function agree(err, tosUrl) {
            if (err) { reject(err); return; }
            if (me._tos !== tosUrl) {
              err = new Error("You must agree to the ToS at '" + me._tos + "'");
              err.code = "E_AGREE_TOS";
              reject(err);
              return;
            }

            var jwk = RSA.exportPublicJwk(options.accountKeypair);
            var body = {
              termsOfServiceAgreed: tosUrl === me._tos
            , onlyReturnExisting: false
            , contact: [ 'mailto:' + options.email ]
            };
            if (options.externalAccount) {
              body.externalAccountBinding = RSA.signJws(
                options.externalAccount.secret
              , undefined
              , { alg: "HS256"
                , kid: options.externalAccount.id
                , url: me._directoryUrls.newAccount
                }
              , new Buffer(JSON.stringify(jwk))
              );
            }
            var payload = JSON.stringify(body);
            var jws = RSA.signJws(
              options.accountKeypair
            , undefined
            , { nonce: me._nonce
              , alg: 'RS256'
              , url: me._directoryUrls.newAccount
              , jwk: jwk
              }
            , new Buffer(payload)
            );

            console.log('[acme-v2] registerNewAccount JSON body:');
            delete jws.header;
            console.log(jws);
            me._nonce = null;
            return request({
              method: 'POST'
            , url: me._directoryUrls.newAccount
            , headers: { 'Content-Type': 'application/jose+json' }
            , json: jws
            }).then(function (resp) {
              me._nonce = resp.toJSON().headers['replay-nonce'];
              var location = resp.toJSON().headers.location;
              console.log('[DEBUG] new account location:'); // the account id url
              console.log(location); // the account id url
              console.log(resp.toJSON());
              me._kid = location;
              return resp.body;
            }).then(resolve);
          }

          console.log('[acme-v2] agreeToTerms');
          options.agreeToTerms(me._tos, agree);
        });
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
        return resp.body;
      });
    }
    // https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
  , _postChallenge: function (options, identifier, ch) {
      var me = this;

      var body = { };

      var payload = JSON.stringify(body);

      var thumbprint = RSA.thumbprint(options.accountKeypair);
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

      return new Promise(function (resolve, reject) {
        if (options.setupChallenge) {
          options.setupChallenge(
            { identifier: identifier
            , hostname: identifier.value
            , type: ch.type
            , token: ch.token
            , thumbprint: thumbprint
            , keyAuthorization: keyAuthorization
            , dnsAuthorization: RSA.utils.toWebsafeBase64(
                require('crypto').createHash('sha256').update(keyAuthorization).digest('base64')
              )
            }
          , testChallenge
          );
        } else {
          options.setChallenge(identifier.value, ch.token, keyAuthorization, testChallenge);
        }

        function testChallenge(err) {
          if (err) { reject(err); return; }

          // TODO put check dns / http checks here?
          // http-01: GET https://example.org/.well-known/acme-challenge/{{token}} => {{keyAuth}}
          // dns-01: TXT _acme-challenge.example.org. => "{{urlSafeBase64(sha256(keyAuth))}}"

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
                try {
                  if (options.teardownChallenge) {
                    options.teardownChallenge(
                      { identifier: identifier
                      , type: ch.type
                      , token: ch.token
                      }
                    , function () {}
                    );
                  } else {
                    options.removeChallenge(identifier.value, ch.token, function () {});
                  }
                } catch(e) {}
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

              return Promise.reject(new Error("[acme-v2] bad challenge state"));
            });
          }

          console.log('\n[DEBUG] postChallenge\n');
          //console.log('\n[DEBUG] stop to fix things\n'); return;

          function post() {
            var jws = RSA.signJws(
              options.accountKeypair
            , undefined
            , { nonce: me._nonce, alg: 'RS256', url: ch.url, kid: me._kid }
            , new Buffer(payload)
            );
            me._nonce = null;
            return request({
              method: 'POST'
            , url: ch.url
            , headers: { 'Content-Type': 'application/jose+json' }
            , json: jws
            }).then(function (resp) {
              me._nonce = resp.toJSON().headers['replay-nonce'];
              console.log('respond to challenge: resp.body:');
              console.log(resp.body);
              return wait().then(pollStatus).then(resolve, reject);
            });
          }

          return wait(20 * 1000).then(post);
        }
      });
    }
  , _finalizeOrder: function (options, validatedDomains) {
      console.log('finalizeOrder:');
      var me = this;

      var csr = RSA.generateCsrWeb64(options.domainKeypair, validatedDomains);
      var body = { csr: csr };
      var payload = JSON.stringify(body);

      function wait(ms) {
        return new Promise(function (resolve) {
          setTimeout(resolve, (ms || 1100));
        });
      }

      function pollCert() {
        var jws = RSA.signJws(
          options.accountKeypair
        , undefined
        , { nonce: me._nonce, alg: 'RS256', url: me._finalize, kid: me._kid }
        , new Buffer(payload)
        );

        console.log('finalize:', me._finalize);
        me._nonce = null;
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
  , _getCertificate: function () {
      var me = this;
      return request({ method: 'GET', url: me._certificate, json: true }).then(function (resp) {
        console.log('Certificate:');
        console.log(resp.body);
        return resp.body;
      });
    }
  , getCertificate: function (options, cb) {
      console.log('[acme-v2] DEBUG get cert 1');
      var me = this;

      if (!options.challengeTypes) {
        if (!options.challengeType) {
          cb(new Error("challenge type must be specified"));
          return Promise.reject(new Error("challenge type must be specified"));
        }
        options.challengeTypes = [ options.challengeType ];
      }

      console.log('[acme-v2] getCertificate');
      return me.getNonce().then(function () {
        var body = {
          identifiers: options.domains.map(function (hostname) {
            return { type: "dns" , value: hostname };
          })
          //, "notBefore": "2016-01-01T00:00:00Z"
          //, "notAfter": "2016-01-08T00:00:00Z"
        };

        var payload = JSON.stringify(body);
        var jws = RSA.signJws(
          options.accountKeypair
        , undefined
        , { nonce: me._nonce, alg: 'RS256', url: me._directoryUrls.newOrder, kid: me._kid }
        , new Buffer(payload)
        );

        console.log('\n[DEBUG] newOrder\n');
        me._nonce = null;
        return request({
          method: 'POST'
        , url: me._directoryUrls.newOrder
        , headers: { 'Content-Type': 'application/jose+json' }
        , json: jws
        }).then(function (resp) {
          me._nonce = resp.toJSON().headers['replay-nonce'];
          var location = resp.toJSON().headers.location;
          console.log(location); // the account id url
          console.log(resp.toJSON());
          //var body = JSON.parse(resp.body);
          me._authorizations = resp.body.authorizations;
          me._order = location;
          me._finalize = resp.body.finalize;
          //console.log('[DEBUG] finalize:', me._finalize); return;

          //return resp.body;
          return Promise.all(me._authorizations.map(function (authUrl) {
            return me._getChallenges(options, authUrl).then(function (results) {
              // var domain = options.domains[i]; // results.identifier.value
              var chType = options.challengeTypes.filter(function (chType) {
                return results.challenges.some(function (ch) {
                  return ch.type === chType;
                });
              })[0];
              var challenge = results.challenges.filter(function (ch) {
                if (chType === ch.type) {
                  return ch;
                }
              })[0];

              if (!challenge) {
                return Promise.reject(new Error("Server didn't offer any challenge we can handle."));
              }

              return me._postChallenge(options, results.identifier, challenge);
            });
          })).then(function () {
            var validatedDomains = body.identifiers.map(function (ident) {
              return ident.value;
            });

            return me._finalizeOrder(options, validatedDomains);
          }).then(function () {
            return me._getCertificate().then(function (result) { cb(null, result); return result; }, cb);
          });
        });
      });
    }
  };
  return acme2;
}

module.exports.ACME = {
  create: create
};
Object.keys(defaults).forEach(function (key) {
  module.exports.ACME[key] = defaults[key];
});
