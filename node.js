/*!
 * acme-v2.js
 * Copyright(c) 2018 AJ ONeal <aj@ppl.family> https://ppl.family
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';
/* globals Promise */

var ACME = module.exports.ACME = {};

ACME.challengePrefixes = {
  'http-01': '/.well-known/acme-challenge'
, 'dns-01': '_acme-challenge'
};
ACME.challengeTests = {
  'http-01': function (me, auth) {
    var url = 'http://' + auth.hostname + ACME.challengePrefixes['http-01'] + '/' + auth.token;
    return me._request({ url: url }).then(function (resp) {
      var err;

      if (auth.keyAuthorization === resp.body.toString('utf8').trim()) {
        return true;
      }

      err = new Error(
        "Error: Failed HTTP-01 Dry Run.\n"
      + "curl '" + url + "' does not return '" + auth.keyAuthorization + "'\n"
      + "See https://git.coolaj86.com/coolaj86/acme-v2.js/issues/4"
      );
      err.code = 'E_FAIL_DRY_CHALLENGE';
      return Promise.reject(err);
    });
  }
, 'dns-01': function (me, auth) {
    var hostname = ACME.challengePrefixes['dns-01'] + '.' + auth.hostname;
    return me._dig({
      type: 'TXT'
    , name: hostname
    }).then(function (ans) {
      var err;

      if (ans.answer.some(function (txt) {
        return auth.dnsAuthorization === txt.data[0];
      })) {
        return true;
      }

      err = new Error(
        "Error: Failed DNS-01 Dry Run.\n"
      + "dig TXT '" + hostname + "' does not return '" + auth.dnsAuthorization + "'\n"
      + "See https://git.coolaj86.com/coolaj86/acme-v2.js/issues/4"
      );
      err.code = 'E_FAIL_DRY_CHALLENGE';
      return Promise.reject(err);
    });
  }
};

ACME._getUserAgentString = function (deps) {
  var uaDefaults = {
      pkg: "Greenlock/" + deps.pkg.version
    , os: "(" + deps.os.type() + "; " + deps.process.arch + " " + deps.os.platform() + " " + deps.os.release() + ")"
    , node: "Node.js/" + deps.process.version
    , user: ''
  };

  var userAgent = [];

  //Object.keys(currentUAProps)
  Object.keys(uaDefaults).forEach(function (key) {
    if (uaDefaults[key]) {
      userAgent.push(uaDefaults[key]);
    }
  });

  return userAgent.join(' ').trim();
};
ACME._directory = function (me) {
  return me._request({ url: me.directoryUrl, json: true });
};
ACME._getNonce = function (me) {
  if (me._nonce) { return new Promise(function (resolve) { resolve(me._nonce); return; }); }
  return me._request({ method: 'HEAD', url: me._directoryUrls.newNonce }).then(function (resp) {
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
ACME._registerAccount = function (me, options) {
  if (me.debug) console.debug('[acme-v2] accounts.create');

  return ACME._getNonce(me).then(function () {
    return new Promise(function (resolve, reject) {

      function agree(tosUrl) {
        var err;
        if (me._tos !== tosUrl) {
          err = new Error("You must agree to the ToS at '" + me._tos + "'");
          err.code = "E_AGREE_TOS";
          reject(err);
          return;
        }

        var jwk = me.RSA.exportPublicJwk(options.accountKeypair);
        var contact;
        if (options.contact) {
          contact = options.contact.slice(0);
        } else if (options.email) {
          contact = [ 'mailto:' + options.email ]
        }
        var body = {
          termsOfServiceAgreed: tosUrl === me._tos
        , onlyReturnExisting: false
        , contact: contact
        };
        if (options.externalAccount) {
          body.externalAccountBinding = me.RSA.signJws(
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
        var jws = me.RSA.signJws(
          options.accountKeypair
        , undefined
        , { nonce: me._nonce
          , alg: 'RS256'
          , url: me._directoryUrls.newAccount
          , jwk: jwk
          }
        , new Buffer(payload)
        );

        delete jws.header;
        if (me.debug) console.debug('[acme-v2] accounts.create JSON body:');
        if (me.debug) console.debug(jws);
        me._nonce = null;
        return me._request({
          method: 'POST'
        , url: me._directoryUrls.newAccount
        , headers: { 'Content-Type': 'application/jose+json' }
        , json: jws
        }).then(function (resp) {
          var account = resp.body;

          me._nonce = resp.toJSON().headers['replay-nonce'];
          var location = resp.toJSON().headers.location;
          // the account id url
          me._kid = location;
          if (me.debug) console.debug('[DEBUG] new account location:');
          if (me.debug) console.debug(location);
          if (me.debug) console.debug(resp.toJSON());

          /*
          {
            id: 5925245,
            key:
             { kty: 'RSA',
               n: 'tBr7m1hVaUNQjUeakznGidnrYyegVUQrsQjNrcipljI9Vxvxd0baHc3vvRZWFyFO5BlS7UDl-KHQdbdqb-MQzfP6T2sNXsOHARQ41pCGY5BYzIPRJF0nD48-CY717is-7BKISv8rf9yx5iSjvK1wZ3Ke3YIpxzK2fWRqccVxXQ92VYioxOfGObACgEUSvdoEttWV2B0Uv4Sdi6zZbk5eo2zALvyGb1P4fKVfQycGLXC41AyhHOAuTqzNCyIkiWEkbfh2lZNcYClP2epS0pHRFXYyjJN6-c8InfM3PISo4k6Qew65HZ-oqUow0tTIgNwuen9q5O6Hc73GvU-2npGJVQ',
               e: 'AQAB' },
            contact: [],
            initialIp: '198.199.82.211',
            createdAt: '2018-04-16T00:41:00.720584972Z',
            status: 'valid'
          }
          */
          if (!account) { account = { _emptyResponse: true, key: {} }; }
          account.key.kid = me._kid;
          return account;
        }).then(resolve, reject);
      }

      if (me.debug) console.debug('[acme-v2] agreeToTerms');
      if (1 === options.agreeToTerms.length) {
        // newer promise API
        return options.agreeToTerms(me._tos).then(agree, reject);
      }
      else if (2 === options.agreeToTerms.length) {
        // backwards compat cb API
        return options.agreeToTerms(me._tos, function (err, tosUrl) {
          if (!err) { agree(tosUrl); return; }
          reject(err);
        });
      }
      else {
        reject(new Error('agreeToTerms has incorrect function signature.'
          + ' Should be fn(tos) { return Promise<tos>; }'));
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
ACME._getChallenges = function (me, options, auth) {
  if (me.debug) console.debug('\n[DEBUG] getChallenges\n');
  return me._request({ method: 'GET', url: auth, json: true }).then(function (resp) {
    return resp.body;
  });
};
ACME._wait = function wait(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, (ms || 1100));
  });
};
// https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
ACME._postChallenge = function (me, options, identifier, ch) {
  var count = 0;

  var thumbprint = me.RSA.thumbprint(options.accountKeypair);
  var keyAuthorization = ch.token + '.' + thumbprint;
  //   keyAuthorization = token || '.' || base64url(JWK_Thumbprint(accountKey))
  //   /.well-known/acme-challenge/:token
  var auth = {
    identifier: identifier
  , hostname: identifier.value
  , type: ch.type
  , token: ch.token
  , thumbprint: thumbprint
  , keyAuthorization: keyAuthorization
  , dnsAuthorization: me.RSA.utils.toWebsafeBase64(
      require('crypto').createHash('sha256').update(keyAuthorization).digest('base64')
    )
  };

  return new Promise(function (resolve, reject) {
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
        options.accountKeypair
      , undefined
      , { nonce: me._nonce, alg: 'RS256', url: ch.url, kid: me._kid }
      , new Buffer(JSON.stringify({ "status": "deactivated" }))
      );
      me._nonce = null;
      return me._request({
        method: 'POST'
      , url: ch.url
      , headers: { 'Content-Type': 'application/jose+json' }
      , json: jws
      }).then(function (resp) {
        if (me.debug) console.debug('[acme-v2.js] deactivate:');
        if (me.debug) console.debug(resp.headers);
        if (me.debug) console.debug(resp.body);
        if (me.debug) console.debug();

        me._nonce = resp.toJSON().headers['replay-nonce'];
        if (me.debug) console.debug('deactivate challenge: resp.body:');
        if (me.debug) console.debug(resp.body);
        return ACME._wait(10 * 1000);
      });
    }

    function pollStatus() {
      if (count >= 5) {
        return Promise.reject(new Error("[acme-v2] stuck in bad pending/processing state"));
      }

      count += 1;

      if (me.debug) console.debug('\n[DEBUG] statusChallenge\n');
      return me._request({ method: 'GET', url: ch.url, json: true }).then(function (resp) {

        if ('processing' === resp.body.status) {
          if (me.debug) console.debug('poll: again');
          return ACME._wait(1 * 1000).then(pollStatus);
        }

        // This state should never occur
        if ('pending' === resp.body.status) {
          if (count >= 4) {
            return ACME._wait(1 * 1000).then(deactivate).then(testChallenge);
          }
          if (me.debug) console.debug('poll: again');
          return ACME._wait(1 * 1000).then(testChallenge);
        }

        if ('valid' === resp.body.status) {
          if (me.debug) console.debug('poll: valid');

          try {
            if (1 === options.removeChallenge.length) {
              options.removeChallenge(auth).then(function () {}, function () {});
            } else if (2 === options.removeChallenge.length) {
              options.removeChallenge(auth, function (err) { return err; });
            } else {
              options.removeChallenge(identifier.value, ch.token, function () {});
            }
          } catch(e) {}
          return resp.body;
        }

        if (!resp.body.status) {
          console.error("[acme-v2] (E_STATE_EMPTY) empty challenge state:");
        }
        else if ('invalid' === resp.body.status) {
          console.error("[acme-v2] (E_STATE_INVALID) invalid challenge state:");
        }
        else {
          console.error("[acme-v2] (E_STATE_UKN) unkown challenge state:");
        }

        return Promise.reject(new Error("[acme-v2] challenge state error"));
      });
    }

    function respondToChallenge() {
      var jws = me.RSA.signJws(
        options.accountKeypair
      , undefined
      , { nonce: me._nonce, alg: 'RS256', url: ch.url, kid: me._kid }
      , new Buffer(JSON.stringify({ }))
      );
      me._nonce = null;
      return me._request({
        method: 'POST'
      , url: ch.url
      , headers: { 'Content-Type': 'application/jose+json' }
      , json: jws
      }).then(function (resp) {
        if (me.debug) console.debug('[acme-v2.js] challenge accepted!');
        if (me.debug) console.debug(resp.headers);
        if (me.debug) console.debug(resp.body);
        if (me.debug) console.debug();

        me._nonce = resp.toJSON().headers['replay-nonce'];
        if (me.debug) console.debug('respond to challenge: resp.body:');
        if (me.debug) console.debug(resp.body);
        return ACME._wait(1 * 1000).then(pollStatus).then(resolve, reject);
      });
    }

    function failChallenge(err) {
      if (err) { reject(err); return; }
      return testChallenge();
    }

    function testChallenge() {
      // TODO put check dns / http checks here?
      // http-01: GET https://example.org/.well-known/acme-challenge/{{token}} => {{keyAuth}}
      // dns-01: TXT _acme-challenge.example.org. => "{{urlSafeBase64(sha256(keyAuth))}}"

      if (me.debug) {console.debug('\n[DEBUG] postChallenge\n'); }
      //if (me.debug) console.debug('\n[DEBUG] stop to fix things\n'); return;

      return ACME._wait(1 * 1000).then(function () {
        if (!me.skipChallengeTest) {
          return ACME.challengeTests[ch.type](me, auth);
        }
      }).then(respondToChallenge);
    }

    try {
      if (1 === options.setChallenge.length) {
        options.setChallenge(auth).then(testChallenge, reject);
      } else if (2 === options.setChallenge.length) {
        options.setChallenge(auth, failChallenge);
      } else {
        options.setChallenge(identifier.value, ch.token, keyAuthorization, failChallenge);
      }
    } catch(e) {
      reject(e);
    }
  });
};
ACME._finalizeOrder = function (me, options, validatedDomains) {
  if (me.debug) console.debug('finalizeOrder:');
  var csr = me.RSA.generateCsrWeb64(options.domainKeypair, validatedDomains);
  var body = { csr: csr };
  var payload = JSON.stringify(body);

  function pollCert() {
    var jws = me.RSA.signJws(
      options.accountKeypair
    , undefined
    , { nonce: me._nonce, alg: 'RS256', url: me._finalize, kid: me._kid }
    , new Buffer(payload)
    );

    if (me.debug) console.debug('finalize:', me._finalize);
    me._nonce = null;
    return me._request({
      method: 'POST'
    , url: me._finalize
    , headers: { 'Content-Type': 'application/jose+json' }
    , json: jws
    }).then(function (resp) {
      // https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
      // Possible values are: "pending" => ("invalid" || "ready") => "processing" => "valid"
      me._nonce = resp.toJSON().headers['replay-nonce'];

      if (me.debug) console.debug('order finalized: resp.body:');
      if (me.debug) console.debug(resp.body);

      if ('valid' === resp.body.status) {
        me._expires = resp.body.expires;
        me._certificate = resp.body.certificate;

        return resp.body;
      }

      if ('processing' === resp.body.status) {
        return ACME._wait().then(pollCert);
      }

      if (me.debug) console.debug("Error: bad status:\n" + JSON.stringify(resp.body, null, 2));

      if ('pending' === resp.body.status) {
        return Promise.reject(new Error(
          "Did not finalize order: status 'pending'."
        + " Best guess: You have not accepted at least one challenge for each domain." + "\n\n"
        + JSON.stringify(resp.body, null, 2)
        ));
      }

      if ('invalid' === resp.body.status) {
        return Promise.reject(new Error(
          "Did not finalize order: status 'invalid'."
        + " Best guess: One or more of the domain challenges could not be verified"
        + " (or the order was canceled)." + "\n\n"
        + JSON.stringify(resp.body, null, 2)
        ));
      }

      if ('ready' === resp.body.status) {
        return Promise.reject(new Error(
          "Did not finalize order: status 'ready'."
        + " Hmmm... this state shouldn't be possible here. That was the last state."
        + " This one should at least be 'processing'." + "\n\n"
        + JSON.stringify(resp.body, null, 2) + "\n\n"
        + "Please open an issue at https://git.coolaj86.com/coolaj86/acme-v2.js"
        ));
      }

      return Promise.reject(new Error(
        "Didn't finalize order: Unhandled status '" + resp.body.status + "'."
      + " This is not one of the known statuses...\n\n"
      + JSON.stringify(resp.body, null, 2) + "\n\n"
      + "Please open an issue at https://git.coolaj86.com/coolaj86/acme-v2.js"
      ));
    });
  }

  return pollCert();
};
ACME._getCertificate = function (me, options) {
  if (me.debug) console.debug('[acme-v2] DEBUG get cert 1');

  if (!options.challengeTypes) {
    if (!options.challengeType) {
      return Promise.reject(new Error("challenge type must be specified"));
    }
    options.challengeTypes = [ options.challengeType ];
  }

  if (!me._kid) {
    if (options.accountKid) {
      me._kid = options.accountKid;
    } else {
      //return Promise.reject(new Error("must include KeyID"));
      return ACME._registerAccount(me, options).then(function () {
        return ACME._getCertificate(me, options);
      });
    }
  }

  if (me.debug) console.debug('[acme-v2] certificates.create');
  return ACME._getNonce(me).then(function () {
    var body = {
      identifiers: options.domains.map(function (hostname) {
        return { type: "dns" , value: hostname };
      })
      //, "notBefore": "2016-01-01T00:00:00Z"
      //, "notAfter": "2016-01-08T00:00:00Z"
    };

    var payload = JSON.stringify(body);
    var jws = me.RSA.signJws(
      options.accountKeypair
    , undefined
    , { nonce: me._nonce, alg: 'RS256', url: me._directoryUrls.newOrder, kid: me._kid }
    , new Buffer(payload)
    );

    if (me.debug) console.debug('\n[DEBUG] newOrder\n');
    me._nonce = null;
    return me._request({
      method: 'POST'
    , url: me._directoryUrls.newOrder
    , headers: { 'Content-Type': 'application/jose+json' }
    , json: jws
    }).then(function (resp) {
      me._nonce = resp.toJSON().headers['replay-nonce'];
      var location = resp.toJSON().headers.location;
      var auths;
      if (me.debug) console.debug(location); // the account id url
      if (me.debug) console.debug(resp.toJSON());
      me._authorizations = resp.body.authorizations;
      me._order = location;
      me._finalize = resp.body.finalize;
      //if (me.debug) console.debug('[DEBUG] finalize:', me._finalize); return;

      if (!me._authorizations) {
        console.error("[acme-v2.js] authorizations were not fetched:");
        console.error(resp.body);
        return Promise.reject(new Error("authorizations were not fetched"));
      }
      if (me.debug) console.debug("47 &#&#&#&#&#&#&&##&#&#&#&#&#&#&#&");

      //return resp.body;
      auths = me._authorizations.slice(0);

      function next() {
        var authUrl = auths.shift();
        if (!authUrl) { return; }

        return ACME._getChallenges(me, options, authUrl).then(function (results) {
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

          return ACME._postChallenge(me, options, results.identifier, challenge);
        }).then(function () {
          return next();
        });
      }

      return next().then(function () {
        if (me.debug) console.debug("37 &#&#&#&#&#&#&&##&#&#&#&#&#&#&#&");
        var validatedDomains = body.identifiers.map(function (ident) {
          return ident.value;
        });

        return ACME._finalizeOrder(me, options, validatedDomains);
      }).then(function () {
        if (me.debug) console.debug('acme-v2: order was finalized');
        return me._request({ method: 'GET', url: me._certificate, json: true }).then(function (resp) {
          if (me.debug) console.debug('acme-v2: csr submitted and cert received:');
          if (me.debug) console.debug(resp.body);
          return resp.body;
        });
      });
    });
  });
};

ACME.create = function create(me) {
  if (!me) { me = {}; }
  // me.debug = true;
  me.challengePrefixes = ACME.challengePrefixes;
  me.RSA = me.RSA || require('rsa-compat').RSA;
  me.request = me.request || require('request');
  me._dig = function (query) {
    // TODO use digd.js
    return new Promise(function (resolve, reject) {
      var dns = require('dns');
      dns.resolveTxt(query.name, function (err, records) {
        if (err) { reject(err); return; }

        resolve({
          answer: records.map(function (rr) {
            return {
              data: rr
            };
          })
        });
      });
    });
  };
  me.promisify = me.promisify || require('util').promisify /*node v8+*/ || require('bluebird').promisify /*node v6*/;


  if ('function' !== typeof me.getUserAgentString) {
    me.pkg = me.pkg || require('./package.json');
    me.os = me.os || require('os');
    me.process = me.process || require('process');
    me.userAgent = ACME._getUserAgentString(me);
  }

  function getRequest(opts) {
    if (!opts) { opts = {}; }

    return me.request.defaults({
      headers: {
        'User-Agent': opts.userAgent || me.userAgent || me.getUserAgentString(me)
      }
    });
  }

  if ('function' !== typeof me._request) {
    me._request = me.promisify(getRequest({}));
  }

  me.init = function (_directoryUrl) {
    me.directoryUrl = me.directoryUrl || _directoryUrl;
    return ACME._directory(me).then(function (resp) {
      me._directoryUrls = resp.body;
      me._tos = me._directoryUrls.meta.termsOfService;
      return me._directoryUrls;
    });
  };
  me.accounts = {
    create: function (options) {
      return ACME._registerAccount(me, options);
    }
  };
  me.certificates = {
    create: function (options) {
      return ACME._getCertificate(me, options);
    }
  };
  return me;
};
