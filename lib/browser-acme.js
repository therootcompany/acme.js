/*global CSR*/
// CSR takes a while to load after the page load
(function (exports) {
'use strict';

var BACME = exports.ACME = {};
var webFetch = exports.fetch;
var Keypairs = exports.Keypairs;
var Promise = exports.Promise;

var directoryUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
var directory;

var nonceUrl;
var nonce;

var accountKeypair;
var accountJwk;

var accountUrl;

BACME.challengePrefixes = {
  'http-01': '/.well-known/acme-challenge'
, 'dns-01': '_acme-challenge'
};

BACME._logHeaders = function (resp) {
  console.log('Headers:');
  Array.from(resp.headers.entries()).forEach(function (h) { console.log(h[0] + ': ' + h[1]); });
};

BACME._logBody = function (body) {
  console.log('Body:');
  console.log(JSON.stringify(body, null, 2));
  console.log('');
};

BACME.directory = function (opts) {
  return webFetch(opts.directoryUrl || directoryUrl, { mode: 'cors' }).then(function (resp) {
    BACME._logHeaders(resp);
    return resp.json().then(function (reply) {
      if (/error/.test(reply.type)) {
        return Promise.reject(new Error(reply.detail || reply.type));
      }
      directory = reply;
      nonceUrl = directory.newNonce || 'https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce';
      accountUrl = directory.newAccount || 'https://acme-staging-v02.api.letsencrypt.org/acme/new-account';
      orderUrl = directory.newOrder || "https://acme-staging-v02.api.letsencrypt.org/acme/new-order";
      BACME._logBody(reply);
      return reply;
    });
  });
};

BACME.nonce = function () {
  return webFetch(nonceUrl, { mode: 'cors' }).then(function (resp) {
    BACME._logHeaders(resp);
    nonce = resp.headers.get('replay-nonce');
    console.log('Nonce:', nonce);
    // resp.body is empty
    return resp.headers.get('replay-nonce');
  });
};

BACME.accounts = {};

// type = ECDSA
// bitlength = 256
BACME.accounts.generateKeypair = function (opts) {
  return BACME.generateKeypair(opts).then(function (result) {
    accountKeypair = result;

    return webCrypto.subtle.exportKey(
      "jwk"
    , result.privateKey
    ).then(function (privJwk) {

      accountJwk = privJwk;
      console.log('private jwk:');
      console.log(JSON.stringify(privJwk, null, 2));

      return privJwk;
      /*
      return webCrypto.subtle.exportKey(
        "pkcs8"
      , result.privateKey
      ).then(function (keydata) {
        console.log('pkcs8:');
        console.log(Array.from(new Uint8Array(keydata)));

        return privJwk;
        //return accountKeypair;
      });
      */
    });
  });
};

// json to url-safe base64
BACME._jsto64 = function (json) {
  return btoa(JSON.stringify(json)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

var textEncoder = new TextEncoder();

BACME._importKey = function (jwk) {
  var alg; // I think the 256 refers to the hash
  var wcOpts = {};
  var extractable = true; // TODO make optionally false?
  var priv = jwk;
  var pub;

  // ECDSA
  if (/^EC/i.test(jwk.kty)) {
    wcOpts.name = 'ECDSA';
    wcOpts.namedCurve = jwk.crv;
    alg = 'ES256';
    pub = {
      crv: priv.crv
    , kty: priv.kty
    , x: priv.x
    , y: priv.y
    };
    if (!priv.d) {
      priv = null;
    }
  }

  // RSA
  if (/^RS/i.test(jwk.kty)) {
    wcOpts.name = 'RSASSA-PKCS1-v1_5';
    wcOpts.hash = { name: "SHA-256" };
    alg = 'RS256';
    pub = {
      e: priv.e
    , kty: priv.kty
    , n: priv.n
    };
    if (!priv.p) {
      priv = null;
    }
  }

  return window.crypto.subtle.importKey(
    "jwk"
  , pub
  , wcOpts
  , extractable
  , [ "verify" ]
  ).then(function (publicKey) {
    function give(privateKey) {
      return {
        wcPub: publicKey
      , wcKey: privateKey
      , wcKeypair: { publicKey: publicKey, privateKey: privateKey }
      , meta: {
          alg: alg
        , name: wcOpts.name
        , hash: wcOpts.hash
        }
      , jwk: jwk
      };
    }
    if (!priv) {
      return give();
    }
    return window.crypto.subtle.importKey(
      "jwk"
    , priv
    , wcOpts
    , extractable
    , [ "sign"/*, "verify"*/ ]
    ).then(give);
  });
};
BACME._sign = function (opts) {
  var wcPrivKey = opts.abstractKey.wcKeypair.privateKey;
  var wcOpts = opts.abstractKey.meta;
  var alg = opts.abstractKey.meta.alg; // I think the 256 refers to the hash
  var signHash;

  console.log('kty', opts.abstractKey.jwk.kty);
  signHash = { name: "SHA-" + alg.replace(/[a-z]+/ig, '') };

  var msg = textEncoder.encode(opts.protected64 + '.' + opts.payload64);
  console.log('msg:', msg);
  return window.crypto.subtle.sign(
    { name: wcOpts.name, hash: signHash }
  , wcPrivKey
  , msg
  ).then(function (signature) {
    //console.log('sig1:', signature);
    //console.log('sig2:', new Uint8Array(signature));
    //console.log('sig3:', Array.prototype.slice.call(new Uint8Array(signature)));
    // convert buffer to urlsafe base64
    var sig64 = btoa(Array.prototype.map.call(new Uint8Array(signature), function (ch) {
      return String.fromCharCode(ch);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

    console.log('[1] URL-safe Base64 Signature:');
    console.log(sig64);

    var signedMsg = {
      protected: opts.protected64
    , payload: opts.payload64
    , signature: sig64
    };

    console.log('Signed Base64 Msg:');
    console.log(JSON.stringify(signedMsg, null, 2));

    return signedMsg;
  });
};
// email = john.doe@gmail.com
// jwk = { ... }
// agree = true
BACME.accounts.sign = function (opts) {

  return BACME._importKey(opts.jwk).then(function (abstractKey) {

    var payloadJson =
      { termsOfServiceAgreed: opts.agree
      , onlyReturnExisting: false
      , contact: opts.contacts || [ 'mailto:' + opts.email ]
      };
    console.log('payload:');
    console.log(payloadJson);
    var payload64 = BACME._jsto64(
      payloadJson
    );

    var protectedJson =
      { nonce: opts.nonce
      , url: accountUrl
      , alg: abstractKey.meta.alg
      , jwk: null
      };

    if (/EC/i.test(opts.jwk.kty)) {
      protectedJson.jwk = {
        crv: opts.jwk.crv
      , kty: opts.jwk.kty
      , x: opts.jwk.x
      , y: opts.jwk.y
      };
    } else if (/RS/i.test(opts.jwk.kty)) {
      protectedJson.jwk = {
        e: opts.jwk.e
      , kty: opts.jwk.kty
      , n: opts.jwk.n
      };
    } else {
      return Promise.reject(new Error("[acme.accounts.sign] unsupported key type '" + opts.jwk.kty + "'"));
    }

    console.log('protected:');
    console.log(protectedJson);
    var protected64 = BACME._jsto64(
      protectedJson
    );

    // Note: this function hashes before signing so send data, not the hash
    return BACME._sign({
      abstractKey: abstractKey
    , payload64: payload64
    , protected64: protected64
    });
  });
};

var accountId;

BACME.accounts.set = function (opts) {
  nonce = null;
  return window.fetch(accountUrl, {
    mode: 'cors'
  , method: 'POST'
  , headers: { 'Content-Type': 'application/jose+json' }
  , body: JSON.stringify(opts.signedAccount)
  }).then(function (resp) {
    BACME._logHeaders(resp);
    nonce = resp.headers.get('replay-nonce');
    accountId = resp.headers.get('location');
    console.log('Next nonce:', nonce);
    console.log('Location/kid:', accountId);

    if (!resp.headers.get('content-type')) {
     console.log('Body: <none>');

     return { kid: accountId };
    }

    return resp.json().then(function (result) {
      if (/^Error/i.test(result.detail)) {
        return Promise.reject(new Error(result.detail));
      }
      result.kid = accountId;
      BACME._logBody(result);

      return result;
    });
  });
};

var orderUrl;

BACME.orders = {};

// identifiers = [ { type: 'dns', value: 'example.com' }, { type: 'dns', value: '*.example.com' } ]
// signedAccount
BACME.orders.sign = function (opts) {
  var payload64 = BACME._jsto64({ identifiers: opts.identifiers });

  return BACME._importKey(opts.jwk).then(function (abstractKey) {
    var protected64 = BACME._jsto64(
      { nonce: nonce, alg: abstractKey.meta.alg/*'ES256'*/, url: orderUrl, kid: opts.kid }
    );
    console.log('abstractKey:');
    console.log(abstractKey);
    return BACME._sign({
      abstractKey: abstractKey
    , payload64: payload64
    , protected64: protected64
    }).then(function (sig) {
      if (!sig) {
        throw new Error('sig is undefined... nonsense!');
      }
      console.log('newsig', sig);
      return sig;
    });
  });
};

var currentOrderUrl;
var authorizationUrls;
var finalizeUrl;

BACME.orders.create = function (opts) {
  nonce = null;
  return window.fetch(orderUrl, {
    mode: 'cors'
  , method: 'POST'
  , headers: { 'Content-Type': 'application/jose+json' }
  , body: JSON.stringify(opts.signedOrder)
  }).then(function (resp) {
    BACME._logHeaders(resp);
    currentOrderUrl = resp.headers.get('location');
    nonce = resp.headers.get('replay-nonce');
    console.log('Next nonce:', nonce);

    return resp.json().then(function (result) {
      if (/^Error/i.test(result.detail)) {
        return Promise.reject(new Error(result.detail));
      }
      authorizationUrls = result.authorizations;
      finalizeUrl = result.finalize;
      BACME._logBody(result);

      result.url = currentOrderUrl;
      return result;
    });
  });
};

BACME.challenges = {};
BACME.challenges.all = function () {
  var challenges = [];

  function next() {
    if (!authorizationUrls.length) {
      return challenges;
    }

    return BACME.challenges.view().then(function (challenge) {
      challenges.push(challenge);
      return next();
    });
  }

  return next();
};
BACME.challenges.view = function () {
  var authzUrl = authorizationUrls.pop();
  var token;
  var challengeDomain;
  var challengeUrl;

  return window.fetch(authzUrl, {
    mode: 'cors'
  }).then(function (resp) {
    BACME._logHeaders(resp);

    return resp.json().then(function (result) {
      // Note: select the challenge you wish to use
      var challenge = result.challenges.slice(0).pop();
      token = challenge.token;
      challengeUrl = challenge.url;
      challengeDomain = result.identifier.value;

      BACME._logBody(result);

      return {
        challenges: result.challenges
      , expires: result.expires
      , identifier: result.identifier
      , status: result.status
      , wildcard: result.wildcard
      //, token: challenge.token
      //, url: challenge.url
      //, domain: result.identifier.value,
      };
    });
  });
};

var thumbprint;
var keyAuth;
var httpPath;
var dnsAuth;
var dnsRecord;

BACME.thumbprint = function (opts) {
  // https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk

  var accountJwk = opts.jwk;
  var keys;

  if (/^EC/i.test(opts.jwk.kty)) {
    keys = [ 'crv', 'kty', 'x', 'y' ];
  } else if (/^RS/i.test(opts.jwk.kty)) {
    keys = [ 'e', 'kty', 'n' ];
  }

  var accountPublicStr = '{' + keys.map(function (key) {
    return '"' + key + '":"' + accountJwk[key] + '"';
  }).join(',') + '}';

  return window.crypto.subtle.digest(
    { name: "SHA-256" } // SHA-256 is spec'd, non-optional
  , textEncoder.encode(accountPublicStr)
  ).then(function (hash) {
    thumbprint = btoa(Array.prototype.map.call(new Uint8Array(hash), function (ch) {
      return String.fromCharCode(ch);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

    console.log('Thumbprint:');
    console.log(opts);
    console.log(accountPublicStr);
    console.log(thumbprint);

    return thumbprint;
  });
};

// { token, thumbprint, challengeDomain }
BACME.challenges['http-01'] = function (opts) {
  // The contents of the key authorization file
  keyAuth = opts.token + '.' + opts.thumbprint;

  // Where the key authorization file goes
  httpPath = 'http://' + opts.challengeDomain + '/.well-known/acme-challenge/' + opts.token;

  console.log("echo '" + keyAuth + "' > '" + httpPath + "'");

  return {
    path: httpPath
  , value: keyAuth
  };
};

// { keyAuth }
BACME.challenges['dns-01'] = function (opts) {
  console.log('opts.keyAuth for DNS:');
  console.log(opts.keyAuth);
  return window.crypto.subtle.digest(
    { name: "SHA-256", }
  , textEncoder.encode(opts.keyAuth)
  ).then(function (hash) {
    dnsAuth = btoa(Array.prototype.map.call(new Uint8Array(hash), function (ch) {
      return String.fromCharCode(ch);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

    dnsRecord = '_acme-challenge.' + opts.challengeDomain;

    console.log('DNS TXT Auth:');
    // The name of the record
    console.log(dnsRecord);
    // The TXT record value
    console.log(dnsAuth);

    return {
      type: 'TXT'
    , host: dnsRecord
    , answer: dnsAuth
    };
  });
};

var challengePollUrl;

// { jwk, challengeUrl, accountId (kid) }
BACME.challenges.accept = function (opts) {
  var payload64 = BACME._jsto64({});

  return BACME._importKey(opts.jwk).then(function (abstractKey) {
    var protected64 = BACME._jsto64(
      { nonce: nonce, alg: abstractKey.meta.alg/*'ES256'*/, url: opts.challengeUrl, kid: opts.accountId }
    );
    return BACME._sign({
      abstractKey: abstractKey
    , payload64: payload64
    , protected64: protected64
    });
  }).then(function (signedAccept) {

    nonce = null;
    return window.fetch(
      opts.challengeUrl
    , { mode: 'cors'
      , method: 'POST'
      , headers: { 'Content-Type': 'application/jose+json' }
      , body: JSON.stringify(signedAccept)
      }
    ).then(function (resp) {
      BACME._logHeaders(resp);
      nonce = resp.headers.get('replay-nonce');
      console.log("ACCEPT NONCE:", nonce);

      return resp.json().then(function (reply) {
        challengePollUrl = reply.url;

        console.log('Challenge ACK:');
        console.log(JSON.stringify(reply));
        return reply;
      });
    });
  });
};

BACME.challenges.check = function (opts) {
  return window.fetch(opts.challengePollUrl, { mode: 'cors' }).then(function (resp) {
    BACME._logHeaders(resp);

    return resp.json().then(function (reply) {
      if (/error/.test(reply.type)) {
        return Promise.reject(new Error(reply.detail || reply.type));
      }
      challengePollUrl = reply.url;

      BACME._logBody(reply);

      return reply;
    });
  });
};

var domainKeypair;
var domainJwk;

BACME.generateKeypair = function (opts) {
  var wcOpts = {};

  // ECDSA has only the P curves and an associated bitlength
  if (/^EC/i.test(opts.type)) {
    wcOpts.name = 'ECDSA';
    if (/256/.test(opts.bitlength)) {
      wcOpts.namedCurve = 'P-256';
    }
  }

  // RSA-PSS is another option, but I don't think it's used for Let's Encrypt
  // I think the hash is only necessary for signing, not generation or import
  if (/^RS/i.test(opts.type)) {
    wcOpts.name = 'RSASSA-PKCS1-v1_5';
    wcOpts.modulusLength = opts.bitlength;
    if (opts.bitlength < 2048) {
      wcOpts.modulusLength = opts.bitlength * 8;
    }
    wcOpts.publicExponent = new Uint8Array([0x01, 0x00, 0x01]);
    wcOpts.hash = { name: "SHA-256" };
  }
  var extractable = true;
  return window.crypto.subtle.generateKey(
    wcOpts
  , extractable
  , [ 'sign', 'verify' ]
  );
};
BACME.domains = {};
// TODO factor out from BACME.accounts.generateKeypair even more
BACME.domains.generateKeypair = function (opts) {
  return BACME.generateKeypair(opts).then(function (result) {
    domainKeypair = result;

    return window.crypto.subtle.exportKey(
      "jwk"
    , result.privateKey
    ).then(function (privJwk) {

      domainJwk = privJwk;
      console.log('private jwk:');
      console.log(JSON.stringify(privJwk, null, 2));

      return privJwk;
    });
  });
};

// { serverJwk, domains }
BACME.orders.generateCsr = function (opts) {
  return BACME._importKey(opts.serverJwk).then(function (abstractKey) {
    return Promise.resolve(CSR.generate({ keypair: abstractKey.wcKeypair, domains: opts.domains }));
  });
};

var certificateUrl;

// { csr, jwk, finalizeUrl, accountId }
BACME.orders.finalize = function (opts) {
  var payload64 = BACME._jsto64(
    { csr: opts.csr }
  );

  return BACME._importKey(opts.jwk).then(function (abstractKey) {
    var protected64 = BACME._jsto64(
      { nonce: nonce, alg: abstractKey.meta.alg/*'ES256'*/, url: opts.finalizeUrl, kid: opts.accountId }
    );
    return BACME._sign({
      abstractKey: abstractKey
    , payload64: payload64
    , protected64: protected64
    });
  }).then(function (signedFinal) {

    nonce = null;
    return window.fetch(
      opts.finalizeUrl
    , { mode: 'cors'
      , method: 'POST'
      , headers: { 'Content-Type': 'application/jose+json' }
      , body: JSON.stringify(signedFinal)
      }
    ).then(function (resp) {
      BACME._logHeaders(resp);
      nonce = resp.headers.get('replay-nonce');

      return resp.json().then(function (reply) {
        if (/error/.test(reply.type)) {
          return Promise.reject(new Error(reply.detail || reply.type));
        }
        certificateUrl = reply.certificate;
        BACME._logBody(reply);

        return reply;
      });
    });
  });
};

BACME.orders.receive = function (opts) {
  return window.fetch(
    opts.certificateUrl
  , { mode: 'cors'
    , method: 'GET'
    }
  ).then(function (resp) {
    BACME._logHeaders(resp);
    nonce = resp.headers.get('replay-nonce');

    return resp.text().then(function (reply) {
      BACME._logBody(reply);

      return reply;
    });
  });
};

BACME.orders.check = function (opts) {
  return window.fetch(
    opts.orderUrl
  , { mode: 'cors'
    , method: 'GET'
    }
  ).then(function (resp) {
    BACME._logHeaders(resp);

    return resp.json().then(function (reply) {
      if (/error/.test(reply.type)) {
        return Promise.reject(new Error(reply.detail || reply.type));
      }
      BACME._logBody(reply);

      return reply;
    });
  });
};

}(window));
