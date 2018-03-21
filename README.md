acme-v2.js
==========

A framework for building letsencrypt clients (and other ACME v2 clients), forked from `le-acme-core.js`.

Summary of spec that I'm working off of here: https://git.coolaj86.com/coolaj86/greenlock.js/issues/5#issuecomment-8

In progress

* Mar 15, 2018 - get directory
* Mar 15, 2018 - get nonce
* Mar 15, 2018 - generate account keypair
* Mar 15, 2018 - create account
* Mar 16, 2018 - new order
* Mar 16, 2018 - get challenges
* Mar 20, 2018 - respond to challenges
* Mar 20, 2018 - generate domain keypair
* Mar 20, 2018 - finalize order (submit csr)
* Mar 20, 2018 - poll for status
* Mar 20, 2018 - download certificate
* Mar 20, 2018 - SUCCESS - got a test certificate (hard-coded)
* Mar 21, 2018 - can now accept values (not hard coded)
* Mar 21, 2018 - *mostly* matches le-acme-core.js API

Todo

* completely match api for acme v1 (le-acme-core.js)
* test http and dns challenges
* export http and dns challenge tests
* support ECDSA keys

## API

```
var ACME = require('acme-v2.js').ACME.create({
  RSA: require('rsa-compat').RSA
});
```

```javascript
// Accounts
ACME.registerNewAccount(options, cb)        // returns "regr" registration data

    { email: '<email>'                        //    valid email (server checks MX records)
    , accountKeypair: {                       //    privateKeyPem or privateKeyJwt
        privateKeyPem: '<ASCII PEM>'
      }
    , agreeToTerms: fn (tosUrl, cb) {}        //    must specify agree=tosUrl to continue (or falsey to end)
    }

// Registration
ACME.getCertificate(options, cb)            // returns (err, pems={ privkey (key), cert, chain (ca) })

    { newAuthzUrl: '<url>'                    //    specify acmeUrls.newAuthz
    , newCertUrl: '<url>'                     //    specify acmeUrls.newCert

    , domainKeypair: {
        privateKeyPem: '<ASCII PEM>'
      }
    , accountKeypair: {
        privateKeyPem: '<ASCII PEM>'
      }
    , domains: [ 'example.com' ]

    , setChallenge: fn (hostname, key, val, cb)
    , removeChallenge: fn (hostname, key, cb)
    }

// Discovery URLs
ACME.getAcmeUrls(acmeDiscoveryUrl, cb)      // returns (err, acmeUrls={newReg,newAuthz,newCert,revokeCert})
```

Helpers & Stuff

```javascript
// Constants
ACME.productionServerUrl                // https://acme-v02.api.letsencrypt.org/directory
ACME.stagingServerUrl                   // https://acme-staging-v02.api.letsencrypt.org/directory
ACME.acmeChallengePrefix                // /.well-known/acme-challenge/
```

