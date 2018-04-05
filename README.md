acme-v2.js
==========

| Sponsored by [ppl](https://ppl.family)

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
* Apr  5, 2018 - completely match api for acme v1 (le-acme-core.js)
* Apr  5, 2018 - test wildcard

Todo

* test http and dns challenges
* export http and dns challenge tests
* support ECDSA keys

## Let's Encrypt Directory URLs

```
# Production URL
https://acme-v02.api.letsencrypt.org/directory
```

```
# Staging URL
https://acme-staging-v02.api.letsencrypt.org/directory
```

## API

```
var ACME = require('acme-v2').ACME.create({
  RSA: require('rsa-compat').RSA

  // other overrides
, request: require('request')
, promisify: require('util').promisify

  // used for constructing user-agent
, os: require('os')
, process: require('process')

  // used for overriding the default user-agent
, userAgent: 'My custom UA String'
, getUserAgentString: function (deps) { return 'My custom UA String'; }
});
```

```javascript
// Accounts
ACME.accounts.create(options)                 // returns Promise<regr> registration data

    { email: '<email>'                        //    valid email (server checks MX records)
    , accountKeypair: {                       //    privateKeyPem or privateKeyJwt
        privateKeyPem: '<ASCII PEM>'
      }
    , agreeToTerms: fn (tosUrl) {}            //    returns Promise with tosUrl
    }


// Registration
ACME.certificates.create(options)             // returns Promise<pems={ privkey (key), cert, chain (ca) }>

    { newAuthzUrl: '<url>'                    //    specify acmeUrls.newAuthz
    , newCertUrl: '<url>'                     //    specify acmeUrls.newCert

    , domainKeypair: {
        privateKeyPem: '<ASCII PEM>'
      }
    , accountKeypair: {
        privateKeyPem: '<ASCII PEM>'
      }
    , domains: [ 'example.com' ]

    , setChallenge: fn (hostname, key, val)   // return Promise
    , removeChallenge: fn (hostname, key)     // return Promise
    }


// Discovery URLs
ACME.init(acmeDirectoryUrl)                   // returns Promise<acmeUrls={keyChange,meta,newAccount,newNonce,newOrder,revokeCert}>
```

Helpers & Stuff

```javascript
// Constants
ACME.acmeChallengePrefix                // /.well-known/acme-challenge/
```

