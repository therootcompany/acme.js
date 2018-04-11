acme-v2.js (draft 11)
==========

| Sponsored by [ppl](https://ppl.family)

A framework for building letsencrypt v2 (IETF ACME draft 11) clients, successor to `le-acme-core.js`.

Summary of spec that I'm working off of here: https://git.coolaj86.com/coolaj86/greenlock.js/issues/5#issuecomment-8

## Let's Encrypt Directory URLs

```
# Production URL
https://acme-v02.api.letsencrypt.org/directory
```

```
# Staging URL
https://acme-staging-v02.api.letsencrypt.org/directory
```

## Two API versions, Two Implementations

This library (acme-v2.js) supports ACME [*draft 11*](https://tools.ietf.org/html/draft-ietf-acme-acme-11),
otherwise known as Let's Encrypt v2 (or v02).

  * ACME draft 11
  * Let's Encrypt v2
  * Let's Encrypt v02

The predecessor (le-acme-core) supports Let's Encrypt v1 (or v01), which was a
[hodge-podge of various drafts](https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md)
of the ACME spec early on.

  * ACME early draft
  * Let's Encrypt v1
  * Let's Encrypt v01

This library maintains compatibility with le-acme-core so that it can be used as a **drop-in replacement**
and requires **no changes to existing code**,
but also provides an updated API more congruent with draft 11.

## le-acme-core-compatible API (recommended)

Status: Stable, Locked, Bugfix-only

```
var RSA = require('rsa-compat').RSA;
var acme = require('acme-v2/compat.js').ACME.create({ RSA: RSA });

//
// Use exactly the same as le-acme-core
//
```

See documentation at <https://git.coolaj86.com/coolaj86/le-acme-core.js>

## draft API (dev)

Status: Almost stable, not locked

This API is a simple evolution of le-acme-core,
but tries to provide a better mapping to the new draft 11 APIs.

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

  // don't try to validate challenges locally
, skipChallengeTest: false
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
ACME.challengePrefixes['http-01']             // '/.well-known/acme-challenge'
ACME.challengePrefixes['dns-01']              // '_acme-challenge'
```

Todo
----

* support ECDSA keys
* Apr  5, 2018 - appears that sometimes 'pending' status cannot be progressed to 'processing' nor 'deactivated'
  * this may be a bug in the staging API as it appears it cannot be cancelled either, but returns success status code

Changelog
---------

* v1.0.0
  * Compat API is ready for use
  * Eliminate debug logging
* Apr 10, 2018 - tested backwards-compatibility using greenlock.js
* Apr  5, 2018 - export http and dns challenge tests
* Apr  5, 2018 - test http and dns challenges (success and failure)
* Apr  5, 2018 - test subdomains and its wildcard
* Apr  5, 2018 - test two subdomains
* Apr  5, 2018 - test wildcard
* Apr  5, 2018 - completely match api for acme v1 (le-acme-core.js)
* Mar 21, 2018 - *mostly* matches le-acme-core.js API
* Mar 21, 2018 - can now accept values (not hard coded)
* Mar 20, 2018 - SUCCESS - got a test certificate (hard-coded)
* Mar 20, 2018 - download certificate
* Mar 20, 2018 - poll for status
* Mar 20, 2018 - finalize order (submit csr)
* Mar 20, 2018 - generate domain keypair
* Mar 20, 2018 - respond to challenges
* Mar 16, 2018 - get challenges
* Mar 16, 2018 - new order
* Mar 15, 2018 - create account
* Mar 15, 2018 - generate account keypair
* Mar 15, 2018 - get nonce
* Mar 15, 2018 - get directory
