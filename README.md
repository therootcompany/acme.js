# ACME.js v3 on its way (Nov 1st, 2019)

ACME.js v3 is in private beta and will be available by Nov 1st.

Follow the updates on the [campaign page](https://indiegogo.com/at/greenlock),
and contribute to support the project and get beta access now.

| **acme-v2.js** ([npm](https://www.npmjs.com/package/acme-v2))
| [acme-v2-cli.js](https://git.coolaj86.com/coolaj86/acme-v2-cli.js)
| [greenlock.js](https://git.coolaj86.com/coolaj86/greenlock.js)
| [goldilocks.js](https://git.coolaj86.com/coolaj86/goldilocks.js)

# [acme-v2.js](https://git.coolaj86.com/coolaj86/acme-v2.js) | a [Root](https://therootcompany.com) project

A **Zero (External) Dependency**\* library for building
Let's Encrypt v2 (ACME draft 18) clients and getting Free SSL certificates.

The primary goal of this library is to make it easy to
get Accounts and Certificates through Let's Encrypt.

# Features

- [x] Let's Encrypt&trade; v2 / ACME Draft 12
  - [ ] (in-progress) Let's Encrypt&trade; v2.1 / ACME Draft 18
  - [ ] (in-progress) StartTLS Everywhere&trade;
- [x] Works with any [generic ACME challenge handler](https://git.rootprojects.org/root/acme-challenge-test.js)
  - [x] **http-01** for single or multiple domains per certificate
  - [x] **dns-01** for wildcards, localhost, private networks, etc
- [x] VanillaJS
  - [x] Zero External Dependencies
  - [x] Safe, Efficient, Maintained
  - [x] Works in Node v6+
  - [ ] (v2) Works in Web Browsers (See [Demo](https://greenlock.domains))

\* <small>The only required dependencies were built by us, specifically for this and related libraries.
There are some, truly optional, backwards-compatibility dependencies for node v6.</small>

## Looking for Quick 'n' Easy&trade;?

If you want something that's more "batteries included" give
[greenlock.js](https://git.coolaj86.com/coolaj86/greenlock.js)
a try.

- [greenlock.js](https://git.coolaj86.com/coolaj86/greenlock.js)

## v1.7+: Transitional v2 Support

By the end of June 2019 we expect to have completed the migration to Let's Encrypt v2.1 (ACME draft 18).

Although the draft 18 changes themselves don't requiring breaking the API,
we've been keeping backwards compatibility for a long time and the API has become messy.

We're taking this **mandatory ACME update** as an opportunity to **clean up** and **greatly simplify**
the code with a fresh new release.

As of **v1.7** we started adding **transitional support** for the **next major version**, v2.0 of acme-v2.js.
We've been really good about backwards compatibility for

## Recommended Example

Due to the upcoming changes we've removed the old documentation.

Instead we recommend that you take a look at the
[Digital Ocean DNS-01 Example](https://git.rootprojects.org/root/acme-v2.js/src/branch/master/examples/dns-01-digitalocean.js)

- [examples/dns-01-digitalocean.js](https://git.rootprojects.org/root/acme-v2.js/src/branch/master/examples/dns-01-digitalocean.js)

That's not exactly the new API, but it's close.

## Let's Encrypt v02 Directory URLs

```
# Production URL
https://acme-v02.api.letsencrypt.org/directory
```

```
# Staging URL
https://acme-staging-v02.api.letsencrypt.org/directory
```

<!--
## How to build ACME clients

As this is intended to build ACME clients, there is not a simple 2-line example
(and if you want that, see [greenlock-express.js](https://git.coolaj86.com/coolaj86/greenlock-express.js)).

I'd recommend first running the example CLI client with a test domain and then investigating the files used for that example:

```bash
node examples/cli.js
```

The example cli has the following prompts:

```
What web address(es) would you like to get certificates for? (ex: example.com,*.example.com)
What challenge will you be testing today? http-01 or dns-01? [http-01]
What email should we use? (optional)
What API style would you like to test? v1-compat or promise? [v1-compat]

Put the string 'mBfh0SqaAV3MOK3B6cAhCbIReAyDuwuxlO1Sl70x6bM.VNAzCR4THe4czVzo9piNn73B1ZXRLaB2CESwJfKkvRM' into a file at 'example.com/.well-known/acme-challenge/mBfh0SqaAV3MOK3B6cAhCbIReAyDuwuxlO1Sl70x6bM'

echo 'mBfh0SqaAV3MOK3B6cAhCbIReAyDuwuxlO1Sl70x6bM.VNAzCR4THe4czVzo9piNn73B1ZXRLaB2CESwJfKkvRM' > 'example.com/.well-known/acme-challenge/mBfh0SqaAV3MOK3B6cAhCbIReAyDuwuxlO1Sl70x6bM'

Then hit the 'any' key to continue...
```

When you've completed the challenge you can hit a key to continue the process.

If you place the certificate you receive back in `tests/fullchain.pem`
you can then test it with `examples/https-server.js`.

```
examples/cli.js
examples/genkeypair.js
tests/compat.js
examples/https-server.js
examples/http-server.js
```

-->

## API

Status: Small, but breaking changes coming in v2

This API is a simple evolution of le-acme-core,
but tries to provide a better mapping to the new draft 11 APIs.

```js
var ACME = require('acme-v2').ACME.create({
	// used for overriding the default user-agent
	userAgent: 'My custom UA String',
	getUserAgentString: function(deps) {
		return 'My custom UA String';
	},

	// don't try to validate challenges locally
	skipChallengeTest: false,
	skipDryRun: false,

	// ask if the certificate can be issued up to 10 times before failing
	retryPoll: 8,
	// ask if the certificate has been validated up to 6 times before cancelling
	retryPending: 4,
	// Wait 1000ms between retries
	retryInterval: 1000,
	// Wait 10,000ms after deauthorizing a challenge before retrying
	deauthWait: 10 * 1000
});

// Discover Directory URLs
ACME.init(acmeDirectoryUrl); // returns Promise<acmeUrls={keyChange,meta,newAccount,newNonce,newOrder,revokeCert}>

// Accounts
ACME.accounts.create(options); // returns Promise<regr> registration data

options = {
	email: '<email>', // valid email (server checks MX records)
	accountKeypair: {
		//    privateKeyPem or privateKeyJwt
		privateKeyPem: '<ASCII PEM>'
	},
	agreeToTerms: function(tosUrl) {} //    should Promise the same `tosUrl` back
};

// Registration
ACME.certificates.create(options); // returns Promise<pems={ privkey (key), cert, chain (ca) }>

options = {
	domainKeypair: {
		privateKeyPem: '<ASCII PEM>'
	},
	accountKeypair: {
		privateKeyPem: '<ASCII PEM>'
	},
	domains: ['example.com'],

	getZones: function(opts) {}, // should Promise an array of domain zone names
	setChallenge: function(opts) {}, // should Promise the record id, or name
	removeChallenge: function(opts) {} // should Promise null
};
```

# Changelog

- v1.8
  - more transitional prepwork for new v2 API
  - support newer (simpler) dns-01 and http-01 libraries
- v1.5
  - perform full test challenge first (even before nonce)
- v1.3
  - Use node RSA keygen by default
  - No non-optional external deps!
- v1.2
  - fix some API out-of-specness
  - doc some magic numbers (status)
  - updated deps
- v1.1.0
  - reduce dependencies (use lightweight @coolaj86/request instead of request)
- v1.0.5 - cleanup logging
- v1.0.4 - v6- compat use `promisify` from node's util or bluebird
- v1.0.3 - documentation cleanup
- v1.0.2
  - use `options.contact` to provide raw contact array
  - made `options.email` optional
  - file cleanup
- v1.0.1
  - Compat API is ready for use
  - Eliminate debug logging
- Apr 10, 2018 - tested backwards-compatibility using greenlock.js
- Apr 5, 2018 - export http and dns challenge tests
- Apr 5, 2018 - test http and dns challenges (success and failure)
- Apr 5, 2018 - test subdomains and its wildcard
- Apr 5, 2018 - test two subdomains
- Apr 5, 2018 - test wildcard
- Apr 5, 2018 - completely match api for acme v1 (le-acme-core.js)
- Mar 21, 2018 - _mostly_ matches le-acme-core.js API
- Mar 21, 2018 - can now accept values (not hard coded)
- Mar 20, 2018 - SUCCESS - got a test certificate (hard-coded)
- Mar 20, 2018 - download certificate
- Mar 20, 2018 - poll for status
- Mar 20, 2018 - finalize order (submit csr)
- Mar 20, 2018 - generate domain keypair
- Mar 20, 2018 - respond to challenges
- Mar 16, 2018 - get challenges
- Mar 16, 2018 - new order
- Mar 15, 2018 - create account
- Mar 15, 2018 - generate account keypair
- Mar 15, 2018 - get nonce
- Mar 15, 2018 - get directory

# Legal

[acme-v2.js](https://git.coolaj86.com/coolaj86/acme-v2.js) |
MPL-2.0 |
[Terms of Use](https://therootcompany.com/legal/#terms) |
[Privacy Policy](https://therootcompany.com/legal/#privacy)
