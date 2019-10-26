# Example [ACME.js](https://git.rootprojects.org/root/acme.js) Usage

| Built by [Root](https://therootcompany.com) for [Hub](https://rootprojects.org/hub)

ACME.js is a _low-level_ client for Let's Encrypt.

Looking for an **easy**, _high-level_ client? Check out [Greenlock.js](https://git.rootprojects.org/root/greenlock.js).

# Overview

A basic example includes the following:

1. Initialization
    - maintainer contact
    - package user-agent
    - log events
2. Discover API
    - retrieves Terms of Service and API endpoints
3. Get Subscriber Account
    - create an ECDSA (or RSA) Account key in JWK format
    - agree to terms
    - register account by the key
4. Prepare a Certificate Signing Request
    - create a RSA (or ECDSA) Server key in PEM format
    - select domains (as punycode)
    - choose challenges
    - sign CSR
    - order certificate

# Code

The tested-working code for this is in [examples/get-certificate-full.js](https://git.rootprojects.org/root/acme.js/src/branch/master/examples/get-certificate-full.js)

# Walkthrough

Whereas [Greenlock.js](https://git.rootprojects.org/root/greenlock.js) is very much "batteries included",
the goal of ACME.js is to be lightweight and over more control.

## 1. Create an `acme` instance

The maintainer contact is used by Root to notify you of security notices and
bugfixes to ACME.js.

The subscriber contact is used by Let's Encrypt to manage your account and
notify you of renewal failures. In the future we plan to enable some of that,
but allowing for your own branding.

The customer email is provided as an example of what NOT to use as either of the other two.
Typically your customers are NOT directly Let's Encrypt subscribers.

```js
// In many cases all three of these are the same (your email)
// However, this is what they may look like when different:

var maintainerEmail = 'security@devshop.com';
var subscriberEmail = 'support@hostingcompany.com';
var customerEmail = 'jane.doe@gmail.com';
```

The ACME spec requires clients to have RFC 7231 style User Agent.
This will be contstructed automatically using your package name.

```js
var pkg = require('../package.json');
var packageAgent = 'test-' + pkg.name + '/' + pkg.version;
```

Set up your logging facility. It's fine to ignore the logs,
but you'll probably want to log `warning` and `error` at least.

```js
// This is intended to get at important messages without
// having to use even lower-level APIs in the code

function notify(ev, msg) {
    	if ('error' === ev || 'warning' === ev) {
    		errors.push(ev.toUpperCase() + ' ' + msg.message);
    		return;
    	}
    	// be brief on all others
    	console.log(ev, msg.altname || '', msg.status || ''');
}
```

```js
var ACME = require('acme');
var acme = ACME.create({ maintainerEmail, packageAgent, notify });
```

## 2. Fetch the API Directory

ACME defines an API discovery mechanism.

For Let's Encrypt specifically, these are the _production_ and _staging_ URLs:

```js
// Choose either the production or staging URL

var directoryUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
//var directoryUrl = 'https://acme-v02.api.letsencrypt.org/directory'
```

The init function will fetch the API and set internal urls and such accordingly.

```js
await acme.init(directoryUrl);
```

## 3. Create (or import) an Account Keypair

You must create a Subscriber Account using a public/private keypair.

The Account key MUST be different from the server key.

Keypairs.js will use native node crypto or WebCrypto to generate the key, and a lightweight parser and packer to translate between formats.

```js
var Keypairs = require('@root/keypairs');
```

Unless you're multi-tenanted, you only ever need ONE account key. Save it.

```js
// You only need ONE account key, ever, in most cases
// save this and keep it safe. ECDSA is preferred.

var accountKeypair = await Keypairs.generate({ kty: 'EC', format: 'jwk' });
var accountKey = accountKeypair.private;
```

If you already have a key you would like to use, you can import it (as shown in the server key section below).

## 4. Create an ACME Subscriber Account

In order to use Let's Encrypt and ACME.js, you must agree to the respective Subscriber Agreement and Terms.

```js
// This can be `true` or an async function which presents the terms of use

var agreeToTerms = true;

// If you are multi-tenanted or white-labled and need to present the terms of
// use to the Subscriber running the service, you can do so with a function.

var agreeToTerms = async function() {
	return true;
};
```

You create an account with a signed JWS message including your public key, which ACME.js handles for you with your account key.

All messages must be signed with your account key.

```js
console.info('registering new ACME account...');

var account = await acme.accounts.create({
	subscriberEmail,
	agreeToTerms,
	accountKey
});
console.info('created account with id', account.key.kid);
```

## 5. Create (or import) a Server Keypair

You must have a SERVER keypair, which is different from your account keypair.

This isn't part of the ACME protocol, but rather something your Web Server uses and which you must use to sign the request for an SSL certificate, the same as with paid issuers in the days of yore.

In many situations you only ever need ONE of these.

```js
// This is the key used by your WEBSERVER, typically named `privkey.pem`,
// `key.crt`, or `bundle.pem`. RSA may be preferrable for legacy compatibility.

// You can generate it fresh
var serverKeypair = await Keypairs.generate({ kty: 'RSA', format: 'jwk' });
var serverKey = serverKeypair.private;
var serverPem = await Keypairs.export({ jwk: serverKey });
await fs.promises.writeFile('./privkey.pem', serverPem, 'ascii');

// Or you can load it from a file
var serverPem = await fs.promises.readFile('./privkey.pem', 'ascii');
console.info('wrote ./privkey.pem');

var serverKey = await Keypairs.import({ pem: serverPem });
```

## 6. Create a Signed Certificate Request (CSR)

Your domains must be `punycode`-encoded:

```js
var punycode = require('punycode');

var domains = ['example.com', '*.example.com', '你好.example.com'];
domains = domains.map(function(name) {
	return punycode.toASCII(name);
});
```

```js
var CSR = require('@root/csr');
var PEM = require('@root/pem');

var encoding = 'der';
var typ = 'CERTIFICATE REQUEST';

var csrDer = await CSR.csr({ jwk: serverKey, domains, encoding });
var csr = PEM.packBlock({ type: typ, bytes: csrDer });
```

## 7. Choose Domain Validation Strategies

You can use one of the existing http-01 or dns-01 plugins, or you can build your own.

There's a test suite that makes this very easy to do:

-   [acme-dns-01-test](https://git.rootprojects.org/root/acme-dns-01-test.js)
-   [acme-http-01-test](https://git.rootprojects.org/root/acme-http-01-test.js)

```js
// You can pick from existing challenge modules
// which integrate with a variety of popular services
// or you can create your own.
//
// The order of priority will be http-01, tls-alpn-01, dns-01
// dns-01 will always be used for wildcards
// dns-01 should be the only option given for local/private domains

var webroot = require('acme-http-01-webroot').create({});
var challenges = {
	'http-01': webroot,
	'dns-01': {
		init: async function(deps) {
			// includes the http request object to use
		},
		zones: async function(args) {
			// return a list of zones
		},
		set: async function(args) {
			// set a TXT record with the lowest allowable TTL
		},
		get: async function(args) {
			// check the TXT record exists
		},
		remove: async function(args) {
			// remove the TXT record
		},
		// how long to wait after *all* TXTs are set
		// before presenting them for validation
		// (for most this is seconds, for some it may be minutes)
		propagationDelay: 5000
	}
};
```

## 8. Verify Domains & Get an SSL Certificate

```js
console.info('validating domain authorization for ' + domains.join(' '));
var pems = await acme.certificates.create({
	account,
	accountKey,
	csr,
	domains,
	challenges
});
```

## 9. Save the Certificate

```js
var fullchain = pems.cert + '\n' + pems.chain + '\n';

await fs.promises.writeFile('fullchain.pem', fullchain, 'ascii');
console.info('wrote ./fullchain.pem');
```

## 10. Test Drive Your Cert

```js
'use strict';

var https = require('http2');
var fs = require('fs');

var key = fs.readFileSync('./privkey.pem');
var cert = fs.readFileSync('./fullchain.pem');

var server = https.createSecureServer({ key, cert }, function(req, res) {
	res.end('Hello, Encrypted World!');
});

server.listen(443, function() {
	console.info('Listening on', server.address());
});
```

Note: You can allow non-root `node` processes to bind to port 443 using `setcap`:

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

You can also set your domain to localhost by editing your `/etc/hosts`:

`/etc/hosts`:

```txt
127.0.0.1 test.example.com

127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
```
