# [ACME.js](https://git.rootprojects.org/root/acme.js) v3

| Built by [Root](https://therootcompany.com) for [Greenlock](https://greenlock.domains)

Free SSL Certificates from Let's Encrypt, for Node.js and Web Browsers

Lightweight. Fast. Modern Crypto. Zero external dependecies.

# Features

| 15k gzipped | 55k minified | 88k (2,500 loc) source with comments |

The primary goal of this library is to make it easy to
get Accounts and Certificates through Let's Encrypt.

-   [x] Let's Encrypt v2 / ACME RFC 8555 (November 2019)
    -   [x] POST-as-GET support
    -   [x] Secure support for EC and RSA for account and server keys
    -   [x] Simple and lightweight PEM, DER, ASN1, X509, and CSR implementations
    -   [ ] (in-progress) StartTLS Everywhere&trade;
-   [x] Supports International Domain Names (i.e. `.中国`)
-   [x] Works with any [generic ACME challenge handler](https://git.rootprojects.org/root/acme-challenge-test.js)
    -   [x] **http-01** for single or multiple domains per certificate
    -   [x] **dns-01** for wildcards, localhost, private networks, etc
-   [x] VanillaJS, Zero External Dependencies
    -   [x] Safe, Efficient, Maintained
    -   [x] Node.js\* (v6+)
    -   [x] WebPack
-   [x] Online Demo
    -   See https://greenlock.domains

\* Although we use `async/await` in the examples, the code is written in CommonJS,
with Promises, so you can use it in Node.js and Browsers without transpiling.

# Want Quick and Easy?

ACME.js is a low-level tool for building Let's Encrypt clients in Node and Browsers.

If you're looking for maximum convenience, try
[Greenlock.js](https://git.rootprojects.org/root/greenlock-express.js).

-   <https://git.rootprojects.org/root/greenlock-express.js>

# Online Demos

-   Greenlock for the Web <https://greenlock.domains>
-   ACME.js Demo <https://rootprojects.org/acme/>

We expect that our hosted versions will meet all of yours needs.
If they don't, please open an issue to let us know why.

We'd much rather improve the app than have a hundred different versions running in the wild.
However, in keeping to our values we've made the source visible for others to inspect, improve, and modify.

# Install

To make it easy to generate, encode, and decode keys and certificates,
ACME.js uses [Keypairs.js](https://git.rootprojects.org/root/keypairs.js)
and [CSR.js](https://git.rootprojects.org/root/csr.js)

## Node.js

```js
npm install --save @root/acme
```

```js
var ACME = require('@root/acme');
```

## WebPack

```html
<meta charset="UTF-8" />
```

(necessary in case the webserver headers don't specify `plain/text; charset="UTF-8"`)

```js
var ACME = require('@root/acme');
```

## Vanilla JS

```html
<meta charset="UTF-8" />
```

(necessary in case the webserver headers don't specify `plain/text; charset="UTF-8"`)

```html
<script src="https://unpkg.com/@root/acme@3.0.0/dist/acme.all.js"></script>
```

`acme.min.js`

```html
<script src="https://unpkg.com/@root/acme@3.0.0/dist/acme.all.min.js"></script>
```

Use

```js
var ACME = window['@root/acme'];
```

## Usage Examples

You can see `tests/index.js`, `examples/index.html`, `examples/app.js` in the repo for full example usage.

### Emails: Maintainer vs Subscriber vs Customer

-   `maintainerEmail` should be the email address of the **author of the code**.
    This person will receive critical security and API change notifications.
-   `subscriberEmail` should be the email of the **admin of the hosting service**.
    This person agrees to the Let's Encrypt Terms of Service and will be notified
    when a certificate fails to renew.
-   `customerEmail` should be the email of individual who owns the domain.
    This is optional (not currently implemented).

Generally speaking **YOU** are the _maintainer_ and you **or your employer** is the _subscriber_.

If you (or your employer) is running any type of service
you **SHOULD NOT** pass the _customer_ email as the subscriber email.

If you are not running a service (you may be building a CLI, for example),
then you should prompt the user for their email address, and they are the subscriber.

### Overview

1. Create an instance of ACME.js
2. Create and SAVE a Subscriber Account private key
3. Retrieve the Let's Encrypt Subscriber account (with the key)
    - the account will be created if it doesn't exist
4. Create a Server Key
    - this should be per-server, or perhaps per-end-user
5. Create a Certificate Signing Request
    - International Domain Names must be converted with `punycode`
6. Create an ACME Order
    - use a challenge plugin for HTTP-01 or DNS-01 challenges

### Instantiate ACME.js

Although built for Let's Encrypt, ACME.js will work with any server
that supports draft-15 of the ACME spec (includes POST-as-GET support).

The `init()` method takes a _directory url_ and initializes internal state according to its response.

```js
var acme = ACME.create({
	maintainerEmail: 'jon@example.com'
});
acme.init('https://acme-staging-v02.api.letsencrypt.org/directory').then(
	function() {
		// Ready to use, show page
		$('body').hidden = false;
	}
);
```

### Create ACME Account with Let's Encrypt

ACME Accounts are key and device based, with an email address as a backup identifier.

A public account key must be registered before an SSL certificate can be requested.

```js
var accountPrivateJwk;
var account;

Keypairs.generate({ kty: 'EC' }).then(function(pair) {
	accountPrivateJwk = pair.private;

	return acme.accounts
		.create({
			agreeToTerms: function(tos) {
				if (
					window.confirm(
						"Do you agree to the ACME.js and Let's Encrypt Terms of Service?"
					)
				) {
					return Promise.resolve(tos);
				}
			},
			accountKey: pair.private,
			subscriberEmail: $('.js-email-input').value
		})
		.then(function(_account) {
			account = _account;
		});
});
```

### Generate a Certificate Private Key

```js
var certKeypair = await Keypairs.generate({ kty: 'RSA' });
var pem = await Keypairs.export({
	jwk: certKeypair.private,
	encoding: 'pem'
});

// This should be saved as `privkey.pem`
console.log(pem);
```

### Generate a CSR

The easiest way to generate a Certificate Signing Request will be either with `openssl` or with `@root/CSR`.

```js
var CSR = require('@root/csr');
var Enc = require('@root/encoding');

// 'subject' should be first in list
// the domains may be in any order, but it should be consistent
var sortedDomains = ['example.com', 'www.example.com'];
var csr = await CSR.csr({
	jwk: certKeypair.private,
	domains: sortedDomains,
	encoding: 'der'
}).then(function(der) {
	return Enc.bufToUrlBase64(der);
});
```

### Get Free 90-day SSL Certificate

Creating an ACME "order" for a 90-day SSL certificate requires use of the account private key,
the names of domains to be secured, and a distinctly separate server private key.

A domain ownership verification "challenge" (uploading a file to an unsecured HTTP url or setting a DNS record)
is a required part of the process, which requires `set` and `remove` callbacks/promises.

```js
var certinfo = await acme.certificates.create({
	agreeToTerms: function(tos) {
		return tos;
	},
	account: account,
	accountKey: accountPrivateJwk,
	csr: csr,
	domains: sortedDomains,
	challenges: challenges, // must be implemented
	customerEmail: null,
	skipChallengeTests: false,
	skipDryRun: false
});

console.log('Got SSL Certificate:');
console.log(results.expires);

// This should be saved as `fullchain.pem`
console.log([results.cert, results.chain].join('\n'));
```

### Example "Challenge" Implementation

Typically here you're just presenting some sort of dialog to the user to ask them to
upload a file or set a DNS record.

It may be possible to do something fancy like using OAuth2 to login to Google Domanis
to set a DNS address, etc, but it seems like that sort of fanciness is probably best
reserved for server-side plugins.

```js
var challenges = {
	'http-01': {
		set: function(opts) {
			console.info('http-01 set challenge:');
			console.info(opts.challengeUrl);
			console.info(opts.keyAuthorization);
			while (
				!window.confirm('Upload the challenge file before continuing.')
			) {
				// spin and wait for the user to upload the challenge file
			}
			return Promise.resolve();
		},
		remove: function(opts) {
			console.log('http-01 remove challenge:', opts.challengeUrl);
			return Promise.resolve();
		}
	}
};
```

Many challenge plugins are already available for popular platforms.

Search `acme-http-01-` or `acme-dns-01-` on npm to find more.

-   [x] DNS-01 Challenges
    -   CloudFlare
    -   [Digital Ocean](https://git.rootprojects.org/root/acme-dns-01-digitalocean.js)
    -   [DNSimple](https://git.rootprojects.org/root/acme-dns-01-dnsimple.js)
    -   [DuckDNS](https://git.rootprojects.org/root/acme-dns-01-duckdns.js)
    -   [GoDaddy](https://git.rootprojects.org/root/acme-dns-01-godaddy.js)
    -   [Gandi](https://git.rootprojects.org/root/acme-dns-01-gandi.js)
    -   [NameCheap](https://git.rootprojects.org/root/acme-dns-01-namecheap.js)
    -   [Name&#46;com](https://git.rootprojects.org/root/acme-dns-01-namedotcom.js)
    -   Route53 (AWS)
    -   [Vultr](https://git.rootprojects.org/root/acme-dns-01-vultr.js)
    -   Build your own
-   [x] HTTP-01 Challenges
    -   [In-Memory](https://git.rootprojects.org/root/acme-http-01-standalone.js) (Standalone)
    -   [FileSystem](https://git.rootprojects.org/root/acme-http-01-webroot.js) (WebRoot)
    -   S3 (AWS, Digital Ocean, etc)
-   [x] TLS-ALPN-01 Challenges
    -   Contact us to learn about Greenlock Pro

# IDN - International Domain Names

Convert domain names to `punycode` before creating the certificate:

```js
var punycode = require('punycode');

acme.certificates.create({
	// ...
	domains: ['example.com', 'www.example.com'].map(function(name) {
		return punycode.toASCII(name);
	})
});
```

The punycode library itself is lightweight and dependency-free.
It is available both in node and for browsers.

# Testing

You will need to use one of the [`acme-dns-01-*` plugins](https://www.npmjs.com/search?q=acme-dns-01-)
to run the test locally.

You'll also need a `.env` that looks something like the one in `examples/example.env`:

```bash
ENV=DEV
SUBSCRIBER_EMAIL=letsencrypt+staging@example.com
BASE_DOMAIN=test.example.com
CHALLENGE_TYPE=dns-01
CHALLENGE_PLUGIN=acme-dns-01-digitalocean
CHALLENGE_OPTIONS='{"token":"xxxxxxxxxxxx"}'
```

For example:

```bash
# Get the repo and change directories into it
git clone https://git.rootprojects.org/root/acme.js
pushd acme.js/

# Install the challenge plugin you'll use for the tests
npm install --save-dev acme-dns-01-digitalocean

# Copy the sample .env file
rsync -av examples/example.env .env

# Edit the config file to use a domain in your account, and your API token
#vim .env
code .env

# Run the tests
node tests/index.js
```

# Developing

You can see `<script>` tags in the `index.html` in the repo, which references the original
source files.

Join `@rootprojects` `#general` on [Keybase](https://keybase.io) if you'd like to chat with us.

# Commercial Support

We have both commercial support and commercial licensing available.

You're welcome to [contact us](mailto:aj@therootcompany.com) in regards to IoT, On-Prem,
Enterprise, and Internal installations, integrations, and deployments.

We also offer consulting for all-things-ACME and Let's Encrypt.

# Legal &amp; Rules of the Road

Greenlock&trade; is a [trademark](https://rootprojects.org/legal/#trademark) of AJ ONeal

The rule of thumb is "attribute, but don't confuse". For example:

> Built with [ACME.js](https://git.rootprojects.org/root/acme.js) (a [Root](https://rootprojects.org) project).

Please [contact us](mailto:aj@therootcompany.com) if have any questions in regards to our trademark,
attribution, and/or visible source policies. We want to build great software and a great community.

[ACME.js](https://git.rootprojects.org/root/acme.js) |
MPL-2.0 |
[Terms of Use](https://therootcompany.com/legal/#terms) |
[Privacy Policy](https://therootcompany.com/legal/#privacy)
