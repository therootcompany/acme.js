# [ACME.js](https://git.rootprojects.org/root/bluecrypt-acme.js)

Free SSL Certificates from Let's Encrypt, for Node.js and Web Browsers

Lightweight. Fast. Modern Crypto. Zero dependecies.

# Features

| 15k gzipped | 55k minified | 88k (2,500 loc) source with comments |

-   [x] Let's Encrypt v2.1+ (November 2019)
    -   [x] ACME draft 15 (supports POST-as-GET)
    -   [x] Secure support for EC and RSA for account and server keys
    -   [x] Simple and lightweight PEM, DER, ASN1, X509, and CSR implementations
-   [x] Supports International Domain Names (i.e. `.中国`)
-   [x] VanillaJS, Zero External Dependencies
    -   [x] Node.js
    -   [x] WebPack

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

# QuickStart

To make it easy to generate, encode, and decode keys and certificates,
ACME.js embeds [Keypairs.js](https://git.rootprojects.org/root/bluecrypt-keypairs.js)
and [CSR.js](https://git.rootprojects.org/root/bluecrypt-csr.js)

## Node.js

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

`acme.js`

```html
<script src="https://unpkg.com/@root/acme@3.0.0/dist/acme.js"></script>
```

`acme.min.js`

```html
<script src="https://unpkg.com/@root/acme@3.0.0/dist/acme.min.js"></script>
```

Use

```js
var ACME = window['@root/acme'];
```

## Examples

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
var accountPrivateKey;
var account;

Keypairs.generate({ kty: 'EC' }).then(function(pair) {
	accountPrivateKey = pair.private;

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
			accountKeypair: { privateKeyJwk: pair.private },
			subscriberEmail: $('.js-email-input').value
		})
		.then(function(_account) {
			account = _account;
		});
});
```

### Get Free 90-day SSL Certificate

Creating an ACME "order" for a 90-day SSL certificate requires use of the account private key,
the names of domains to be secured, and a distinctly separate server private key.

A domain ownership verification "challenge" (uploading a file to an unsecured HTTP url or setting a DNS record)
is a required part of the process, which requires `set` and `remove` callbacks/promises.

```js
var serverPrivateKey;

Keypairs.generate({ kty: 'EC' }).then(function(pair) {
	serverPrivateKey = pair.private;

	return acme.certificates
		.create({
			agreeToTerms: function(tos) {
				return tos;
			},
			account: account,
			accountKeypair: { privateKeyJwk: accountPrivateKey },
			serverKeypair: { privateKeyJwk: serverPrivateKey },
			domains: ['example.com', 'www.example.com'],
			challenges: challenges, // must be implemented
			customerEmail: null,
			skipDryRun: true
		})
		.then(function(results) {
			console.log('Got SSL Certificate:');
			console.log(results.expires);
			console.log(results.cert);
			console.log(results.chain);
		});
});
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
			) {}
			return Promise.resolve();
		},
		remove: function(opts) {
			console.log('http-01 remove challenge:', opts.challengeUrl);
			return Promise.resolve();
		}
	}
};
```

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
git clone https://git.rootprojects.org/root/bluecrypt-acme.js
pushd bluecrypt-acme.js/

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

> Built with [ACME.js](https://git.rootprojects.org/root/bluecrypt-acme.js) (a [Root](https://rootprojects.org) project).

Please [contact us](mailto:aj@therootcompany.com) if have any questions in regards to our trademark,
attribution, and/or visible source policies. We want to build great software and a great community.

[ACME.js](https://git.rootprojects.org/root/acme.js) |
MPL-2.0 |
[Terms of Use](https://therootcompany.com/legal/#terms) |
[Privacy Policy](https://therootcompany.com/legal/#privacy)
