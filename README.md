# Bluecrypt&trade; [ACME.js](https://git.rootprojects.org/root/bluecrypt-acme.js) | A [Root](https://rootprojects.org/acme/) project

Free SSL Certificates from Let's Encrypt, right in your Web Browser

Lightweight. Fast. Modern Crypto. Zero dependecies.

(a port of [acme.js](https://git.coolaj86.com/coolaj86/acme-v2.js) to the browser)

# Features

| 15k gzipped | 55k minified | 88k (2,500 loc) source with comments |

* [x] Let's Encrypt
  * [x] ACME draft 15 (supports POST-as-GET)
  * [x] Secure support for EC and RSA for account and server keys
  * [x] Simple and lightweight PEM, DER, ASN1, X509, and CSR implementations
* [x] VanillaJS, Zero Dependencies

# Online Demos

* Greenlock for the Web <https://greenlock.domains>
* Bluecrypt ACME Demo <https://rootprojects.org/acme/>

We expect that our hosted versions will meet all of yours needs.
If they don't, please open an issue to let us know why.

We'd much rather improve the app than have a hundred different versions running in the wild.
However, in keeping to our values we've made the source visible for others to inspect, improve, and modify.

# QuickStart

Bluecrypt ACME embeds [Keypairs.js](https://git.rootprojects.org/root/bluecrypt-keypairs.js)
and [CSR.js](https://git.rootprojects.org/root/bluecrypt-csr.js)

`bluecrypt-acme.js`
```html
<script src="https://rootprojects.org/acme/bluecrypt-acme.js"></script>
```

`bluecrypt-acme.min.js`
```html
<script src="https://rootprojects.org/acme/bluecrypt-acme.min.js"></script>
```

You can see `index.html` and `app.js` in the repo for full example usage.

### Instantiate Bluecrypt ACME

Although built for Let's Encrypt, Bluecrypt ACME will work with any server
that supports draft-15 of the ACME spec (includes POST-as-GET support).

The `init()` method takes a _directory url_ and initializes internal state according to its response.

```js
var acme = ACME.create({});
acme.init('https://acme-staging-v02.api.letsencrypt.org/directory').then(function () {
  // Ready to use, show page
  $('body').hidden = false;
});
```

### Create ACME Account with Let's Encrypt

ACME Accounts are key and device based, with an email address as a backup identifier.

A public account key must be registered before an SSL certificate can be requested.

```js
var accountPrivateKey;
var account;

Keypairs.generate({ kty: 'EC' }).then(function (pair) {
  accountPrivateKey = pair.private;

  return acme.accounts.create({
    agreeToTerms: function (tos) {
      if (window.confirm("Do you agree to the Bluecrypt and Let's Encrypt Terms of Service?")) {
        return Promise.resolve(tos);
      }
    }
  , accountKeypair: { privateKeyJwk: pair.private }
  , email: $('.js-email-input').value
  }).then(function (_account) {
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

Keypairs.generate({ kty: 'EC' }).then(function (pair) {
  serverPrivateKey = pair.private;

  return acme.certificates.create({
    agreeToTerms: function (tos) {
      return tos;
    }
  , account: account
  , accountKeypair: { privateKeyJwk: accountPrivateKey }
  , serverKeypair: { privateKeyJwk: serverPrivateKey }
  , domains: ['example.com','www.example.com']
  , challenges: challenges // must be implemented
  , skipDryRun: true
  }).then(function (results) {
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
    set: function (opts) {
      console.info('http-01 set challenge:');
      console.info(opts.challengeUrl);
      console.info(opts.keyAuthorization);
      while (!window.confirm("Upload the challenge file before continuing.")) {}
      return Promise.resolve();
    }
  , remove: function (opts) {
      console.log('http-01 remove challenge:', opts.challengeUrl);
      return Promise.resolve();
    }
  }
};
```

# Full Documentation

See [acme.js](https://git.coolaj86.com/coolaj86/acme-v2.js).

Aside from the loading instructions (`npm` and `require` instead of `script` tags),
the usage is identical to the node version.

That said, the two may leap-frog a little from time to time
(for example, the browser version is just a touch ahead at the moment).

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

Bluecrypt&trade; and Greenlock&trade; are [trademarks](https://rootprojects.org/legal/#trademark) of AJ ONeal

The rule of thumb is "attribute, but don't confuse". For example:

> Built with [Root](https://rootprojects.org)'s [Bluecrypt ACME](https://git.rootprojects.org/root/bluecrypt-acme.js).

Please [contact us](mailto:aj@therootcompany.com) if have any questions in regards to our trademark,
attribution, and/or visible source policies. We want to help to community as we build great software.

[bluecrypt.js](https://git.coolaj86.com/coolaj86/bluecrypt.js) |
MPL-2.0 |
[Terms of Use](https://therootcompany.com/legal/#terms) |
[Privacy Policy](https://therootcompany.com/legal/#privacy)
