/*global Promise*/
(function (exports) {
'use strict';

var Keypairs = exports.Keypairs = {};

Keypairs._stance = "We take the stance that if you're knowledgeable enough to"
  + " properly and securely use non-standard crypto then you shouldn't need Bluecrypt anyway.";
Keypairs._universal = "Bluecrypt only supports crypto with standard cross-browser and cross-platform support.";
Keypairs.generate = function (opts) {
  var wcOpts = {};
  if (!opts) {
    opts = {};
  }
  if (!opts.kty) {
    opts.kty = 'EC';
  }

  // ECDSA has only the P curves and an associated bitlength
  if (/^EC/i.test(opts.kty)) {
    wcOpts.name = 'ECDSA';
    if (!opts.namedCurve) {
      opts.namedCurve = 'P-256';
    }
    wcOpts.namedCurve = opts.namedCurve; // true for supported curves
    if (/256/.test(wcOpts.namedCurve)) {
      wcOpts.namedCurve = 'P-256';
      wcOpts.hash = { name: "SHA-256" };
    } else if (/384/.test(wcOpts.namedCurve)) {
      wcOpts.namedCurve = 'P-384';
      wcOpts.hash = { name: "SHA-384" };
    } else {
      return Promise.Reject(new Error("'" + wcOpts.namedCurve + "' is not an NIST approved ECDSA namedCurve. "
        + " Please choose either 'P-256' or 'P-384'. "
        + Keypairs._stance));
    }
  } else if (/^RSA$/i.test(opts.kty)) {
    // Support PSS? I don't think it's used for Let's Encrypt
    wcOpts.name = 'RSASSA-PKCS1-v1_5';
    if (!opts.modulusLength) {
      opts.modulusLength = 2048;
    }
    wcOpts.modulusLength = opts.modulusLength;
    if (wcOpts.modulusLength >= 2048 && wcOpts.modulusLength < 3072) {
      // erring on the small side... for no good reason
      wcOpts.hash = { name: "SHA-256" };
    } else if (wcOpts.modulusLength >= 3072 && wcOpts.modulusLength < 4096) {
      wcOpts.hash = { name: "SHA-384" };
    } else if (wcOpts.modulusLength < 4097) {
      wcOpts.hash = { name: "SHA-512" };
    } else {
      // Public key thumbprints should be paired with a hash of similar length,
      // so anything above SHA-512's keyspace would be left under-represented anyway.
      return Promise.Reject(new Error("'" + wcOpts.modulusLength + "' is not within the safe and universally"
        + " acceptable range of 2048-4096. Typically you should pick 2048, 3072, or 4096, though other values"
        + " divisible by 8 are allowed. " + Keypairs._stance));
    }
    // TODO maybe allow this to be set to any of the standard values?
    wcOpts.publicExponent = new Uint8Array([0x01, 0x00, 0x01]);
  } else {
    return Promise.Reject(new Error("'" + opts.kty + "' is not a well-supported key type."
      + Keypairs._universal
      + " Please choose either 'EC' or 'RSA' keys."));
  }

  var extractable = true;
  return window.crypto.subtle.generateKey(
    wcOpts
  , extractable
  , [ 'sign', 'verify' ]
  ).then(function (result) {
    return window.crypto.subtle.exportKey(
      "jwk"
    , result.privateKey
    ).then(function (privJwk) {
      // TODO remove
      console.log('private jwk:');
      console.log(JSON.stringify(privJwk, null, 2));
      return {
        privateKey: privJwk
      };
    });
  });
};

}(window));
