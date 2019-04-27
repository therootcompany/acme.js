/*global Promise*/
(function (exports) {
'use strict';

var EC = exports.Eckles = {};
var x509 = exports.x509;
if ('undefined' !== typeof module) { module.exports = EC; }
var PEM = exports.PEM;
var SSH = exports.SSH;
var Enc = {};
var textEncoder = new TextEncoder();

EC._stance = "We take the stance that if you're knowledgeable enough to"
  + " properly and securely use non-standard crypto then you shouldn't need Bluecrypt anyway.";
EC._universal = "Bluecrypt only supports crypto with standard cross-browser and cross-platform support.";
EC.generate = function (opts) {
  var wcOpts = {};
  if (!opts) { opts = {}; }
  if (!opts.kty) { opts.kty = 'EC'; }

  // ECDSA has only the P curves and an associated bitlength
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
      + EC._stance));
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
      return {
        private: privJwk
      , public: EC.neuter({ jwk: privJwk })
      };
    });
  });
};

EC.export = function (opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.jwk || 'object' !== typeof opts.jwk) {
      throw new Error("must pass { jwk: jwk } as a JSON object");
    }
    var jwk = JSON.parse(JSON.stringify(opts.jwk));
    var format = opts.format;
    if (opts.public || -1 !== [ 'spki', 'pkix', 'ssh', 'rfc4716' ].indexOf(format)) {
      jwk.d = null;
    }
    if ('EC' !== jwk.kty) {
      throw new Error("options.jwk.kty must be 'EC' for EC keys");
    }
    if (!jwk.d) {
      if (!format || -1 !== [ 'spki', 'pkix' ].indexOf(format)) {
        format = 'spki';
      } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
        format = 'ssh';
      } else {
        throw new Error("options.format must be 'spki' or 'ssh' for public EC keys, not ("
          + typeof format + ") " + format);
      }
    } else {
      if (!format || 'sec1' === format) {
        format = 'sec1';
      } else if ('pkcs8' !== format) {
        throw new Error("options.format must be 'sec1' or 'pkcs8' for private EC keys, not '" + format + "'");
      }
    }
    if (-1 === [ 'P-256', 'P-384' ].indexOf(jwk.crv)) {
      throw new Error("options.jwk.crv must be either P-256 or P-384 for EC keys, not '" + jwk.crv + "'");
    }
    if (!jwk.y) {
      throw new Error("options.jwk.y must be a urlsafe base64-encoded either P-256 or P-384");
    }

    if ('sec1' === format) {
      return PEM.packBlock({ type: "EC PRIVATE KEY", bytes: x509.packSec1(jwk) });
    } else if ('pkcs8' === format) {
      return PEM.packBlock({ type: "PRIVATE KEY", bytes: x509.packPkcs8(jwk) });
    } else if (-1 !== [ 'spki', 'pkix' ].indexOf(format)) {
      return PEM.packBlock({ type: "PUBLIC KEY", bytes: x509.packSpki(jwk) });
    } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
      return SSH.packSsh(jwk);
    } else {
      throw new Error("Sanity Error: reached unreachable code block with format: " + format);
    }
  });
};
EC.pack = function (opts) {
  return Promise.resolve().then(function () {
    return EC.exportSync(opts);
  });
};

// Chopping off the private parts is now part of the public API.
// I thought it sounded a little too crude at first, but it really is the best name in every possible way.
EC.neuter = function (opts) {
  // trying to find the best balance of an immutable copy with custom attributes
  var jwk = {};
  Object.keys(opts.jwk).forEach(function (k) {
    if ('undefined' === typeof opts.jwk[k]) { return; }
    // ignore EC private parts
    if ('d' === k) { return; }
    jwk[k] = JSON.parse(JSON.stringify(opts.jwk[k]));
  });
  return jwk;
};

// https://stackoverflow.com/questions/42588786/how-to-fingerprint-a-jwk
EC.__thumbprint = function (jwk) {
  // Use the same entropy for SHA as for key
  var alg = 'SHA-256';
  if (/384/.test(jwk.crv)) {
    alg = 'SHA-384';
  }
  return window.crypto.subtle.digest(
    { name: alg }
  , textEncoder.encode('{"crv":"' + jwk.crv + '","kty":"EC","x":"' + jwk.x + '","y":"' + jwk.y + '"}')
  ).then(function (hash) {
    return Enc.bufToUrlBase64(new Uint8Array(hash));
  });
};

EC.thumbprint = function (opts) {
  return Promise.resolve().then(function () {
    var jwk;
    if ('EC' === opts.kty) {
      jwk = opts;
    } else if (opts.jwk) {
      jwk = opts.jwk;
    } else {
      return EC.import(opts).then(function (jwk) {
        return EC.__thumbprint(jwk);
      });
    }
    return EC.__thumbprint(jwk);
  });
};

Enc.bufToUrlBase64 = function (u8) {
  return Enc.bufToBase64(u8)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

Enc.bufToBase64 = function (u8) {
  var bin = '';
  u8.forEach(function (i) {
    bin += String.fromCharCode(i);
  });
  return btoa(bin);
};

}('undefined' !== typeof module ? module.exports : window));
