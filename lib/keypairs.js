/*global Promise*/
(function (exports) {
'use strict';

var Keypairs = exports.Keypairs = {};
var Rasha = exports.Rasha || require('rasha');
var Eckles = exports.Eckles || require('eckles');

Keypairs._stance = "We take the stance that if you're knowledgeable enough to"
  + " properly and securely use non-standard crypto then you shouldn't need Bluecrypt anyway.";
Keypairs._universal = "Bluecrypt only supports crypto with standard cross-browser and cross-platform support.";
Keypairs.generate = function (opts) {
  opts = opts || {};
  var p;
  if (!opts.kty) { opts.kty = opts.type; }
  if (!opts.kty) { opts.kty = 'EC'; }
  if (/^EC/i.test(opts.kty)) {
    p = Eckles.generate(opts);
  } else if (/^RSA$/i.test(opts.kty)) {
    p = Rasha.generate(opts);
  } else {
    return Promise.Reject(new Error("'" + opts.kty + "' is not a well-supported key type."
      + Keypairs._universal
      + " Please choose 'EC', or 'RSA' if you have good reason to."));
  }
  return p.then(function (pair) {
    return Keypairs.thumbprint({ jwk: pair.public }).then(function (thumb) {
      pair.private.kid = thumb; // maybe not the same id on the private key?
      pair.public.kid = thumb;
      return pair;
    });
  });
};


// Chopping off the private parts is now part of the public API.
// I thought it sounded a little too crude at first, but it really is the best name in every possible way.
Keypairs.neuter = Keypairs._neuter = function (opts) {
  // trying to find the best balance of an immutable copy with custom attributes
  var jwk = {};
  Object.keys(opts.jwk).forEach(function (k) {
    if ('undefined' === typeof opts.jwk[k]) { return; }
    // ignore RSA and EC private parts
    if (-1 !== ['d', 'p', 'q', 'dp', 'dq', 'qi'].indexOf(k)) { return; }
    jwk[k] = JSON.parse(JSON.stringify(opts.jwk[k]));
  });
  return jwk;
};

Keypairs.thumbprint = function (opts) {
  return Promise.resolve().then(function () {
    if (/EC/i.test(opts.jwk.kty)) {
      return Eckles.thumbprint(opts);
    } else {
      return Rasha.thumbprint(opts);
    }
  });
};

Keypairs.publish = function (opts) {
  if ('object' !== typeof opts.jwk || !opts.jwk.kty) { throw new Error("invalid jwk: " + JSON.stringify(opts.jwk)); }

  // returns a copy
  var jwk = Keypairs.neuter(opts);

  if (jwk.exp) {
    jwk.exp = setTime(jwk.exp);
  } else {
    if (opts.exp) { jwk.exp = setTime(opts.exp); }
    else if (opts.expiresIn) { jwk.exp = Math.round(Date.now()/1000) + opts.expiresIn; }
    else if (opts.expiresAt) { jwk.exp = opts.expiresAt; }
  }
  if (!jwk.use && false !== jwk.use) { jwk.use = "sig"; }

  if (jwk.kid) { return Promise.resolve(jwk); }
  return Keypairs.thumbprint({ jwk: jwk }).then(function (thumb) { jwk.kid = thumb; return jwk; });
};

function setTime(time) {
  if ('number' === typeof time) { return time; }

  var t = time.match(/^(\-?\d+)([dhms])$/i);
  if (!t || !t[0]) {
    throw new Error("'" + time + "' should be datetime in seconds or human-readable format (i.e. 3d, 1h, 15m, 30s");
  }

  var now = Math.round(Date.now()/1000);
  var num = parseInt(t[1], 10);
  var unit = t[2];
  var mult = 1;
  switch(unit) {
    // fancy fallthrough, what fun!
    case 'd':
      mult *= 24;
      /*falls through*/
    case 'h':
      mult *= 60;
      /*falls through*/
    case 'm':
      mult *= 60;
      /*falls through*/
    case 's':
      mult *= 1;
  }

  return now + (mult * num);
}

}('undefined' !== typeof module ? module.exports : window));
