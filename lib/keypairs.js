/*global Promise*/
(function (exports) {
'use strict';

var Keypairs = exports.Keypairs = {};
var Rasha = exports.Rasha || require('rasha');
var Eckles = exports.Eckles || require('eckles');
var Enc = exports.Enc || {};

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

// JWT a.k.a. JWS with Claims using Compact Serialization
Keypairs.signJwt = function (opts) {
  return Keypairs.thumbprint({ jwk: opts.jwk }).then(function (thumb) {
    var header = opts.header || {};
    var claims = JSON.parse(JSON.stringify(opts.claims || {}));
    header.typ = 'JWT';

    if (!header.kid) { header.kid = thumb; }
    if (!header.alg && opts.alg) { header.alg = opts.alg; }
    if (!claims.iat && (false === claims.iat || false === opts.iat)) {
      claims.iat = undefined;
    } else if (!claims.iat) {
      claims.iat = Math.round(Date.now()/1000);
    }

    if (opts.exp) {
      claims.exp = setTime(opts.exp);
    } else if (!claims.exp && (false === claims.exp || false === opts.exp)) {
      claims.exp = undefined;
    } else if (!claims.exp) {
      throw new Error("opts.claims.exp should be the expiration date as seconds, human form (i.e. '1h' or '15m') or false");
    }

    if (opts.iss) { claims.iss = opts.iss; }
    if (!claims.iss && (false === claims.iss || false === opts.iss)) {
      claims.iss = undefined;
    } else if (!claims.iss) {
      throw new Error("opts.claims.iss should be in the form of https://example.com/, a secure OIDC base url");
    }

    return Keypairs.signJws({
      jwk: opts.jwk
    , pem: opts.pem
    , protected: header
    , header: undefined
    , payload: claims
    }).then(function (jws) {
      return [ jws.protected, jws.payload, jws.signature ].join('.');
    });
  });
};

Keypairs.signJws = function (opts) {
  return Keypairs.thumbprint(opts).then(function (thumb) {

    function alg() {
      if (!opts.jwk) {
        throw new Error("opts.jwk must exist and must declare 'typ'");
      }
      return ('RSA' === opts.jwk.kty) ? "RS256" : "ES256";
    }

    function sign(pem) {
      var header = opts.header;
      var protect = opts.protected;
      var payload = opts.payload;

      // Compute JWS signature
      var protectedHeader = "";
      // Because unprotected headers are allowed, regrettably...
      // https://stackoverflow.com/a/46288694
      if (false !== protect) {
        if (!protect) { protect = {}; }
        if (!protect.alg) { protect.alg = alg(); }
        // There's a particular request where Let's Encrypt explicitly doesn't use a kid
        if (!protect.kid && false !== protect.kid) { protect.kid = thumb; }
        protectedHeader = JSON.stringify(protect);
      }

      // Not sure how to handle the empty case since ACME POST-as-GET must be empty
      //if (!payload) {
      //  throw new Error("opts.payload should be JSON, string, or ArrayBuffer (it may be empty, but that must be explicit)");
      //}
      // Trying to detect if it's a plain object (not Buffer, ArrayBuffer, Array, Uint8Array, etc)
      if (payload && ('string' !== typeof payload)
        && ('undefined' === typeof payload.byteLength)
        && ('undefined' === typeof payload.byteLength)
      ) {
        payload = JSON.stringify(payload);
      }
      // Converting to a buffer, even if it was just converted to a string
      if ('string' === typeof payload) {
        payload = Enc.binToBuf(payload);
      }

      // node specifies RSA-SHAxxx even when it's actually ecdsa (it's all encoded x509 shasums anyway)
      var nodeAlg = "SHA" + (((protect||header).alg||'').replace(/^[^\d]+/, '')||'256');
      var protected64 = Enc.strToUrlBase64(protectedHeader);
      var payload64 = Enc.bufToUrlBase64(payload);
      var binsig = require('crypto')
        .createSign(nodeAlg)
        .update(protect ? (protected64 + "." + payload64) : payload64)
        .sign(pem)
      ;
      if ('EC' === opts.jwk.kty) {
        // ECDSA JWT signatures differ from "normal" ECDSA signatures
        // https://tools.ietf.org/html/rfc7518#section-3.4
        binsig = convertIfEcdsa(binsig);
      }

      var sig = binsig.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
      ;

      return {
        header: header
      , protected: protected64 || undefined
      , payload: payload64
      , signature: sig
      };
    }

    function convertIfEcdsa(binsig) {
      // should have asn1 sequence header of 0x30
      if (0x30 !== binsig[0]) { throw new Error("Impossible EC SHA head marker"); }
      var index = 2; // first ecdsa "R" header byte
      var len = binsig[1];
      var lenlen = 0;
      // Seek length of length if length is greater than 127 (i.e. two 512-bit / 64-byte R and S values)
      if (0x80 & len) {
        lenlen = len - 0x80; // should be exactly 1
        len = binsig[2]; // should be <= 130 (two 64-bit SHA-512s, plus padding)
        index += lenlen;
      }
      // should be of BigInt type
      if (0x02 !== binsig[index]) { throw new Error("Impossible EC SHA R marker"); }
      index += 1;

      var rlen = binsig[index];
      var bits = 32;
      if (rlen > 49) {
        bits = 64;
      } else if (rlen > 33) {
        bits = 48;
      }
      var r = binsig.slice(index + 1, index + 1 + rlen).toString('hex');
      var slen = binsig[index + 1 + rlen + 1]; // skip header and read length
      var s = binsig.slice(index + 1 + rlen + 1 + 1).toString('hex');
      if (2 *slen !== s.length) { throw new Error("Impossible EC SHA S length"); }
      // There may be one byte of padding on either
      while (r.length < 2*bits) { r = '00' + r; }
      while (s.length < 2*bits) { s = '00' + s; }
      if (2*(bits+1) === r.length) { r = r.slice(2); }
      if (2*(bits+1) === s.length) { s = s.slice(2); }
      return Enc.hexToBuf(r + s);
    }

    if (opts.pem && opts.jwk) {
      return sign(opts.pem);
    } else {
      return Keypairs.export({ jwk: opts.jwk }).then(sign);
    }
  });
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

Enc.hexToBuf = function (hex) {
  var arr = [];
  hex.match(/.{2}/g).forEach(function (h) {
    arr.push(parseInt(h, 16));
  });
  return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};
Enc.strToUrlBase64 = function (str) {
  return Enc.bufToUrlBase64(Enc.binToBuf(str));
};
Enc.binToBuf = function (bin) {
  var arr = bin.split('').map(function (ch) {
    return ch.charCodeAt(0);
  });
  return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};

}('undefined' !== typeof module ? module.exports : window));
