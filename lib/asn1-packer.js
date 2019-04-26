;(function (exports) {
'use strict';

if (!exports.ASN1) { exports.ASN1 = {}; }
if (!exports.Enc) { exports.Enc = {}; }
if (!exports.PEM) { exports.PEM = {}; }

var ASN1 = exports.ASN1;
var Enc = exports.Enc;
var PEM = exports.PEM;

//
// Packer
//

// Almost every ASN.1 type that's important for CSR
// can be represented generically with only a few rules.
exports.ASN1 = function ASN1(/*type, hexstrings...*/) {
  var args = Array.prototype.slice.call(arguments);
  var typ = args.shift();
  var str = args.join('').replace(/\s+/g, '').toLowerCase();
  var len = (str.length/2);
  var lenlen = 0;
  var hex = typ;

  // We can't have an odd number of hex chars
  if (len !== Math.round(len)) {
    throw new Error("invalid hex");
  }

  // The first byte of any ASN.1 sequence is the type (Sequence, Integer, etc)
  // The second byte is either the size of the value, or the size of its size

  // 1. If the second byte is < 0x80 (128) it is considered the size
  // 2. If it is > 0x80 then it describes the number of bytes of the size
  //    ex: 0x82 means the next 2 bytes describe the size of the value
  // 3. The special case of exactly 0x80 is "indefinite" length (to end-of-file)

  if (len > 127) {
    lenlen += 1;
    while (len > 255) {
      lenlen += 1;
      len = len >> 8;
    }
  }

  if (lenlen) { hex += Enc.numToHex(0x80 + lenlen); }
  return hex + Enc.numToHex(str.length/2) + str;
};

// The Integer type has some special rules
ASN1.UInt = function UINT() {
  var str = Array.prototype.slice.call(arguments).join('');
  var first = parseInt(str.slice(0, 2), 16);

  // If the first byte is 0x80 or greater, the number is considered negative
  // Therefore we add a '00' prefix if the 0x80 bit is set
  if (0x80 & first) { str = '00' + str; }

  return ASN1('02', str);
};

// The Bit String type also has a special rule
ASN1.BitStr = function BITSTR() {
  var str = Array.prototype.slice.call(arguments).join('');
  // '00' is a mask of how many bits of the next byte to ignore
  return ASN1('03', '00' + str);
};

ASN1.pack = function (arr) {
  var typ = Enc.numToHex(arr[0]);
  var str = '';
  if (Array.isArray(arr[1])) {
    arr[1].forEach(function (a) {
      str += ASN1.pack(a);
    });
  } else if ('string' === typeof arr[1]) {
    str = arr[1];
  } else {
    throw new Error("unexpected array");
  }
  if ('03' === typ) {
    return ASN1.BitStr(str);
  } else if ('02' === typ) {
    return ASN1.UInt(str);
  } else {
    return ASN1(typ, str);
  }
};
Object.keys(ASN1).forEach(function (k) {
  exports.ASN1[k] = ASN1[k];
});
ASN1 = exports.ASN1;

PEM.packBlock = function (opts) {
  // TODO allow for headers?
  return '-----BEGIN ' + opts.type + '-----\n'
    + Enc.bufToBase64(opts.bytes).match(/.{1,64}/g).join('\n') + '\n'
    + '-----END ' + opts.type + '-----'
  ;
};

Enc.bufToBase64 = function (u8) {
  var bin = '';
  u8.forEach(function (i) {
    bin += String.fromCharCode(i);
  });
  return btoa(bin);
};

Enc.hexToBuf = function (hex) {
  var arr = [];
  hex.match(/.{2}/g).forEach(function (h) {
    arr.push(parseInt(h, 16));
  });
  return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
};

Enc.numToHex = function (d) {
  d = d.toString(16);
  if (d.length % 2) {
    return '0' + d;
  }
  return d;
};

}('undefined' !== typeof window ? window : module.exports));
