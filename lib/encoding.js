(function(exports) {
	var Enc = (exports.Enc = {});

	Enc.bufToBin = function(buf) {
		var bin = '';
		// cannot use .map() because Uint8Array would return only 0s
		buf.forEach(function(ch) {
			bin += String.fromCharCode(ch);
		});
		return bin;
	};

	Enc.bufToHex = function toHex(u8) {
		var hex = [];
		var i, h;
		var len = u8.byteLength || u8.length;

		for (i = 0; i < len; i += 1) {
			h = u8[i].toString(16);
			if (h.length % 2) {
				h = '0' + h;
			}
			hex.push(h);
		}

		return hex.join('').toLowerCase();
	};

	Enc.urlBase64ToBase64 = function urlsafeBase64ToBase64(str) {
		var r = str % 4;
		if (2 === r) {
			str += '==';
		} else if (3 === r) {
			str += '=';
		}
		return str.replace(/-/g, '+').replace(/_/g, '/');
	};

	Enc.base64ToBuf = function(b64) {
		return Enc.binToBuf(atob(b64));
	};
	Enc.binToBuf = function(bin) {
		var arr = bin.split('').map(function(ch) {
			return ch.charCodeAt(0);
		});
		return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
	};
	Enc.bufToHex = function(u8) {
		var hex = [];
		var i, h;
		var len = u8.byteLength || u8.length;

		for (i = 0; i < len; i += 1) {
			h = u8[i].toString(16);
			if (h.length % 2) {
				h = '0' + h;
			}
			hex.push(h);
		}

		return hex.join('').toLowerCase();
	};
	Enc.numToHex = function(d) {
		d = d.toString(16);
		if (d.length % 2) {
			return '0' + d;
		}
		return d;
	};

	Enc.bufToUrlBase64 = function(u8) {
		return Enc.base64ToUrlBase64(Enc.bufToBase64(u8));
	};

	Enc.base64ToUrlBase64 = function(str) {
		return str
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	};

	Enc.bufToBase64 = function(u8) {
		var bin = '';
		u8.forEach(function(i) {
			bin += String.fromCharCode(i);
		});
		return btoa(bin);
	};

	Enc.hexToBuf = function(hex) {
		var arr = [];
		hex.match(/.{2}/g).forEach(function(h) {
			arr.push(parseInt(h, 16));
		});
		return 'undefined' !== typeof Uint8Array ? new Uint8Array(arr) : arr;
	};

	Enc.numToHex = function(d) {
		d = d.toString(16);
		if (d.length % 2) {
			return '0' + d;
		}
		return d;
	};

	//
	// JWK to SSH (tested working)
	//
	Enc.base64ToHex = function(b64) {
		var bin = atob(Enc.urlBase64ToBase64(b64));
		return Enc.binToHex(bin);
	};

	Enc.binToHex = function(bin) {
		return bin
			.split('')
			.map(function(ch) {
				var h = ch.charCodeAt(0).toString(16);
				if (h.length % 2) {
					h = '0' + h;
				}
				return h;
			})
			.join('');
	};
	// TODO are there any nuance differences here?
	Enc.utf8ToHex = Enc.binToHex;

	Enc.hexToBase64 = function(hex) {
		return btoa(Enc.hexToBin(hex));
	};

	Enc.hexToBin = function(hex) {
		return hex
			.match(/.{2}/g)
			.map(function(h) {
				return String.fromCharCode(parseInt(h, 16));
			})
			.join('');
	};

	Enc.urlBase64ToBase64 = function urlsafeBase64ToBase64(str) {
		var r = str % 4;
		if (2 === r) {
			str += '==';
		} else if (3 === r) {
			str += '=';
		}
		return str.replace(/-/g, '+').replace(/_/g, '/');
	};
})('undefined' !== typeof exports ? module.exports : window);
