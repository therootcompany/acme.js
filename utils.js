'use strict';

var U = module.exports;

var Keypairs = require('@root/keypairs');

// Handle nonce, signing, and request altogether
U._jwsRequest = function(me, bigopts) {
	return U._getNonce(me).then(function(nonce) {
		bigopts.protected.nonce = nonce;
		bigopts.protected.url = bigopts.url;
		// protected.alg: added by Keypairs.signJws
		if (!bigopts.protected.jwk) {
			// protected.kid must be overwritten due to ACME's interpretation of the spec
			if (!bigopts.protected.kid) {
				bigopts.protected.kid = bigopts.options._kid;
			}
		}

		// this will shasum the thumbprint the 2nd time
		return Keypairs.signJws({
			jwk:
				bigopts.options.accountKey ||
				bigopts.options.accountKeypair.privateKeyJwk,
			protected: bigopts.protected,
			payload: bigopts.payload
		})
			.then(function(jws) {
				//#console.debug('[ACME.js] url: ' + bigopts.url + ':');
				//#console.debug(jws);
				return U._request(me, { url: bigopts.url, json: jws });
			})
			.catch(function(e) {
				if (/badNonce$/.test(e.urn)) {
					// retry badNonces
					var retryable = bigopts._retries >= 2;
					if (!retryable) {
						bigopts._retries = (bigopts._retries || 0) + 1;
						return U._jwsRequest(me, bigopts);
					}
				}
				throw e;
			});
	});
};

U._getNonce = function(me) {
	var nonce;
	while (true) {
		nonce = me._nonces.shift();
		if (!nonce) {
			break;
		}
		if (Date.now() - nonce.createdAt > 15 * 60 * 1000) {
			nonce = null;
		} else {
			break;
		}
	}
	if (nonce) {
		return Promise.resolve(nonce.nonce);
	}

	// HEAD-as-HEAD ok
	return U._request(me, {
		method: 'HEAD',
		url: me._directoryUrls.newNonce
	}).then(function(resp) {
		return resp.headers['replay-nonce'];
	});
};

// Handle some ACME-specific defaults
U._request = function(me, opts) {
	if (!opts.headers) {
		opts.headers = {};
	}
	if (opts.json && true !== opts.json) {
		opts.headers['Content-Type'] = 'application/jose+json';
		opts.body = JSON.stringify(opts.json);
		if (!opts.method) {
			opts.method = 'POST';
		}
	}
	return me.request(opts).then(function(resp) {
		if (resp.toJSON) {
			resp = resp.toJSON();
		}
		if (resp.headers['replay-nonce']) {
			U._setNonce(me, resp.headers['replay-nonce']);
		}

		var e;
		var err;
		if (resp.body) {
			err = resp.body.error;
			e = new Error('');
			if (400 === resp.body.status) {
				err = { type: resp.body.type, detail: resp.body.detail };
			}
			if (err) {
				e.status = resp.body.status;
				e.code = 'E_ACME';
				if (e.status) {
					e.message = '[' + e.status + '] ';
				}
				e.detail = err.detail;
				e.message += err.detail || JSON.stringify(err);
				e.urn = err.type;
				e.uri = resp.body.url;
				e._rawError = err;
				e._rawBody = resp.body;
				throw e;
			}
		}

		return resp;
	});
};

U._setNonce = function(me, nonce) {
	me._nonces.unshift({ nonce: nonce, createdAt: Date.now() });
};

U._importKeypair = function(me, kp) {
	var jwk = kp.privateKeyJwk;
	if (kp.kty) {
		jwk = kp;
		kp = {};
	}
	var pub;
	var p;
	if (jwk) {
		// nix the browser jwk extras
		jwk.key_ops = undefined;
		jwk.ext = undefined;
		pub = Keypairs.neuter({ jwk: jwk });
		p = Promise.resolve({
			private: jwk,
			public: pub
		});
	} else {
		p = Keypairs.import({ pem: kp.privateKeyPem });
	}
	return p.then(function(pair) {
		kp.privateKeyJwk = pair.private;
		kp.publicKeyJwk = pair.public;
		if (pair.public.kid) {
			pair = JSON.parse(JSON.stringify(pair));
			delete pair.public.kid;
			delete pair.private.kid;
		}
		return pair;
	});
};
