'use strict';

var native = module.exports;
var promisify = require('util').promisify;
var resolveTxt = promisify(require('dns').resolveTxt);

native._canCheck = function(me) {
	me._canCheck['http-01'] = true;
	me._canCheck['dns-01'] = true;
	return Promise.resolve();
};

native._dns01 = function(me, ch) {
	// TODO use digd.js
	return resolveTxt(ch.dnsHost).then(function(records) {
		return {
			answer: records.map(function(rr) {
				return {
					data: rr
				};
			})
		};
	});
};

native._http01 = function(me, ch) {
	return new me.request({
		url: ch.challengeUrl
	}).then(function(resp) {
		return resp.body;
	});
};
