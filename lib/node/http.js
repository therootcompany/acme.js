'use strict';

var http = module.exports;
var promisify = require('util').promisify;
var request = promisify(require('@root/request'));

http.request = function(opts) {
	if (!opts.headers) {
		opts.headers = {};
	}
	if (
		!Object.keys(opts.headers).some(function(key) {
			return 'user-agent' === key.toLowerCase();
		})
	) {
		// TODO opts.headers['User-Agent'] = 'TODO';
	}
	return request(opts);
};
