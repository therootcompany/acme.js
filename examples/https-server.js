'use strict';

var https = require('http2');
var fs = require('fs');

var key = fs.readFileSync('./privkey.pem');
var cert = fs.readFileSync('./fullchain.pem');

var server = https
	.createSecureServer({ key, cert }, function(req, res) {
		res.end('Hello, Encrypted World!');
	})
	.listen(443, function() {
		console.info('Listening on', server.address());
	});
