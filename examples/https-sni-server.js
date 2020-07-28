'use strict';

var https = require('http2');
var tls = require('tls');
var fs = require('fs');

var key = fs.readFileSync('./privkey.pem');
var cert = fs.readFileSync('./fullchain.pem');

function SNICallback(servername, cb) {
	console.log('sni:', servername);
	cb(null, tls.createSecureContext({ key, cert }));
}

var server = https
	.createSecureServer({ SNICallback: SNICallback }, function (req, res) {
		res.end('Hello, Encrypted World!');
	})
	.listen(443, function () {
		console.info('Listening on', server.address());
	});
