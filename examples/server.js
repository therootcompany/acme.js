'use strict';

var crypto = require('crypto');
//var dnsjs = require('dns-suite');
var dig = require('dig.js/dns-request');
var request = require('util').promisify(require('@root/request'));
var express = require('express');
var app = express();

var nameservers = require('dns').getServers();
var index = crypto.randomBytes(2).readUInt16BE(0) % nameservers.length;
var nameserver = nameservers[index];

app.use('/', express.static(__dirname));
app.use('/api', express.json());
app.get('/api/dns/:domain', function(req, res, next) {
	var domain = req.params.domain;
	var casedDomain = domain
		.toLowerCase()
		.split('')
		.map(function(ch) {
			// dns0x20 takes advantage of the fact that the binary operation for toUpperCase is
			// ch = ch | 0x20;
			return Math.round(Math.random()) % 2 ? ch : ch.toUpperCase();
		})
		.join('');
	var typ = req.query.type;
	var query = {
		header: {
			id: crypto.randomBytes(2).readUInt16BE(0),
			qr: 0,
			opcode: 0,
			aa: 0, // Authoritative-Only
			tc: 0, // NA
			rd: 1, // Recurse
			ra: 0, // NA
			rcode: 0 // NA
		},
		question: [
			{
				name: casedDomain,
				//, type: typ || 'A'
				typeName: typ || 'A',
				className: 'IN'
			}
		]
	};
	var opts = {
		onError: function(err) {
			next(err);
		},
		onMessage: function(packet) {
			var fail0x20;

			if (packet.id !== query.id) {
				console.error(
					"[SECURITY] ignoring packet for '" +
						packet.question[0].name +
						"' due to mismatched id"
				);
				console.error(packet);
				return;
			}

			packet.question.forEach(function(q) {
				// if (-1 === q.name.lastIndexOf(cli.casedQuery))
				if (q.name !== casedDomain) {
					fail0x20 = q.name;
				}
			});

			['question', 'answer', 'authority', 'additional'].forEach(function(
				group
			) {
				(packet[group] || []).forEach(function(a) {
					var an = a.name;
					var i = domain
						.toLowerCase()
						.lastIndexOf(a.name.toLowerCase()); // answer is something like ExAMPle.cOM and query was wWw.ExAMPle.cOM
					var j = a.name
						.toLowerCase()
						.lastIndexOf(domain.toLowerCase()); // answer is something like www.ExAMPle.cOM and query was ExAMPle.cOM

					// it's important to note that these should only relpace changes in casing that we expected
					// any abnormalities should be left intact to go "huh?" about
					// TODO detect abnormalities?
					if (-1 !== i) {
						// "EXamPLE.cOm".replace("wWw.EXamPLE.cOm".substr(4), "www.example.com".substr(4))
						a.name = a.name.replace(
							casedDomain.substr(i),
							domain.substr(i)
						);
					} else if (-1 !== j) {
						// "www.example.com".replace("EXamPLE.cOm", "example.com")
						a.name =
							a.name.substr(0, j) +
							a.name.substr(j).replace(casedDomain, domain);
					}

					// NOTE: right now this assumes that anything matching the query matches all the way to the end
					// it does not handle the case of a record for example.com.uk being returned in response to a query for www.example.com correctly
					// (but I don't think it should need to)
					if (a.name.length !== an.length) {
						console.error(
							"[ERROR] question / answer mismatch: '" +
								an +
								"' != '" +
								a.length +
								"'"
						);
						console.error(a);
					}
				});
			});

			if (fail0x20) {
				console.warn(
					";; Warning: DNS 0x20 security not implemented (or packet spoofed). Queried '" +
						casedDomain +
						"' but got response for '" +
						fail0x20 +
						"'."
				);
				return;
			}

			res.send({
				header: packet.header,
				question: packet.question,
				answer: packet.answer,
				authority: packet.authority,
				additional: packet.additional,
				edns_options: packet.edns_options
			});
		},
		onListening: function() {},
		onSent: function(/*res*/) {},
		onTimeout: function(res) {
			console.error('dns timeout:', res);
			next(new Error('DNS timeout - no response'));
		},
		onClose: function() {},
		//, mdns: cli.mdns
		nameserver: nameserver,
		port: 53,
		timeout: 2000
	};

	dig.resolveJson(query, opts);
});
app.get('/api/http', function(req, res) {
	var url = req.query.url;
	return request({ method: 'GET', url: url }).then(function(resp) {
		res.send(resp.body);
	});
});
app.get('/api/_acme_api_', function(req, res) {
	res.send({ success: true });
});

module.exports = app;
if (require.main === module) {
	// curl -L http://localhost:3000/api/dns/example.com?type=A
	console.info('Listening on localhost:3000');
	app.listen(3000);
	console.info('Try this:');
	console.info("\tcurl -L 'http://localhost:3000/api/_acme_api_/'");
	console.info(
		"\tcurl -L 'http://localhost:3000/api/dns/example.com?type=A'"
	);
	console.info(
		"\tcurl -L 'http://localhost:3000/api/http/?url=https://example.com'"
	);
}
