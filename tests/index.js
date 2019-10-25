'use strict';

async function main() {
	await require('./generate-cert-key.js')();
	await require('./format-pem-chains.js')();
	await require('./compute-authorization-response.js')();
	await require('./issue-certificates.js')();
}

main();
