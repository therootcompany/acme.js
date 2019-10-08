'use strict';

async function run() {
	var Keypairs = require('@root/keypairs');

	var certKeypair = await Keypairs.generate({ kty: 'RSA' });
  console.log(certKeypair);
	var pem = await Keypairs.export({
		jwk: certKeypair.private,
		encoding: 'pem'
	});
	console.log(pem);
}

run();
