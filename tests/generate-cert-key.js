'use strict';

module.exports = async function () {
	console.log('[Test] can generate, export, and import key');
	var Keypairs = require('@root/keypairs');

	var certKeypair = await Keypairs.generate({ kty: 'RSA' });
	//console.log(certKeypair);
	var pem = await Keypairs.export({
		jwk: certKeypair.private,
		encoding: 'pem'
	});
	var jwk = await Keypairs.import({
		pem: pem
	});
	['kty', 'd', 'n', 'e'].forEach(function (k) {
		if (!jwk[k] || jwk[k] !== certKeypair.private[k]) {
			throw new Error('bad export/import');
		}
	});
	//console.log(pem);
	console.log('PASS');
};

if (require.main === module) {
	module.exports();
}
