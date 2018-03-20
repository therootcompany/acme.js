var RSA = require('rsa-compat').RSA;
var fs = require('fs');

RSA.generateKeypair(2048, 65537, {}, function (err, keypair) {
	console.log(keypair);
	var privkeyPem = RSA.exportPrivatePem(keypair)
	console.log(privkeyPem);

	fs.writeFileSync(__dirname + '/account.privkey.pem', privkeyPem);
});

RSA.generateKeypair(2048, 65537, {}, function (err, keypair) {
	console.log(keypair);
	var privkeyPem = RSA.exportPrivatePem(keypair)
	console.log(privkeyPem);

	fs.writeFileSync(__dirname + '/privkey.pem', privkeyPem);
});
