var RSA = require('rsa-compat').RSA;
var fs = require('fs');

if (!fs.existsSync(__dirname + '/../tests/account.privkey.pem')) {
  RSA.generateKeypair(2048, 65537, {}, function (err, keypair) {
    console.log(keypair);
    var privkeyPem = RSA.exportPrivatePem(keypair)
    console.log(privkeyPem);

    fs.writeFileSync(__dirname + '/../tests/account.privkey.pem', privkeyPem);
  });
}

if (!fs.existsSync(__dirname + '/../tests/privkey.pem')) {
  RSA.generateKeypair(2048, 65537, {}, function (err, keypair) {
    console.log(keypair);
    var privkeyPem = RSA.exportPrivatePem(keypair)
    console.log(privkeyPem);

    fs.writeFileSync(__dirname + '/../tests/privkey.pem', privkeyPem);
  });
}
