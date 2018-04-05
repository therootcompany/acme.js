'use strict';

module.exports.run = function run(web, chType, email) {
  var RSA = require('rsa-compat').RSA;
  var directoryUrl = 'https://acme-staging-v02.api.letsencrypt.org/directory';
  var acme2 = require('./compat').ACME.create({ RSA: RSA });
  // [ 'test.ppl.family' ] 'coolaj86@gmail.com''http-01'
	console.log(web, chType, email);
	return;
  acme2.init(directoryUrl).then(function (body) {
    console.log(body);
		return;

    var options = {
      agreeToTerms: function (tosUrl, agree) {
        agree(null, tosUrl);
      }
    , setChallenge: function (opts, cb) {

        console.log("");
        console.log('identifier:');
        console.log(opts.identifier);
        console.log('hostname:');
        console.log(opts.hostname);
        console.log('type:');
        console.log(opts.type);
        console.log('token:');
        console.log(opts.token);
        console.log('thumbprint:');
        console.log(opts.thumbprint);
        console.log('keyAuthorization:');
        console.log(opts.keyAuthorization);
        console.log('dnsAuthorization:');
        console.log(opts.dnsAuthorization);
        console.log("");

        console.log("Put the string '" + opts.keyAuthorization + "' into a file at '" + opts.hostname + "/" + opts.token + "'");
        console.log("\nThen hit the 'any' key to continue (must be specifically the 'any' key)...");

        function onAny() {
          process.stdin.pause();
          process.stdin.removeEventListener('data', onAny);
          process.stdin.setRawMode(false);
          cb();
        }
        process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.on('data', onAny);
      }
    , removeChallenge: function (opts, cb) {
				// hostname, key
        console.log('[DEBUG] remove challenge', hostname, key);
        setTimeout(cb, 1 * 1000);
      }
    , challengeType: chType
    , email: email
    , accountKeypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/account.privkey.pem') })
    , domainKeypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/privkey.pem') })
    , domains: web
    };

    acme2.registerNewAccount(options).then(function (account) {
      console.log('account:');
      console.log(account);

      acme2.getCertificate(options, function (fullchainPem) {
        console.log('[acme-v2] A fullchain.pem:');
        console.log(fullchainPem);
      }).then(function (fullchainPem) {
        console.log('[acme-v2] B fullchain.pem:');
        console.log(fullchainPem);
      });
    });
  });
};
