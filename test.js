'use strict';

var RSA = require('rsa-compat').RSA;
var acme2 = require('./').ACME.create({ RSA: RSA });

acme2.getAcmeUrls(acme2.stagingServerUrl).then(function (body) {
  console.log(body);

  var options = {
    agreeToTerms: function (tosUrl, agree) {
      agree(null, tosUrl);
    }
    /*
  , setupChallenge: function (opts) {
      console.log('type:');
      console.log(ch.type);
      console.log('ch.token:');
      console.log(ch.token);
      console.log('thumbprint:');
      console.log(thumbprint);
      console.log('keyAuthorization:');
      console.log(keyAuthorization);
      console.log('dnsAuthorization:');
      console.log(dnsAuthorization);
    }
    */
    // teardownChallenge
  , setChallenge: function (hostname, key, val, cb) {
      console.log('[DEBUG] set challenge', hostname, key, val);
      console.log("You have 20 seconds to put the string '" + val + "' into a file at '" + hostname + "/" + key + "'");
      setTimeout(cb, 20 * 1000);
    }
  , removeChallenge: function (hostname, key, cb) {
      console.log('[DEBUG] remove challenge', hostname, key);
      setTimeout(cb, 1 * 1000);
    }
  , challengeType: 'http-01'
  , email: 'coolaj86@gmail.com'
  , accountKeypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/account.privkey.pem') })
  , domainKeypair: RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/privkey.pem') })
  , domains: [ 'test.ppl.family' ]
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
