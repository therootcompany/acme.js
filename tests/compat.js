'use strict';

module.exports.run = function (directoryUrl, RSA, web, chType, email, accountKeypair, domainKeypair) {
  console.log('[DEBUG] run', web, chType, email);

  var acme2 = require('../compat.js').ACME.create({ RSA: RSA });
  acme2.getAcmeUrls(acme2.stagingServerUrl, function (err/*, directoryUrls*/) {
    if (err) { console.log('err 1'); throw err; }

    var options = {
      agreeToTerms: function (tosUrl, agree) {
        agree(null, tosUrl);
      }
    , setChallenge: function (hostname, token, val, cb) {
        var pathname = hostname + acme2.acmeChallengePrefix + token;
        console.log("Put the string '" + val + "' into a file at '" + pathname + "'");
        console.log("echo '" + val + "' > '" + pathname + "'");
        console.log("\nThen hit the 'any' key to continue...");

        function onAny() {
          console.log("'any' key was hit");
          process.stdin.pause();
          process.stdin.removeListener('data', onAny);
          process.stdin.setRawMode(false);
          cb();
        }

        process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.on('data', onAny);
      }
    , removeChallenge: function (hostname, key, cb) {
        console.log('[DEBUG] remove challenge', hostname, key);
        setTimeout(cb, 1 * 1000);
      }
    , challengeType: chType
    , email: email
    , accountKeypair: accountKeypair
    , domainKeypair: domainKeypair
    , domains: web
    };

    acme2.registerNewAccount(options, function (err, account) {
      if (err) { console.log('err 2'); throw err; }
      if (options.debug) console.debug('account:');
      if (options.debug) console.log(account);

      acme2.getCertificate(options, function (err, fullchainPem) {
        if (err) { console.log('err 3'); throw err; }
        console.log('[acme-v2] A fullchain.pem:');
        console.log(fullchainPem);
      });
    });
  });
};
