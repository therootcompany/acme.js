'use strict';

var RSA = require('rsa-compat').RSA;
var readline = require('readline');
var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function getWeb() {
  rl.question('What web address(es) would you like to get certificates for? (ex: example.com,*.example.com) ', function (web) {
    web = (web||'').trim().split(/,/g);
    if (!web[0]) { getWeb(); return; }

    if (web.some(function (w) { return '*' === w[0]; })) {
      console.log('Wildcard domains must use dns-01');
      getEmail(web, 'dns-01');
    } else {
      getChallengeType(web);
    }
  });
}

function getChallengeType(web) {
  rl.question('What challenge will you be testing today? http-01 or dns-01? [http-01] ', function (chType) {
    chType = (chType||'').trim();
    if (!chType) { chType = 'http-01'; }

    getEmail(web, chType);
  });
}

function getEmail(web, chType) {
  rl.question('What email should we use? (optional) ', function (email) {
    email = (email||'').trim();
    if (!email) { email = null; }

    rl.close();
    var accountKeypair = RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/account.privkey.pem') });
    var domainKeypair = RSA.import({ privateKeyPem: require('fs').readFileSync(__dirname + '/privkey.pem') });
    //require('./test.compat.js').run(web, chType, email, accountKeypair, domainKeypair);
    require('./test.cb.js').run(web, chType, email, accountKeypair, domainKeypair);
    //require('./test.promise.js').run(web, chType, email, accountKeypair, domainKeypair);
  });
}

getWeb();
