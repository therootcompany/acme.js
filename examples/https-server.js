'use strict';

var https = require('https');
var server = https.createServer({
  key: require('fs').readFileSync('../tests/privkey.pem')
, cert: require('fs').readFileSync('../tests/fullchain.pem')
}, function (req, res) {
  res.end("Hello, World!");
}).listen(443, function () {
  console.log('Listening on', this.address());
});
