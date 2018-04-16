'use strict';

var http = require('http');
var express = require('express');
var server = http.createServer(express.static('../tests')).listen(80, function () {
  console.log('Listening on', this.address());
});
