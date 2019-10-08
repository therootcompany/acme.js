'use strict';

var path = require('path');

module.exports = {
	entry: './lib/acme.js',
	output: {
		path: path.resolve(__dirname, 'dist'),
		filename: 'acme.js',
		library: '@root/acme',
		libraryTarget: 'umd',
		globalObject: "typeof self !== 'undefined' ? self : this"
	},
	resolve: {
		aliasFields: ['webpack', 'browser'],
		mainFields: ['browser']
	}
};
