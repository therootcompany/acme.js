acme-v2.js
==========

A framework for building letsencrypt clients (and other ACME v2 clients), forked from `le-acme-core.js`.

Summary of spec that I'm working off of here: https://git.coolaj86.com/coolaj86/greenlock.js/issues/5#issuecomment-8

In progress

* Mar 15, 2018 - get directory
* Mar 15, 2018 - get nonce
* Mar 15, 2018 - generate account keypair
* Mar 15, 2018 - create account
* Mar 16, 2018 - new order
* Mar 16, 2018 - get challenges
* Mar 20, 2018 - respond to challenges
* Mar 20, 2018 - generate domain keypair
* Mar 20, 2018 - finalize order (submit csr)
* Mar 20, 2018 - poll for status
* Mar 20, 2018 - download certificate

* Mar 20, 2018 - SUCCESS - got a test certificate (hard-coded)

Todo

* match api for acme v1 (le-acme-core.js)
* make not hard-coded
