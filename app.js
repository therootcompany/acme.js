/*global Promise*/
(function () {
  'use strict';

  var Keypairs = window.Keypairs;
  var Rasha = window.Rasha;
  var Eckles = window.Eckles;
  var x509 = window.x509;
  var CSR = window.CSR;
  var ACME = window.ACME;
  var accountStuff = {};

  function $(sel) {
    return document.querySelector(sel);
  }
  function $$(sel) {
    return Array.prototype.slice.call(document.querySelectorAll(sel));
  }

  function run() {
    console.log('hello');

    // Show different options for ECDSA vs RSA
    $$('input[name="kty"]').forEach(function ($el) {
      $el.addEventListener('change', function (ev) {
        console.log(this);
        console.log(ev);
        if ("RSA" === ev.target.value) {
          $('.js-rsa-opts').hidden = false;
          $('.js-ec-opts').hidden = true;
        } else {
          $('.js-rsa-opts').hidden = true;
          $('.js-ec-opts').hidden = false;
        }
      });
    });

    // Generate a key on submit
    $('form.js-keygen').addEventListener('submit', function (ev) {
      ev.preventDefault();
      ev.stopPropagation();
      $('.js-loading').hidden = false;
      $('.js-jwk').hidden = true;
      $('.js-toc-der-public').hidden = true;
      $('.js-toc-der-private').hidden = true;
      $$('.js-toc-pem').forEach(function ($el) {
        $el.hidden = true;
      });
      $$('input').map(function ($el) { $el.disabled = true; });
      $$('button').map(function ($el) { $el.disabled = true; });
      var opts = {
        kty: $('input[name="kty"]:checked').value
      , namedCurve: $('input[name="ec-crv"]:checked').value
      , modulusLength: $('input[name="rsa-len"]:checked').value
      };
      var then = Date.now();
      console.log('opts', opts);
      Keypairs.generate(opts).then(function (results) {
        console.log("Key generation time:", (Date.now() - then) + "ms");
        var pubDer;
        var privDer;
        if (/EC/i.test(opts.kty)) {
          privDer = x509.packPkcs8(results.private);
          pubDer = x509.packSpki(results.public);
          Eckles.export({ jwk: results.private, format: 'sec1' }).then(function (pem) {
            $('.js-input-pem-sec1-private').innerText = pem;
            $('.js-toc-pem-sec1-private').hidden = false;
          });
          Eckles.export({ jwk: results.private, format: 'pkcs8' }).then(function (pem) {
            $('.js-input-pem-pkcs8-private').innerText = pem;
            $('.js-toc-pem-pkcs8-private').hidden = false;
          });
          Eckles.export({ jwk: results.public, public: true }).then(function (pem) {
            $('.js-input-pem-spki-public').innerText = pem;
            $('.js-toc-pem-spki-public').hidden = false;
          });
        } else {
          privDer = x509.packPkcs8(results.private);
          pubDer = x509.packSpki(results.public);
          Rasha.export({ jwk: results.private, format: 'pkcs1' }).then(function (pem) {
            $('.js-input-pem-pkcs1-private').innerText = pem;
            $('.js-toc-pem-pkcs1-private').hidden = false;
          });
          Rasha.export({ jwk: results.private, format: 'pkcs8' }).then(function (pem) {
            $('.js-input-pem-pkcs8-private').innerText = pem;
            $('.js-toc-pem-pkcs8-private').hidden = false;
          });
          Rasha.export({ jwk: results.public, format: 'pkcs1' }).then(function (pem) {
            $('.js-input-pem-pkcs1-public').innerText = pem;
            $('.js-toc-pem-pkcs1-public').hidden = false;
          });
          Rasha.export({ jwk: results.public, format: 'spki' }).then(function (pem) {
            $('.js-input-pem-spki-public').innerText = pem;
            $('.js-toc-pem-spki-public').hidden = false;
          });
        }

        $('.js-der-public').innerText = pubDer;
        $('.js-toc-der-public').hidden = false;
        $('.js-der-private').innerText = privDer;
        $('.js-toc-der-private').hidden = false;
        $('.js-jwk').innerText = JSON.stringify(results, null, 2);
        $('.js-loading').hidden = true;
        $('.js-jwk').hidden = false;
        $$('input').map(function ($el) { $el.disabled = false; });
        $$('button').map(function ($el) { $el.disabled = false; });
        $('.js-toc-jwk').hidden = false;

        $('.js-create-account').hidden = false;
        $('.js-create-csr').hidden = false;
      });
    });

    $('.js-generate').hidden = false;
  }

  window.addEventListener('load', run);
}());
