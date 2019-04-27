(function () {
  'use strict';

  var Keypairs = window.Keypairs;

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
      $('.js-toc-der').hidden = true;
      $('.js-toc-pem').hidden = true;
      $$('input').map(function ($el) { $el.disabled = true; });
      $$('button').map(function ($el) { $el.disabled = true; });
      var opts = {
        kty: $('input[name="kty"]:checked').value
        , namedCurve: $('input[name="ec-crv"]:checked').value
        , modulusLength: $('input[name="rsa-len"]:checked').value
      };
      console.log('opts', opts);
      Keypairs.generate(opts).then(function (results) {
        var der;
        if (opts.kty == 'EC') {
          der = x509.packPkcs8(results.private);
          var pem = Eckles.export({ jwk: results.private })
          $('.js-input-pem').innerText = pem;
          $('.js-toc-pem').hidden = false;
        } else {
          der = x509.packPkcs8(results.private);
          var pem = Rasha.pack({ jwk: results.private }).then(function (pem) {
            $('.js-input-pem').innerText = pem;
            $('.js-toc-pem').hidden = false;
          })
        }

        $('.js-der').innerText = JSON.stringify(der, null, 2);
        $('.js-toc-der').hidden = false;
        $('.js-jwk').innerText = JSON.stringify(results, null, 2);
        $('.js-loading').hidden = true;
        $('.js-jwk').hidden = false;
        $$('input').map(function ($el) { $el.disabled = false; });
        $$('button').map(function ($el) { $el.disabled = false; });
        $('.js-toc-jwk').hidden = false;
      });
    });

    $('form.js-acme-account').addEventListener('submit', function (ev) {
      ev.preventDefault();
      ev.stopPropagation();
      $('.js-loading').hidden = false;
      ACME.accounts.create
    });

    $('.js-generate').hidden = false;
    $('.js-create-account').hidden = false;
  }

  window.addEventListener('load', run);
}());
