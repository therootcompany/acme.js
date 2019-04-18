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
    $$('input').map(function ($el) { $el.disabled = true; });
    $$('button').map(function ($el) { $el.disabled = true; });
    var opts = {
      kty: $('input[name="kty"]:checked').value
    , namedCurve: $('input[name="ec-crv"]:checked').value
    , modulusLength: $('input[name="rsa-len"]:checked').value
    };
    console.log('opts', opts);
    Keypairs.generate(opts).then(function (results) {
      $('.js-jwk').innerText = JSON.stringify(results, null, 2);
      //
      $('.js-loading').hidden = true;
      $('.js-jwk').hidden = false;
      $$('input').map(function ($el) { $el.disabled = false; });
      $$('button').map(function ($el) { $el.disabled = false; });
    });
  });

  $('.js-generate').hidden = false;
}

window.addEventListener('load', run);
}());
