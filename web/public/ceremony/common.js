/* Spellbook ceremony — shared browser code.
 *
 * Runs only in the human's browser. Nothing here touches the network,
 * storage or the console (the page CSP has connect-src 'none', and the
 * asset index check refuses those APIs). Secrets leave a page only inside
 * an envelope encrypted to a public key; the human copies it by hand.
 *
 * Envelope format: src/spellbook/ceremony.py (SPELLBOOK-CEREMONY1) and the
 * daemon's SPELLBOOK-SEED-ENC2; backup envelopes: src/spellbook/export.py.
 */
"use strict";
(function (root) {
  var te = new TextEncoder();
  var ALG = "RSA-OAEP-SHA256+A256GCM";
  var COMMON = ["password", "qwerty", "letmein", "welcome", "admin",
                "iloveyou", "spellbook", "123456", "abcdef"];

  function $(id) { return document.getElementById(id); }
  function show(el, on) { el.hidden = !on; }

  function bytesToHex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }
  function bytesToB64(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function b64ToBytes(s) {
    s = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function b64url(b) {
    return bytesToB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /* The agent puts only PUBLIC data in the fragment: k = SPKI DER
   * (base64url), op = seal | unlock | restore. Browsers never send the
   * fragment to the server. */
  function readFragment(hash) {
    var out = { key: null, op: null };
    var h = (hash || "").replace(/^#/, "");
    h.split("&").forEach(function (kv) {
      var i = kv.indexOf("=");
      if (i < 0) return;
      var k = kv.slice(0, i), v = decodeURIComponent(kv.slice(i + 1));
      if (k === "k" && v) out.key = b64ToBytes(v);
      if (k === "op" && /^(seal|unlock|restore)$/.test(v)) out.op = v;
    });
    return out;
  }

  async function fingerprint(der) {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", der)));
  }
  function grouped(hex) { return hex.replace(/(.{4})/g, "$1 ").trim(); }
  function normFp(s) { return (s || "").toLowerCase().replace(/[^0-9a-f]/g, ""); }

  async function importPub(der) {
    var key = await crypto.subtle.importKey(
      "spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
    if (key.algorithm.modulusLength < 2048) throw new Error("key is under 2048 bits");
    return key;
  }

  function canonicalAad(kind, kfp) {
    /* Same bytes as json.dumps(sort_keys=True, separators=(",", ":")). */
    return te.encode('{"alg":"' + ALG + '","kfp":"' + kfp + '","kind":"' +
                     kind + '","v":1}');
  }

  async function hybrid(der, plaintext, aad) {
    var pub = await importPub(der);
    var aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var params = { name: "AES-GCM", iv: iv };
    if (aad) params.additionalData = aad;
    var ct = new Uint8Array(await crypto.subtle.encrypt(params, aes, plaintext));
    var raw = new Uint8Array(await crypto.subtle.exportKey("raw", aes));
    var ek = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, raw));
    raw.fill(0);
    if (plaintext.fill) plaintext.fill(0);
    return { ek: ek, iv: iv, ct: ct };
  }

  /* SPELLBOOK-CEREMONY1: seal / unlock / restore, bound to the key's
   * fingerprint and the kind (AAD). */
  async function sealEnvelope(kind, payload, der) {
    var kfp = await fingerprint(der);
    var h = await hybrid(der, te.encode(JSON.stringify(payload)), canonicalAad(kind, kfp));
    var env = { v: 1, kind: kind, kfp: kfp, alg: ALG,
                ek: bytesToB64(h.ek), iv: bytesToB64(h.iv), ct: bytesToB64(h.ct) };
    return "SPELLBOOK-CEREMONY1." + b64url(te.encode(JSON.stringify(env)));
  }

  /* SPELLBOOK-SEED-ENC2: the daemon's passwordless sealed seed
   * (sealed_envelope_path). 128 hex chars of BIP-39 seed. */
  async function sealEnc2(seedHex, der) {
    var h = await hybrid(der, te.encode(seedHex), null);
    var env = { v: 2, algo: "RSA-OAEP-SHA256+AES-GCM-256",
                ek: bytesToHex(h.ek), iv: bytesToHex(h.iv), ct: bytesToHex(h.ct) };
    return "SPELLBOOK-SEED-ENC2." + btoa(JSON.stringify(env));
  }

  /* BIP-39: checksum-verify 24 words; returns the 32-byte entropy. */
  async function mnemonicEntropy(sentence, label) {
    var words = (sentence || "").trim().toLowerCase().split(/\s+/);
    if (words.length !== 24 || words[0] === "")
      throw new Error(label + ": enter all 24 words, separated by spaces.");
    var idx = root.SB_BIP39_INDEX;
    if (!idx) {
      idx = {};
      root.SB_BIP39.forEach(function (w, i) { idx[w] = i; });
      root.SB_BIP39_INDEX = idx;
    }
    var bits = 0n;
    for (var i = 0; i < words.length; i++) {
      var v = idx[words[i]];
      if (v === undefined) throw new Error(label + ": word " + (i + 1) + " is not a BIP-39 word.");
      bits = (bits << 11n) | BigInt(v);
    }
    var ent = bits >> 8n, entropy = new Uint8Array(32);
    for (var j = 0; j < 32; j++) entropy[31 - j] = Number((ent >> BigInt(j * 8)) & 0xFFn);
    var digest = new Uint8Array(await crypto.subtle.digest("SHA-256", entropy));
    if (digest[0] !== Number(bits & 0xFFn))
      throw new Error(label + ": checksum failed — a word is mis-copied. Check each against your paper.");
    return { entropy: entropy, words: words.join(" ") };
  }

  async function mnemonicToSeedHex(words) {
    var km = await crypto.subtle.importKey("raw", te.encode(words.normalize("NFKD")),
                                           { name: "PBKDF2" }, false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-512", salt: te.encode("mnemonic"), iterations: 2048 }, km, 512);
    return bytesToHex(new Uint8Array(bits));
  }

  /* Strength rule — mirrors spellbook.ceremony.password_problem exactly. */
  function passwordProblem(pw) {
    var chars = Array.from(pw), n = chars.length;
    if (n < 12) return "use at least 12 characters";
    if (n > 512) return "keep it under 512 characters";
    var low = pw.toLowerCase();
    var words = low.split(/\s+/).filter(function (w) { return w; });
    if (words.length >= 6 && new Set(words).size >= 6 &&
        words.every(function (w) { return root.SB_BIP39.indexOf(w) >= 0; })) return null;
    var distinct = new Set(chars).size;
    if (distinct < 8) return "too repetitive: use at least 8 different characters";
    if (n < 20 && COMMON.some(function (c) { return low.indexOf(c) >= 0; }))
      return "contains a common password pattern";
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (chars.some(function (c) { return !/^[A-Za-z0-9]$/.test(c); })) pool += 33;
    var bits = Math.min(n, 2 * distinct) * Math.log2(pool);
    if (bits < 60) return "too weak: make it longer or mix character types (or use 6+ generated words)";
    return null;
  }

  function generateWords(count) {
    /* 2^32 is a multiple of 2048, so the modulo is unbiased. */
    var r = new Uint32Array(count), out = [];
    crypto.getRandomValues(r);
    for (var i = 0; i < count; i++) out.push(root.SB_BIP39[r[i] % 2048]);
    r.fill(0);
    return out.join(" ");
  }

  async function copy(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) { /* fall through */ }
    return false;
  }

  function selectAll(el) {
    try {
      var sel = window.getSelection(), r = document.createRange();
      sel.removeAllRanges(); r.selectNodeContents(el); sel.addRange(r);
    } catch (_) { /* nothing to do */ }
  }

  /* Recipient-key panel: shows the fingerprint, lets the human compare it
   * with the one their daemon printed. Resolves to the key DER or null. */
  async function keyPanel(ids) {
    var frag = readFragment(location.hash);
    if (!frag.key) {
      $(ids.fp).textContent = "No key in this link. Ask your agent for the full link (it ends in #k=...).";
      return { der: null, op: frag.op };
    }
    try { await importPub(frag.key); } catch (e) {
      $(ids.fp).textContent = "The key in this link is not a usable RSA public key.";
      return { der: null, op: frag.op };
    }
    var fp = await fingerprint(frag.key);
    $(ids.fp).textContent = grouped(fp);
    var check = function () {
      var typed = normFp($(ids.input).value);
      var ok = typed.length >= 16 && fp.indexOf(typed) === 0;
      $(ids.status).textContent = !typed ? "" : ok
        ? "Matches the fingerprint you entered."
        : "DOES NOT MATCH. Stop: this link carries a different key than your daemon's.";
      $(ids.status).className = !typed ? "note" : ok ? "ok" : "err";
      return ok;
    };
    $(ids.input).addEventListener("input", check);
    return { der: frag.key, op: frag.op, fp: fp, matched: check };
  }

  root.SB = {
    $: $, show: show, bytesToHex: bytesToHex, bytesToB64: bytesToB64,
    b64ToBytes: b64ToBytes, b64url: b64url, readFragment: readFragment,
    fingerprint: fingerprint, grouped: grouped, importPub: importPub,
    sealEnvelope: sealEnvelope, sealEnc2: sealEnc2,
    mnemonicEntropy: mnemonicEntropy, mnemonicToSeedHex: mnemonicToSeedHex,
    passwordProblem: passwordProblem, generateWords: generateWords,
    copy: copy, selectAll: selectAll, keyPanel: keyPanel
  };
})(window);
