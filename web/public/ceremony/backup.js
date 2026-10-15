/* Backup reveal: a non-extractable RSA key made in this tab; the agent
 * relays its public half to `spellbook export --reveal-key` and brings back
 * the envelope (src/spellbook/export.py seal_to_reveal_key). */
"use strict";
(function () {
  var SB = window.SB, $ = SB.$;
  var priv = null;
  var CODE_RE = /BACKUP CONFIRMATION CODE:\s*([A-Z0-9]{4}(?:-[A-Z0-9]{4}){3})/;

  $("genBtn").addEventListener("click", async function () {
    $("genErr").textContent = "";
    try {
      var kp = await crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        false, ["encrypt", "decrypt"]);
      priv = kp.privateKey;
      var spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
      $("pubOut").value = SB.bytesToB64(spki);
      SB.show($("pubBox"), true);
      $("genBtn").disabled = true;
    } catch (e) {
      $("genErr").textContent = "Key generation failed: " + e.message;
    }
  });

  $("copyPub").addEventListener("click", async function () {
    var ok = await SB.copy($("pubOut").value);
    $("pubOk").textContent = ok ? "Copied. Paste it to your agent." : "Copy was blocked; select the text and copy by hand.";
  });

  $("openBtn").addEventListener("click", async function () {
    var err = $("openErr");
    err.textContent = "";
    if (!priv) { err.textContent = "Make the reveal key first (step 1)."; return; }
    try {
      var env = JSON.parse(new TextDecoder().decode(SB.b64ToBytes($("envIn").value.trim())));
      var aesRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, SB.b64ToBytes(env.k));
      var aes = await crypto.subtle.importKey("raw", aesRaw, "AES-GCM", false, ["decrypt"]);
      new Uint8Array(aesRaw).fill(0);
      var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: SB.b64ToBytes(env.n) }, aes, SB.b64ToBytes(env.c));
      var doc = new TextDecoder().decode(pt);
      new Uint8Array(pt).fill(0);
      $("docOut").textContent = doc;
      $("envIn").value = "";
      SB.show($("docBox"), true);
      /* S-16: the backup ends with a one-time code the daemon needs back
       * (spellbook backup-confirm) before it moves funds. */
      var m = CODE_RE.exec(doc);
      $("codeOut").textContent = m ? m[1] : "";
      $("codeOk").textContent = "";
      SB.show($("codeStep"), !!m);
    } catch (e) {
      err.textContent = "Could not decrypt. Paste the whole envelope, and keep this tab open from step 1.";
    }
  });

  $("copyCode").addEventListener("click", async function () {
    var ok = await SB.copy($("codeOut").textContent);
    $("codeOk").textContent = ok ? "Copied. Send it to your agent once the words are on paper."
      : "Copy was blocked; select the code and copy by hand.";
  });

  $("clearBtn").addEventListener("click", function () {
    $("docOut").textContent = "";
    SB.show($("docBox"), false);
  });
})();
