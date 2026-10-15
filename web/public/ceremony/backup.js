/* Backup reveal: a non-extractable RSA key made in this tab; the agent
 * relays its public half to `spellbook export --reveal-key` and brings back
 * the envelope (src/spellbook/export.py seal_to_reveal_key). */
"use strict";
(function () {
  var SB = window.SB, $ = SB.$;
  var priv = null;

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
      $("docOut").textContent = new TextDecoder().decode(pt);
      new Uint8Array(pt).fill(0);
      $("envIn").value = "";
      SB.show($("docBox"), true);
    } catch (e) {
      err.textContent = "Could not decrypt. Paste the whole envelope, and keep this tab open from step 1.";
    }
  });

  $("clearBtn").addEventListener("click", function () {
    $("docOut").textContent = "";
    SB.show($("docBox"), false);
  });
})();
