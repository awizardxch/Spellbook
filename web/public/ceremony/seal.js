/* Seal / unlock: the password is encrypted to the daemon's public key in
 * this browser and leaves only as a SPELLBOOK-CEREMONY1 envelope. */
"use strict";
(async function () {
  var SB = window.SB, $ = SB.$;
  var key = await SB.keyPanel({ fp: "keyfp", input: "fpIn", status: "fpStatus" });
  var op = key.op === "seal" ? "seal" : "unlock";

  function setOp(o) {
    op = o;
    $("opSeal").checked = o === "seal";
    $("opUnlock").checked = o === "unlock";
    SB.show($("sealBox"), o === "seal");
    SB.show($("unlockBox"), o === "unlock");
    $("pwErr").textContent = "";
  }
  $("opSeal").addEventListener("change", function () { setOp("seal"); });
  $("opUnlock").addEventListener("change", function () { setOp("unlock"); });
  setOp(op);

  $("genPw").addEventListener("click", function () {
    var w = SB.generateWords(8);
    $("pw1").value = w; $("pw2").value = w;
    $("pw1").type = "text"; $("pw2").type = "text";
    $("togglePw").textContent = "Hide";
  });
  $("togglePw").addEventListener("click", function () {
    var showIt = $("pw1").type === "password";
    $("pw1").type = $("pw2").type = showIt ? "text" : "password";
    $("togglePw").textContent = showIt ? "Hide" : "Show";
  });

  function clearFields() {
    $("pw1").value = ""; $("pw2").value = ""; $("pwU").value = "";
    $("pw1").type = $("pw2").type = "password";
    $("togglePw").textContent = "Show";
  }

  $("encBtn").addEventListener("click", async function () {
    var err = $("pwErr");
    err.textContent = "";
    SB.show($("outStep"), false);
    if (!key.der) { err.textContent = "This link has no usable key. Ask your agent for the full link."; return; }
    if (!key.matched() && !$("noFp").checked) {
      err.textContent = "Compare the key fingerprint first (step 1), or tick the box if you have none.";
      return;
    }
    var pw;
    if (op === "seal") {
      pw = $("pw1").value;
      if (pw !== $("pw2").value) { err.textContent = "The two passwords do not match."; return; }
      var problem = SB.passwordProblem(pw);
      if (problem) { err.textContent = "Password refused: " + problem + "."; return; }
    } else {
      pw = $("pwU").value;
      if (!pw) { err.textContent = "Enter your seal password."; return; }
    }
    var btn = $("encBtn");
    btn.disabled = true;
    try {
      var env = await SB.sealEnvelope(op, { password: pw }, key.der);
      pw = null;
      clearFields();
      $("envOut").textContent = env;
      SB.show($("outStep"), true);
      $("envOk").textContent = "Encrypted. Copy it and paste it to your agent.";
      $("copyEnv").onclick = async function () {
        var ok = await SB.copy(env);
        $("envOk").textContent = ok ? "Copied. Paste it to your agent."
          : "Copy was blocked. Tap the envelope to select it, then copy by hand.";
      };
      $("envOut").addEventListener("click", function () { SB.selectAll($("envOut")); });
    } catch (e) {
      err.textContent = "Encryption failed: " + e.message;
    }
    btn.disabled = false;
  });
})();
