/* Restore: paper words -> envelope for the daemon's key. Words are
 * checksum-checked here and leave only encrypted. */
"use strict";
(async function () {
  var SB = window.SB, $ = SB.$;
  var key = await SB.keyPanel({ fp: "keyfp", input: "fpIn", status: "fpStatus" });
  var mode = "full";

  function setMode(m) {
    mode = m;
    SB.show($("fullBox"), m === "full");
    SB.show($("seedBox"), m === "seed");
    $("inErr").textContent = "";
  }
  $("modeFull").addEventListener("change", function () { setMode("full"); });
  $("modeSeed").addEventListener("change", function () { setMode("seed"); });

  $("encBtn").addEventListener("click", async function () {
    var err = $("inErr");
    err.textContent = "";
    SB.show($("outStep"), false);
    if (!key.der) { err.textContent = "This link has no usable key. Ask your agent for the full link."; return; }
    if (!key.matched() && !$("noFp").checked) {
      err.textContent = "Compare the key fingerprint first (step 1), or tick the box if you have none.";
      return;
    }
    var btn = $("encBtn");
    btn.disabled = true;
    try {
      var env;
      if (mode === "full") {
        var s1 = await SB.mnemonicEntropy($("set1").value, "SET 1");
        var s2 = await SB.mnemonicEntropy($("set2").value, "SET 2");
        if (s1.words === s2.words) throw new Error("SET 1 and SET 2 are the same words; they are two different sets.");
        env = await SB.sealEnvelope("restore",
          { set1_standard: s1.words, set2_daemon: s2.words }, key.der);
        s1.entropy.fill(0); s2.entropy.fill(0);
        $("set1").value = ""; $("set2").value = "";
      } else {
        var raw = $("seedIn").value.trim().toLowerCase(), seedHex;
        if (/^[0-9a-f]{128}$/.test(raw)) {
          seedHex = raw;
        } else {
          var m = await SB.mnemonicEntropy(raw, "SET 1");
          m.entropy.fill(0);
          seedHex = await SB.mnemonicToSeedHex(m.words);
        }
        env = await SB.sealEnc2(seedHex, key.der);
        seedHex = null;
        $("seedIn").value = "";
      }
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
      err.textContent = e.message;
    }
    btn.disabled = false;
  });
})();
