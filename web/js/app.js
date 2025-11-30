
// Copyright 2025 David Guillen Fandos <david@davidgf.net>

function Uint8ArrayfromHex(s) {
  if (s.length % 2 !== 0) {
    throw "Even num of chars required";
  }
  var blen = s.length / 2;
  var ret = new Uint8Array(blen);
  for (var i = 0; i < blen; i++) {
    ret[i] = parseInt(s.substr(i*2, 2), 16);
  }
  return ret;
}

var pyodide = null;
async function main() {
  async function loadpy() {
    pyodide = await loadPyodide();
    let response = await fetch("../py/patchtool-0.2.2-py3-none-any.whl");
    var buf = await response.arrayBuffer();
    await pyodide.unpackArchive(buf, "wheel");
    pyodide.pyimport("patchtool");
  }
  let pyrdy = loadpy()

  const ptypes = ["waitcnt", "irq", "swi1", "save", "layout", "rtc", "symmap"];
  const pnames = {"waitcnt": "WaitCNT", "irq": "IRQ handler", "swi1": "WaitCNT (SWI1)",
                  "save": "Save game", "layout": "ROM Layout", "rtc": "RTC emulation",
                  "symmap": "Symbol Map"};
  var patchmap = {};
  var nump = 0;

  function render_status() {
    var ret = "";
    for (var t in patchmap) {
      if (patchmap[t]["result"] == "err")
        ret += "<div> &#x274C; " + pnames[t] + " patches</div>";
      else {
        var einfo = (patchmap[t]["data"] == null) ? "[No patches]" : "";
        ret += "<div> &#x2705; " + pnames[t] + " patches " + einfo + "</div>";
      }
    }
    return ret;
  }

  var patch_ret = async function (event) {
    var r = JSON.parse(event.data.result);
    patchmap[event.data.type] = r;

    if (r["result"] == "err")
      console.log(r);

    // Update the status DIV with the current patches
    var st = render_status();

    // Check if we have all the necessary patch types
    nump--;
    if (nump == 0) {
      // TODO: Validate all patches, if any patch has an error, prompt a modal
      // with some ereror info. And generate the patch nevertheless :)

      // Merge the patches trivially since there's only one ROM!
      // SWI1 and WAITCNT patches need some custom merging though.
      if ("swi1" in patchmap && "waitcnt" in patchmap && patchmap.swi1.data != null) {
        patchmap.waitcnt.data.targets.waitcnt["patch-sites"] = patchmap.waitcnt.data.targets.waitcnt["patch-sites"].concat(
                                                                 patchmap.swi1.data.targets.waitcnt["patch-sites"]);
        delete patchmap["swi1"];
      }

      // Prepare generator input, merge all dicts
      var merged = {
        "game-code": patchmap.waitcnt.data["game-code"],
        "game-version": patchmap.waitcnt.data["game-version"],
        "files": [],
        "romsize": patchmap.waitcnt.data["filesize"],
        "targets": {},
      };
      // Merge all assets in order by ptypes. This makes symmap win over other targets.
      for (var t of ptypes)
        if (t in patchmap && patchmap[t].data != null)
          merged["targets"] = { ...merged["targets"], ...patchmap[t].data.targets };

      console.log(merged);

      // Do some pythoning :)
      var pbin = await generate_patches(merged);

      // Generate binary patch in .patch format (not a PatchDB!)
      if (pbin.result == "ok") {
        var pbuf = Uint8ArrayfromHex(pbin.data);
        var fname = document.getElementById("filebox").files[0].name;
        var bname = fname.lastIndexOf('.') < 0 ? fname : fname.substring(0, fname.lastIndexOf('.'));

        const f = new File([pbuf], bname + '.patch', { type: "octet/stream" });
        const u = URL.createObjectURL(f);
        document.getElementById('downbut').href = u;

      } else {
        st = "An error occured: " + pbin.data;
      }

      document.getElementById('downb').classList.toggle('d-none');
    } else {
      st += "<div>Generating patches...</div>";
    }

    document.getElementById("status").innerHTML = st;
  };

  // Create a bunch of workers.
  var workermap = {};
  for (var t of ptypes) {
    const worker = new Worker("js/worker.js");
    worker.onmessage = patch_ret;
    workermap[t] = worker;
  }

  var b = document.getElementById("mainb");
  b.addEventListener("click", processrom);

  function loadFiles(fileMap, cb, resultMap = {}) {
    const keys = Object.keys(fileMap);
    if (!keys.length)
      return cb(resultMap);

    const key = keys[0];
    const reader = new FileReader();

    reader.onload = () => {
      resultMap[key] = new Int8Array(reader.result);
      const remaining = Object.fromEntries(keys.slice(1).map(k => [k, fileMap[k]]));
      loadFiles(remaining, cb, resultMap);
    };

    reader.readAsArrayBuffer(fileMap[key]);
  }

  function processrom() {
    patchmap = {};

    // Read local file to a buffer
    var fm = document.getElementById("filebox");
    var fs = document.getElementById("symfilebox");
    var imap = {
      "rom": fm.files[0],
    };
    if (fs.files && fs.files.length > 0)
      imap["sym"] = fs.files[0];

    if (!fm.files[0]) {
      alert("You need to pick a GBA ROM!");
      return;
    }

    if (fm.files[0].size > 32*1024*1024) {
      alert("GBA rom exceeds 32MiB!");
      return;
    }

    try {
      loadFiles(imap, (arrays) => {
        document.getElementById("status").innerHTML = "Generating patches...";
        nump = 0;
        for (let t of ptypes) {
          if (document.getElementById("p-" + t) && !document.getElementById("p-" + t).checked)
            continue;
          workermap[t].postMessage({
            "type": t,
            "rom": arrays["rom"],
            "sym": arrays["sym"],
          });
          nump++;
        }
      });

      document.getElementById("status").innerHTML = "Loading ROM...";
      document.getElementById('inpf').classList.toggle('d-none');
      document.getElementById('outf').classList.toggle('d-none');
    } catch (error) {
      // Show some error
      console.log(error);
    }
  }

  async function generate_patches(patchset) {
    await pyrdy;

    var script = `
        import struct, json, traceback, patchtool.generator

        try:
          # Generate patches by loading the game patch data
          p = json.loads(p)
          gp = patchtool.generator.GamePatch(p["game-code"], p["game-version"], p["targets"], p["romsize"])
          hinfo = gp.layout_patches()[0] if gp.layout_patches() else 0
          # Output a proper patch file with the right header.
          hdr = b"SUPERFWPATCHV01\\x00"
          hdr += struct.pack("<BBBBBxIxxxxxx",
                             len(gp.waitcnt_patches()),
                             len(gp.save_patches()),
                             gp.save_type,
                             len(gp.irq_patches()),
                             len(gp.rtc_patches()),
                             hinfo)

          for prgn in range(4):
            prg = patchtool.generator.PROGRAMS[prgn]
            hdr += struct.pack("<I", len(prg)) + prg + (b"\\x00" * (60 - len(prg)))

          content = b"".join(struct.pack("<I", x) for x in gp.waitcnt_patches() + gp.save_patches() + gp.irq_patches() + gp.rtc_patches())
          content += (b"\\x00" * (512 - len(content)))
          pload = "".join("%02x" % x for x in hdr + content)
          response = {"result": "ok", "data": pload}
        except Exception as e:
          response = {"result": "err", "data": str(traceback.format_exc())}

        response = json.dumps(response)
    `;

    const globals = pyodide.toPy({ p: JSON.stringify(patchset) });
    pyodide.runPython(script, { globals });

    return JSON.parse(globals.get('response').toString());
  }
}
main();

// Advanced menu toggle ON/OFF
document.getElementById('toggleAdvOn').addEventListener('click', togad);
document.getElementById('toggleAdvOff').addEventListener('click', togad);
function togad() {
  var advancedOptions = document.getElementById('advancedOptions');
  advancedOptions.classList.toggle('show');
  document.getElementById('toggleAdvOn').classList.toggle('advanced-options');
  document.getElementById('toggleAdvOff').classList.toggle('advanced-options');
};

document.getElementById('resetb').addEventListener('click', function () {
  document.getElementById('downb').classList.toggle('d-none');
  document.getElementById('inpf').classList.toggle('d-none');
  document.getElementById('outf').classList.toggle('d-none');
  document.getElementById('filebox').value = null;
});

