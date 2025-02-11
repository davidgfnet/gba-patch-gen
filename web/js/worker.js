
// Copyright 2025 David Guillen Fandos <david@davidgf.net>

// Placing ROM processors here to avoid blocking the UI and to achieve
// (potentially) some parallelism.

importScripts("pyodide.js");

async function pyload() {
  // Load python interpreter and the patchtool.
  self.pyodide = await loadPyodide();
  let response = await fetch("../py/patchtool-0.1.0-py3-none-any.whl");
  var buf = await response.arrayBuffer();
  await self.pyodide.unpackArchive(buf, "wheel");
  self.pyodide.pyimport("patchtool");
}
let initm = pyload()


self.onmessage = async function (e) {
  await initm;     // Ensure we initialized the pyodide lib.

  // Generate input variables.
  const globals = self.pyodide.toPy({ rom: e.data.rom });

  // Run the process_rom handler in the module
  var ptype = e.data.type;
  var script = `
      import io, json, patchtool.${ptype}
      rom = io.BytesIO(rom).read()   # Convert memoryview to byte string
      try:
        response = {"result": "ok", "data": patchtool.${ptype}.process_rom(rom)}
      except Exception as e:
        response = {"result": "err", "data": str(e)}

      response = json.dumps(response)
  `;

  // We need to convert the variable to a pure string so it can cross the boundary.
  self.pyodide.runPython(script, { globals });
  var resp = globals.get('response').toString();

  self.postMessage({ "type": e.data.type, "result": resp });
}


