> [!WARNING]
> 💥 Attention please! You've entered our testing ground! ☠ The contents of this repo are purely for testing purposes. Please don't use the files or information here for any other reason. Thank you for your cooperation! 🌟

# Create SBOM from ports

As this is not yet integrated to ports Makefiles as target it means it has to be run like this:

```bash
LUA_PATH="/location/of/lua/files/?.lua;;" /usr/libexec/flua /location/of/lua/files/spdx-traverse-deps.lua
```

# Test files
There is some output files to see how does it look like:
* fv.json-ld is SBOM Lite 3.0.1 JSON-LD for graphics/fv
* fyre.json-ld is SBOM Lite 3.0.1 JSON-LD for graphics/fyre

One can see graphical export with (In SVG format):

```
rdf2dot -f json-ld fv.json-ld | dot -Tsvg > fv.svg
```

