> [!WARNING]
> 💥 Attention please! You've entered our testing ground! ☠ The contents of this repo are purely for testing purposes. Please don't use the files or information here for any other reason. Thank you for your cooperation! 🌟

# vuln-test

This repository contains vulnerability data converted from [VuXML](https://vuxml.freebsd.org/freebsd/index.html) to the 
[OSVF](https://ossf.github.io/osv-schema/) format.

## Database Structures

### Non-flat Database (`vuln-noflat`-directory)
- Organized by yearly subdirectories
- Each year has a directory for affected packages with OSVF-formatted JSON files named `FBSD-YYYY-MM-DD-??.json`
- Example:
  ```
  vuln-noflat/
              2025/
                   somepackage/
                              FBSD-2025-06-03-00.json
  ```

### Flat Database (`vuln-flat`-directory)
- All files in a single directory (can be organized by year)
- Files named `FBSD-YYYY-MM-DD-??.json`, with running numbers for same-date vulnerabilities
- Example:
  ```
  vuln-flat/
            FBSD-2025-06-03-00.json
            FBSD-2025-06-03-01.json
            FBSD-2025-06-04-00.json
  ```

### Flat Running ID Database (`vuln-flatid`-directory)
- Similar to flat database, but files have running IDs starting yearly from `0001`
- Example:
  ```
  vuln-flatid/
            FBSD-2025-0001.json
            FBSD-2025-0002.json
            FBSD-2025-0003.json
            FBSD-2025-0004.json
  ```

## Why Use Git?
- Easy local database copy with `git clone`
- Simple yearly vulnerability lookup by package name and year

## Conversion Instructions
Use Python 3.11+ (requires the `lxml`, `markdownify` (for convert HTML to CommonMark), `tomli_w` (for TOML writing) and `ruamel.yaml` (for YAML) module):

> [!TIP]
> If you like to have YAML output add `-Y` in parameters. For TOML output add `-T`.

```bash
# Download VuXML data
wget https://vuxml.freebsd.org/freebsd/vuln.xml

# Convert to Non-flat Database:
python3 bin/convert_vuxml.py -o vuln vuln.xml

# Convert to Flat Database:
python3 bin/convert_vuxml.py -F -o vuln vuln.xml

# Convert to Flat Running ID Database:
python3 bin/convert_vuxml.py -F -r -o vuln vuln.xml

```
