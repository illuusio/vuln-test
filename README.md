> [!WARNING]
> 💥 Attention please! You've entered our testing ground! ☠ The contents of this repo are purely for testing purposes. Please don't use the files or information here for any other reason. Thank you for your cooperation! 🌟

# Vulnerability Naming Convention

## Context
The FreeBSD ecosystem includes the core system, kernel, and ports.

## How the vulnerability ID is used
A JSON Open Source Vulnerability format (OSVF) file is created for each vulnerability record. Each vulnerability has a unique ID that is used as both the filename and referenced within the JSON file.

## File organization in database
Files are organized by year in subdirectories under the `vuln` directory. The prefix resets to `0001` on January 1st of each year, with directories changing to reflect the current year:
```
vuln/
     2024/
          FREEBSD-2024-0001.json
          FREEBSD-2024-0002.json
          FREEBSD-2024-0003.json
          FREEBSD-2024-0004.json
          ...
    2025/
          FREEBSD-2025-0001.json
          FREEBSD-2025-0002.json
          FREEBSD-2025-0003.json
          FREEBSD-2025-0004.json
          ...
```
A tool may be created to generate a flattened JSON file from all vulnerabilities, stored as `db/FREEBSD-osvf.json`. This file should reside within the Git repository and be constructed whenever a new 
vulnerability is added. It would be served by `pkg(8)`.

Tools for constructing this flattened JSON will be located in the `bin` directory of the repository and can be written in Lua or Python, with Lua preferred for Core package tooling. If using Lua, UCL 
should be used for JSON processing.

## Vulnerability ID construction
The ID starts with the prefix `FREEBSD`, followed by the current year (to ensure uniqueness) and a running number that resets to `0001` every January 1st.

## Example Ports OSVF file:
OSVF schema is available at [https://ossf.github.io/osv-schema/](https://ossf.github.io/osv-schema/). The following example is taken from VuXML and includes the `database_specific.vid` field, which may 
not be present in all cases. Note that the OSVF schema version should be updated as needed.

```
{
    "affected": [
        {
            "package": {
                "ecosystem": "FreeBSD:ports",
                "name": "FreeBSD"
            },
            "ranges": [
                {
                    "events": [
                        {
                            "introduced": "1.0"
                        },
                        {
                            "fixed": "1.0_5"
                        }
                    ],
                    "type": "ECOSYSTEM"
                }
            ]
        }
    ],
    "database_specific": {
        "discovery": "2025-09-10T00:00:00Z",
        "vid": "1111111-2222-3333-4444-55555555"
    },
    "details": "Problem Description:\n====================\n\nA malicious value",
    "id": "FBSD-2024-0101",
    "modified": "2025-09-10T00:00:00Z",
    "published": "2025-09-10T00:00:00Z",
    "references": [
        {
            "type": "ADVISORY",
            "url": "https://www.freebsd.org/"
        }
    ],
    "schema_version": "1.7.0",
    "summary": "FreeBSD -- Integer overflow"
}
```

### Example with Linux binaries

This is just a hypothetical example.

```
{
    "affected": [
        {
            "package": {
                "ecosystem": "FreeBSD:ports",
                "name": "FreeBSD"
            },
            "ranges": [
                {
                    "events": [
                        {
                            "introduced": "1.0"
                        },
                        {
                            "fixed": "1.0_1"
                        }
                    ],
                    "type": "ECOSYSTEM"
                },
            ],
            "ecosystem_specific": {
                "linux_binary": true,
                "original_linux_distro": "Ubuntu",
                "original_distro_release": "24.04",
                "original_distro_package": "test_package_1.0.deb"
            }
        }
    ],
...
```

## Core package(s)
Once `pkgbase` is the default installation system for FreeBSD core, vulnerability names follow the same format as ports. If a vulnerability affects a specific binary, the name should be like 
`usr.bin.<binary_name>`, or if it's a larger construct, just **core**. The ecosystem naming and other details remain similar to ports with these differences:

* Ecosystem name is `FreeBSD:core`.
* Can include `:<RELEASE>` for version-specific vulnerabilities (e.g., `FreeBSD:core:14.3`).
* Affected versions are FreeBSD release or package names in the `pkg(8)` system.

### Core JSON example
```
{
    "affected": [
        {
            "package": {
                "ecosystem": "FreeBSD:core",
                "name": "usr.bin.ls"
            },
            "ranges": [
                {
                    "events": [
                        {
                            "introduced": "14.3"
                        },
                        {
                            "fixed": "14.4"
                        }
                    ],
                    "type": "ECOSYSTEM"
                },
            ],
        }
    ],
    "details": "Problem Description:\n====================\n\nls has some problem",
    "id": "FBSD-2025-0999",
    "modified": "2025-09-10T00:00:00Z",
    "published": "2025-09-10T00:00:00Z",
    "references": [
        {
            "type": "ADVISORY",
            "url": "https://www.freebsd.org/"
        },
        {
            "type": "WEB",
            "url": "https://www.freebsd.org/"
        }
    ],
    "schema_version": "1.7.0",
    "summary": "FreeBSD -- ls has a problem"
}
```

## Kernel vulnerability JSON
Kernel vulnerabilities follow the same structure as core packages with these adjustments:

* `name` should reference the module where the vulnerability appears.
* Ecosystem name is `FreeBSD:kernel`.
* Can include `:<RELEASE>` for version-specific vulnerabilities (e.g., `FreeBSD:kernel:14.3`).
* Affected versions are FreeBSD release or package names in the `pkg(8)` system.


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
