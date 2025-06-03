# vuln-test
This repository contains a snapshot from a trivial [VuXML](https://vuxml.freebsd.org/freebsd/index.html) converted to an [OSVF](https://ossf.github.io/osv-schema/) database.

## The idea behind the database
The vulnerabilities are stored in the `vuln` directory, which is divided into yearly subdirectories.
This structure aims to reduce the size of the directory. Each yearly subdirectory contains all affected
packages that were spotted in that year, organized under a package-named directory, with an OSVF-formatted
file named after the tagging `FBSD-YYYY-MM-DD.json`.

For example:

```
vuln/
    2025/
        somepackage/
                    FBSD-2025-06-03.json
```

## Why use Git?
Using Git makes it easy to get a local copy of the database. If you want to have a local first  database,
cloning and updating the repository is straightforward. Additionally, if you know the package name and year,
you can easily search backward yearly and check if there are any vulnerabilities that year.

# How to convert
Do this with Python 3.11 and above:
```
wget https://vuxml.freebsd.org/freebsd/vuln.xml
python3 bin/convert_vuxml.py -o vuln vuln.xml`
```
