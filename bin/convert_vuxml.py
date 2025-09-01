#!/usr/bin/env python
#
# Copyright (C) 1994-2024 The FreeBSD Project.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Copyright (c) 2024 The FreeBSD Foundation
#
# Portions of this software were developed by Pierre Pronchery
# <pierre@defora.net> at Defora Networks GmbH under sponsorship
# from the FreeBSD Foundation.

"""VuXML to OSV converter."""
import datetime
import getopt
import json
from lxml import etree
import os
from pathlib import Path
import re
import sys
from markdownify import markdownify as md

# ruamel.yaml is a YAML 1.2 loader/dumper package for Python.
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString
import tomli_w

re_date = re.compile(r"^(19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}$")
re_invalid_package_name = re.compile("[@!#$%^&*()<>?/\\|}{~:]")

# warn if description has more than X characters
DESCRIPTION_LENGTH = 5000

namespace = "{http://www.vuxml.org/apps/vuxml-1}"

url_advisories = [
    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
    "https://nvd.nist.gov/vuln/detail/",
    "https://github.com/advisories/",
    "https://www.debian.org/security/",
]
url_bid = "https://www.securityfocus.com/bid/%s/info"
url_certsa = "https://www.cert.org/advisories/%s.html"
url_certvu = "https://www.kb.cert.org/vuls/id/%s"
url_cve = "https://api.osv.dev/v1/vulns/%s"
url_freebsd_bugzilla = "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=%s"
url_freebsd_sa = "https://www.freebsd.org/security/advisories/FreeBSD-%s.asc"
url_reports = [
    "https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=",
    "http://bugzilla.mozilla.org/show_bug.cgi?id=",
    "https://bugzilla.mozilla.org/show_bug.cgi?id=",
    "https://bugzilla.redhat.com/show_bug.cgi?id=",
    "https://bugzilla.suse.com/show_bug.cgi?id=",
]


class PrefixResolver(etree.Resolver):
    def __init__(self, prefix):
        self.prefix = prefix
        self.result_xml = (
            """\
              <xsl:stylesheet
                     xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                <test xmlns="testNS">%s-TEST</test>
              </xsl:stylesheet>
              """
            % prefix
        )

    def resolve(self, url, pubid, context):
        if url.startswith(self.prefix):
            print("Resolved url %s as prefix %s" % (url, self.prefix))
            return self.resolve_string(self.result_xml, context)


# dateof
def dateof(string):
    return datetime.datetime.strptime(string, "%Y-%m-%d")


def formatdate(date):
    # RFC 3339 ending with Z
    return date.strftime("%Y-%m-%dT%H:%M:%SZ")


# error
def error(string):
    print(f"{sys.argv[0]}: error: {string}", file=sys.stderr)
    return 2


# usage
def usage(e=None):
    if e is not None:
        print(e, file=sys.stderr)
    print(
        "Usage: %s [-e ecosystem][-o output_directory][-F][-r] vuln.xml" % sys.argv[0],
        file=sys.stderr,
    )
    return 1


# warn
def warn(string):
    print(f"{sys.argv[0]}: warning: {string}", file=sys.stderr)


# main
def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "e:o:FrYT")
    except getopt.GetoptError as e:
        return usage(e)
    ecosystem = "FreeBSD:ports"
    output = None
    output_flat = False
    output_running = False
    output_json = False
    output_yaml = False
    output_toml = False
    yaml = None

    output_id = {}

    for name, optarg in opts:
        if name == "-e":
            ecosystem = optarg
        elif name == "-o":
            output = optarg
        elif name == "-F":
            output_flat = True
        elif name == "-r":
            output_running = True
        elif name == "-Y":
            output_yaml = True
            yaml = YAML()
        elif name == "-T":
            output_toml = True
        else:
            return usage("%s: Unsupported option" % name)

    if len(args) != 1:
        return usage()

    if output_yaml == False and output_toml == False:
        output_json = True

    parser = etree.XMLParser(dtd_validation=False)
    tree = etree.parse(args[0], parser)
    root = tree.getroot()

    ret = 0

    entries = []
    for vuln in root:
        if vuln.find(namespace + "cancelled") is not None:
            continue

        # id
        vid = vuln.get("vid")
        entry = {"schema_version": "1.7.0"}
        dates = {"modified": None, "published": None}

        # modified
        try:
            d = vuln.find(namespace + "dates").find(namespace + "entry").text
            if not re_date.match(d):
                ret = error("entry date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_entry = dateof(d)
        except Exception as e:
            dates_entry = None
        try:
            d = vuln.find(namespace + "dates").find(namespace + "modified").text
            if not re_date.match(d):
                ret = error("modified date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_modified = dateof(d)
        except Exception as e:
            dates_modified = None
        if dates_modified is not None:
            entry["modified"] = formatdate(dates_modified)
            dates["modified"] = dates_modified
        elif dates_entry is not None:
            entry["modified"] = formatdate(dates_entry)
            dates["modified"] = dates_entry
        if dates_entry is not None:
            entry["published"] = formatdate(dates_entry)
            dates["published"] = dates_entry

        # summary
        try:
            summary = vuln.find(namespace + "topic").text
        except Exception as e:
            ret = error(f"{vid} has no topic")
            summary = None
        if summary is not None:
            entry["summary"] = summary

        # details
        details = vuln.find(namespace + "description")
        if details is None:
            ret = error(f"{vid} has no description")
        else:
            try:
                details_html = etree.tostring(
                    details, encoding="unicode", method="html"
                ).strip()
                # Documentatio states that:
                # The details field is CommonMark markdown (a subset of GitHub-Flavored Markdown).
                # Input is in HTML5. Make conversion with markdownify.
                if output_json or output_toml:
                    details = str(md(details_html))
                elif output_yaml == True:
                    # With YAML we like to have output:
                    # details: |-
                    #    Some text here
                    #    > Some quatation here
                    details = LiteralScalarString(str(md(details_html)))

                if len(details) > DESCRIPTION_LENGTH:
                    warn("%s: description truncated (> %s)" % (vid, DESCRIPTION_LENGTH))
                    details = details[0:DESCRIPTION_LENGTH]
            except Exception as e:
                ret = error(
                    "%s could not parse description: %s: %s"
                    % (vid, type(e).__name__, e)
                )
                details = None
        if details is not None:
            entry["details"] = details

        # references
        references = []
        refs = vuln.find(namespace + "references")
        for ref in refs:
            if ref.text is None or len(ref.text) == 0:
                continue
            if ref.tag == namespace + "bid":
                reference = {"type": "ADVISORY", "url": url_bid % ref.text}
            elif ref.tag == namespace + "certsa":
                reference = {"type": "ADVISORY", "url": url_certsa % ref.text}
            elif ref.tag == namespace + "certvu":
                reference = {"type": "ADVISORY", "url": url_certvu % ref.text}
            elif ref.tag == namespace + "cvename":
                reference = {"type": "ADVISORY", "url": url_cve % ref.text}
            elif ref.tag == namespace + "freebsdpr" and len(ref.text.split("/")) == 2:
                id = ref.text.split("/")[1]
                reference = {"type": "REPORT", "url": url_freebsd_bugzilla % id}
            elif ref.tag == namespace + "freebsdsa":
                reference = {"type": "ADVISORY", "url": url_freebsd_sa % ref.text}
            elif ref.tag == namespace + "mlist":
                reference = {"type": "DISCUSSION", "url": ref.text}
            elif ref.tag == namespace + "url":
                reference = {"type": "WEB", "url": ref.text}
                for prefix in url_advisories:
                    if str(ref.text).startswith(prefix):
                        reference["type"] = "ADVISORY"
                        break
                if reference["type"] == "WEB":
                    for prefix in url_reports:
                        if str(ref.text).startswith(prefix):
                            reference["type"] = "REPORT"
                            break
            else:
                continue
            references.append(reference)
        if len(references) > 0:
            entry["references"] = references

        # affected
        affected = []
        affects = vuln.find(namespace + "affects")
        for package in affects.findall(namespace + "package"):

            # affected: package
            for name in package.findall(namespace + "name"):
                a = {}
                if re_invalid_package_name.search(name.text) is not None:
                    ret = error("%s package with invalid name: %s" % (vid, name.text))
                    continue
                p = {"ecosystem": ecosystem, "name": name.text}
                a["package"] = p

                # affected: ranges
                try:
                    ranges = []
                    versions = []
                    for e in package.findall(namespace + "range"):
                        events = []
                        semver = {"type": "ECOSYSTEM"}

                        # affected: ranges
                        event = {}
                        ge = e.find(namespace + "ge")
                        if ge is not None and len(ge.text) > 0 and ge.text != "*":
                            event["introduced"] = ge.text
                        gt = e.find(namespace + "gt")
                        if gt is not None and len(gt.text) > 0 and gt.text != "*":
                            # FIXME not accurate!!1
                            event["introduced"] = gt.text + ",1"
                        le = e.find(namespace + "le")
                        if le is not None and len(le.text) > 0 and le.text != "*":
                            event["last_affected"] = le.text
                        lt = e.find(namespace + "lt")
                        if lt is not None and len(lt.text) > 0 and lt.text != "*":
                            event["fixed"] = lt.text
                        if "fixed" in event or "introduced" in event:
                            if "introduced" not in event:
                                event["introduced"] = "0"
                        for k, v in event.items():
                            events.append({k: v})

                        # affected: versions
                        eq = e.find(namespace + "eq")
                        if eq is not None and len(eq.text) > 0 and eq.text != "*":
                            versions.append(eq.text)

                        if len(events) > 0:
                            semver["events"] = events
                            ranges.append(semver)
                except Exception as e:
                    warn(e, file=sys.stderr)
                    ranges = []
                if len(ranges) > 0:
                    a["ranges"] = ranges
                if len(versions) > 0:
                    a["versions"] = versions

                if len(a) > 0:
                    affected.append(a)
            if len(affected) > 0:
                entry["affected"] = affected

        # database_specific
        database_specific = {"vid": vid}
        try:
            d = vuln.find(namespace + "dates").find(namespace + "discovery").text
            if not re_date.match(d):
                ret = error("discovery date not in YYYY-MM-DD format: {0}".format(d))
                raise
            else:
                dates_discovery = dateof(d)
        except Exception as e:
            dates_discovery = None
        if dates_discovery is not None:
            database_specific["discovery"] = formatdate(dates_discovery)
        if len(database_specific) > 0:
            entry["database_specific"] = database_specific

        if output is not None:
            try:
                date_str = None
                date_obj = None
                year_str = None
                if dates["published"] is not None:
                    date_str = dates["published"].strftime("%Y-%m-%d")
                    year_str = dates["published"].strftime("%Y")
                    date_obj = dates["published"]
                elif dates["modified"] is not None:
                    date_str = dates["modified"].strftime("%Y-%m-%d")
                    year_str = dates["published"].strftime("%Y")
                    date_obj = dates["modified"]

                # File name can be with date of release:
                # FBSD-20250101.json
                # or just running number
                # FBSD-2025-0001.json
                # When using running id then there won't be yearly
                # subdirs
                if output_running is False:
                    if date_str not in output_id:
                        output_id[date_str] = 0
                    output_id[date_str] += 1
                    output_file = (
                        f"FBSD-" + date_str + "-" + str(output_id[date_str]).zfill(2)
                    )
                else:
                    if year_str not in output_id:
                        output_id[year_str] = 0
                    output_id[year_str] += 1
                    output_file = (
                        f"FBSD-" + year_str + "-" + str(output_id[year_str]).zfill(4)
                    )

                # Make sure that is same as filename
                entry["id"] = output_file

                if date_str is None:
                    raise Exception("There is no date in " + str(entry["affected"]))

                if output_flat is False:
                    output_year_path = output + "/" + year_str
                    print(output_year_path)
                else:
                    output_year_path = output

                if os.path.isdir(output_year_path) is False:
                    os.mkdir(output_year_path)
                    year_date = datetime.date(int(year_str), 1, 1)
                    year_time_ts = int(year_date.strftime("%s"))
                    os.utime(output_year_path, (year_time_ts, year_time_ts))

                affected_array = entry["affected"]

                output_name = affected_array[0]["package"]["name"]

                del affected_array[0]

                # If output is not flat then output path will be like
                # 2025/somepackage/ with flat only 2025/
                if output_flat is False:
                    output_path_with_name = output_year_path + "/" + output_name
                else:
                    output_path_with_name = output_year_path

                if os.path.isdir(output_path_with_name) is False:
                    os.mkdir(output_path_with_name)

                if output_json:
                    output_with_suffix = output_file + ".json"
                elif output_yaml:
                    output_with_suffix = output_file + ".yaml"
                else:
                    output_with_suffix = output_file + ".toml"

                output_full_path = output_path_with_name + "/" + output_with_suffix

                if os.path.isfile(output_full_path) is True:
                    print("already here: " + output_full_path)

                # JSON and YAML take string but with TOML dump
                # one have to open file with binary to write
                # as bytes
                if output_json or output_yaml:
                    with open(output_full_path, "w") as f:
                        if output_json:
                            print(json.dumps(entry, indent=4, sort_keys=True), file=f)
                        elif output_yaml:
                            yaml.dump(entry, f)
                else:
                    with open(output_full_path, "wb") as f:
                        tomli_w.dump(entry, f, indent=4, multiline_strings=True)

                if os.path.isfile(output_full_path):
                    timeint = int(date_obj.strftime("%s"))
                    os.utime(output_full_path, (timeint, timeint))

                # If we are not havin flat system then for saving space link
                # to original file do not make duplicates
                if output_flat is False:
                    for affected in affected_array:
                        affected_year_with_name = (
                            output_year_path + "/" + affected["package"]["name"]
                        )

                        if os.path.isdir(affected_year_with_name) is False:
                            os.mkdir(affected_year_with_name)

                        src_path = "../" + output_name + "/" + output_with_suffix
                        to_path = affected_year_with_name + "/" + output_with_suffix

                        if (
                            os.path.isfile(to_path) is False
                            and os.path.islink(to_path) is False
                        ):
                            os.symlink(src_path, to_path)
            except Exception as e:
                print("There was an error: ", e)
                ret = error(e)
        else:
            entries.append(entry)

    if output is None:
        if output_json:
            if len(entries) == 1:
                print(json.dumps(entries[0], indent=4))
            else:
                print(json.dumps(entries, indent=4))
        elif output_yaml:
            yaml.dump(entries, sys.stdout)
        else:
            for item in entries:
                print(tomli_w.dumps(item, indent=4, multiline_strings=True))

    return ret


if __name__ == "__main__":
    sys.exit(main())
