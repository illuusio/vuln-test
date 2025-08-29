#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
-- under sponsorship from the FreeBSD Foundation.
--
-- This Lua script should create Open Source Vulnerability format a.k.a OSVF
-- file (https://ossf.github.io/osv-schema/). It prompts you dialogs with bsddialog and
-- ask needed questions to create vulnerability report.
--
local unistd = require("posix.unistd")
local sys_wait = require("posix.sys.wait")

local bsddialog_location = {
	"/usr/bin/bsddialog",
	"/usr/local/bin/bsddialog",
}

local bsddialog_bin = nil
local ecosystem_array = {
	{ "FreeBSD:core", "Core packages", "off" },
	{ "FreeBSD:kernel", "Kernel packages", "off" },
	{ "FreeBSD:ports", "Ports packages", "on" },
}

local severity_type_array = {
	{
		"CVSS_V2",
		'A CVSS vector string representing the unique characteristics and severity of the vulnerability using a version of the Common Vulnerability Scoring System notation that is == 2.0 (e.g."AV:L/AC:M/Au:N/C:N/I:P/A:C").',
		"off",
	},
	{
		"CVSS_V3",
		'A CVSS vector string representing the unique characteristics and severity of the vulnerability using a version of the Common Vulnerability Scoring System notation that is >= 3.0 and < 4.0 (e.g."CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N").',
		"off",
	},
	{
		"CVSS_V4",
		'A CVSS vector string representing the unique characteristics and severity of the vulnerability using a version on the Common Vulnerability Scoring System notation that is >= 4.0 and < 5.0 (e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N").',
		"on",
	},
	{
		"Ubuntu",
		"A lowercased string representing the Ubuntu priority. This is based on many factors including severity, importance, risk, estimated number of affected users, software configuration, active exploitation, and other factors.",
		"off",
	},
}

local version_type_array = {
	{ "SEMVER", "Semantic versions defined by SemVer 2.0.0", "off" },
	{ "ECOSYSTEM", "Version specific to the package ecosystem", "on" },
	{ "GIT", "Full-length Git commit hashes", "off" },
}

local event_type_array = {
	{ "introduced", "Introduces a vulnerability", "off" },
	{ "fixed", "Fixes a vulnerability", "on" },
	{ "last_affected", "Describes the last known affected version", "off" },
	{ "limit", "Sets an upper limit on the range being described", "off" },
}

local reference_type_array = {
	{ "ADVISORY", "Security advisory for the vulnerability.", "off" },
	{ "ARTICLE", "An article or blog post describing the vulnerability.", "on" },
	{
		"DETECTION",
		"A tool, script, scanner, or other mechanism that allows for detection of the vulnerability in production environments.",
		"off",
	},
	{ "DISCUSSION", "A social media discussion regarding the vulnerability.", "off" },
	{ "REPORT", "A report, typically on a bug or issue tracker, of the vulnerability.", "off" },
	{
		"FIX",
		"A source code browser link to the fix Note that the fix type is meant for viewing by people using web browsers.",
		"off",
	},
	{
		"INTRODUCED",
		"A source code browser link to the introduction of the vulnerability Note that the introduced type is meant for viewing by people using web browsers.",
		"off",
	},
	{ "PACKAGE", "A home web page for the package.", "off" },
	{
		"EVIDENCE",
		"A demonstration of the validity of a vulnerability claim, e.g. app.any.run replaying the exploitation of the vulnerability.",
		"off",
	},
	{ "WEB", "A web page of some unspecified kind.", "off" },
}

local credit_type_array = {
	{ "FINDER", "Identified the vulnerability..", "off" },
	{ "REPORTER", "Notified the vendor of the vulnerability to a CNA.", "on" },
	{ "ANALYST", "Validated the vulnerability to ensure accuracy or severity", "off" },
	{ "COORDINATOR", "Facilitated the coordinated response process.", "off" },
	{ "REMEDIATION_DEVELOPER", "Prepared a code change or other remediation plans.", "off" },
	{
		"REMEDIATION_REVIEWER",
		"Reviewed vulnerability remediation plans or code changes for effectiveness and completeness.",
		"off",
	},
	{ "REMEDIATION_VERIFIER", "Tested and verified the vulnerability or its remediation.", "off" },
	{ "TOOL", "Names of tools used in vulnerability discovery or identification.", "off" },
	{ "SPONSOR", "Supported the vulnerability identification or remediation activities.", "off" },
	{ "OTHER", "Any other type or role that does not fall under the categories described above.", "off" },
}

local osvf_hash_table = {
	schema_version = "1.7.0",
	id = "FREEBSD-2025-0001",
	modified = nil,
	published = nil,
	withdrawn = nil,
	aliases = {},
	upstream = {},
	related = {},
	summary = "Vulnerability summary",
	details = "Vulnerability details",
	severity = {
		{
			type = "CVSS_V4",
			score = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
		},
	},
	affected = {
		{
			package = {
				ecosystem = "FreeBSD:core",
				name = "unknown",
				purl = "pkg:bsd/freebsd/unknown",
			},
			severity = {
				{
					type = "CVSS_V4",
					score = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
				},
			},
			ranges = {
				{
					type = "ECOSYSTEM",
					repo = nil,
					events = {
						{},
					},
					database_specific = {},
				},
			},
			versions = { "1.0.0" },
			ecosystem_specific = {},
			database_specific = {},
		},
	},
	references = {
		{
			type = "WEB",
			url = "https://www.freebsd.org/",
		},
	},
	credits = {
		{
			name = "Some Name",
			contact = { "example@example.com" },
			type = "FINDER",
		},
	},
	database_specific = {},
}

for _, path in ipairs(bsddialog_location) do
	if io.open(path) then
		bsddialog_bin = path
	end
end

if not bsddialog_bin then
	io.stderr:write("[!] Can't find bsddialog from path[s]\n")
	os.exit(1)
end

-- Read from the given fd until EOF
-- Returns all the data read as a single string
local function read_all(fd)
	local ret = ""
	repeat
		local buffer = assert(unistd.read(fd, 1024))
		ret = ret .. buffer
	until buffer == ""
	return ret
end

-- Run bsddialog and return exit code and
-- output
local function bsddialog(args)
	local r, w = assert(unistd.pipe())
	-- Create fork or application then
	local pid = assert(unistd.fork())
	if pid == 0 then
		-- We are inside Forked app
		-- Close readinging
		assert(unistd.close(r))
		-- Redirect stdout to pipe which goes to parent
		assert(unistd.dup2(w, 2))
		--  Then run bsddialog with args
		assert(unistd.execp(bsddialog_bin, args))
		--  Terminate Fork
		unistd._exit()
	end
	-- Close writing pipe
	assert(unistd.close(w))

	-- Read all output from reading pipe
	local output = read_all(r)
	-- Close reading pipe
	assert(unistd.close(r))

	-- Get exit code of pid
	local _, _, exit_code = assert(sys_wait.wait(pid))

	return exit_code, output
end

-- bsddialog yes/no
-- Prompts the user for a yes/no answer to the given question using bsddialog
-- Returns true if the user answers yes and false if the user answers no.
local function prompt_yn(question)
	local exit_code = bsddialog({
		"--yesno",
		"--disable-esc",
		question,
		0,
		0,
	})
	return exit_code == 0
end

-- bsddialog inputbox
-- Ask some string input from user
local function prompt_inputbox(title, message, default)
	local exit_code, output = bsddialog({
		"--title",
		title,
		"--inputbox",
		message,
		24,
		80,
		default,
	})

	if exit_code == 1 or exit_code == 5 then
		os.exit(1)
	end

	return output:gsub("\n", "")
end

-- bsddialog radio list
-- list should look like
-- {
--    {"OUTPUT", "Description", "on"}
--    {"OUTPUT2", "Description 2", "off"}
-- }
local function prompt_radiolist(title, message, addlist_array)
	local radiolist_array = {
		"--title",
		title,
		"--radiolist",
		message,
		24,
		80,
		#addlist_array,
	}

	for _, value in ipairs(addlist_array) do
		for _, innervalue in ipairs(value) do
			table.insert(radiolist_array, innervalue)
		end
	end

	local exit_code, output = bsddialog(radiolist_array)

	if exit_code == 1 or exit_code == 5 then
		os.exit(1)
	end

	return output:gsub("\n", "")
end

-- Affected package info
-- Add affected packages and package versions
local function prompt_affected()
	local affected_array = {}
	local current_array = {}
	local package_more = true
	local ranges_more = true
	local events_more = true

	while package_more do
		current_array.package = {}

		current_array.package.ecosystem = prompt_radiolist(
			"FreeBSD OSVF Ecosystem (affected[].package.ecosystem)",
			"The ecosystem identifies the overall library ecosystem. It must be one of the strings in the table -- below. The name field is a string identifying the library within its ecosystem.",
			ecosystem_array
		)

		current_array.package.name = prompt_inputbox(
			"FreeBSD OSVF package name affected[].package.name)",
			"The affected object’s package field is a JSON object identifying the affected code library or command provided by the package. The object itself has two required fields, ecosystem and name, and an optional purl field.",
			osvf_hash_table.affected[1].package.name
		)

		current_array.package.purl = "pkg:bsd/freebsd/" .. current_array.package.name

		current_array.ranges = {}
		ranges_array = {}
		ranges_more = true

		while ranges_more do
			ranges_array.type = prompt_radiolist(
				"FreeBSD OSVF Range Version type",
				"In the ranges field, the type field is required. It specifies the type of version range being recorded and defines the interpretation of the events object’s introduced, fixed, and any type-specific fields.",
				version_type_array
			)

			local events_array = {}
			ranges_array.events = {}
			events_more = true

			while events_more do
				local event_type_str = prompt_radiolist(
					"FreeBSD OSVF Range Event type",
					'The ranges object’s events field is a JSON array of objects. Each object describes a single version that either:\n\n * Introduces a vulnerability: {"introduced": string}\n * Fixes a vulnerability: {"fixed": string}\n * Describes the last known affected version: {"last_affected": string}\n * Sets an upper limit on the range being described: {"limit": string}.',
					event_type_array
				)

				events_array[event_type_str] =
					prompt_inputbox("FreeBSD OSVF Range Event version", "Version when event happened", "1.0.0")

				events_more = prompt_yn("Do you want to add new event for range")
				table.insert(ranges_array.events, events_array)
				events_array = {}
			end

			ranges_more = prompt_yn("Do you want to add new range")
			table.insert(current_array.ranges, ranges_array)
			ranges_array = {}
		end

		package_more = prompt_yn("Do you want to add new affected package")

		table.insert(affected_array, current_array)
		current_array = {}
	end

	osvf_hash_table.affected = affected_array

	return true
end

-- Refences prompt
-- What references does this vuln have
-- mark them down or remove all together
local function prompt_refrences()
	local refences_loop = true
	local refrennces_array = {}
	local single_array = {}

	if prompt_yn("Do you want to add reference info") == false then
		osvf_hash_table.references = nil
		return true
	end

	while refences_loop do
		single_array.type = prompt_radiolist(
			"FreeBSD OSVF Event type",
			"Type specifies what kind of reference the URL is.",
			reference_type_array
		)

		single_array.url =
			prompt_inputbox("FreeBSD OSVF Reference URL", "URL for reference", osvf_hash_table.references[1].url)

		refences_loop = prompt_yn("Do you want to add new reference")
		table.insert(refrennces_array, single_array)
		single_array = {}
	end

	osvf_hash_table.references = refrennces_array
	return true
end

-- Severity prompt
-- Ask if one want to add severity score
-- Current version is 4 and it can be found from
-- https://www.first.org/cvss/v4-0/specification-document
local function prompt_severity()
	local severity_loop = true
	local severity_array = {}
	local single_array = {}

	if prompt_yn("Do you want to add severity score") == false then
		osvf_hash_table.severity = nil
		return true
	end

	while severity_loop do
		single_array.type = prompt_radiolist(
			"FreeBSD OSVF Severity type",
			"The severity[].type property must be one of the types defined below, which describes the quantitative method used to calculate the associated score",
			severity_type_array
		)

		single_array.score = prompt_inputbox(
			"FreeBSD OSVF Severity Score",
			"The severity[].score property is a string representing the severity score based on the selected severity[].type",
			osvf_hash_table.severity[1].score
		)

		severity_loop = prompt_yn("Do you want to add new severity score")
		table.insert(severity_array, single_array)
		single_array = {}
	end

	osvf_hash_table.severity = severity_array
	return true
end

-- Credits prompt
-- Ask whether user wants to add credits or not
-- If not remove credits from output
local function prompt_credits()
	local credits_loop = true
	local contact_loop = true
	local credits_array = {}
	local single_array = {}
	local contact_array = {}
	local contact_string = ""

	if prompt_yn("Do you want to add credits info") == false then
		osvf_hash_table.credits = nil
		return true
	end

	while credits_loop do
		single_array.type = prompt_radiolist(
			"FreeBSD OSVF Credits type",
			"The optional credits[].type field should specify the type or role of the individual or entity being credited.",
			credit_type_array
		)

		single_array.name =
			prompt_inputbox("FreeBSD OSVF Credited name", "Name for credited person", osvf_hash_table.credits[1].name)

		contact_loop = true
		while contact_loop do
			contact_string = prompt_inputbox(
				"FreeBSD OSVF Credited contact",
				"Contact for credited person",
				osvf_hash_table.credits[1].contact[1]
			)

			contact_loop = prompt_yn("Do you want to add new contact info")
			table.insert(contact_array, contact_string)
		end
		single_array.contact = contact_array
		contact_array = {}

		credits_loop = prompt_yn("Do you want to add new credits info")
		table.insert(credits_array, single_array)
		single_array = {}
	end

	osvf_hash_table.credits = credits_array

	return true
end

osvf_hash_table.id = prompt_inputbox(
	"FreeBSD OSVF ID",
	"The id field is a unique identifier for the vulnerability entry. It is a string of the format <DB>-<ENTRYID>, where DB names the database and ENTRYID is  in the format used by the database. For FreeBSD correct ID is something like: FREEBSD-YEAR-1234 for example FREEBSD-2025-0001.",
	osvf_hash_table.id
)

osvf_hash_table.summary = prompt_inputbox(
	"FreeBSD OSVF Summary",
	"The summary field gives a one-line, English textual summary of the vulnerability. It is recommended that this field be kept short, on the order of  no more than 120 characters.",
	osvf_hash_table.summary
)

osvf_hash_table.details = prompt_inputbox(
	"FreeBSD OSVF Details",
	"The details field is CommonMark markdown (a subset of GitHub-Flavored Markdown). Display code may at its discretion sanitize the input further, such as stripping raw HTML and links that do not start with http:// or https://. Databases are encouraged not to include those in the first place. (The goal is to balance flexibility of presentation with not exposing vulnerability database display sites to unnecessary vulnerabilities.",
	osvf_hash_table.details
)

prompt_severity()

prompt_affected()

prompt_refrences()

prompt_credits()

local lyaml = require("lyaml")
print(lyaml.dump({ osvf_hash_table }))
