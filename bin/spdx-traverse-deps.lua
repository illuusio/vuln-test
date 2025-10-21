#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
-- under sponsorship from the FreeBSD Foundation.
--
-- Traverse package dependencies for SBOM
--
-- !! Heavy WIP warning !!
--

local Logging = require("logging")
local Make = require("ports-make")
local Make = require("spdx-lite")

local ucl = require("ucl")

local logger = Logging.new(nil, "INFO")

-------------------------------------------------------------------------------
-- Run 'describe-json' with make and parse output.
-- @param location If something else than nil then make if runned with '-C'
-- @return Parse output which contains name, version and licenses array
-------------------------------------------------------------------------------
local function spdx_traverse_describe_json(location)
	local addition_str = ""

	if location ~= nil then
		addition_str = "-C " .. location .. " "
	end

	local output_table = ports_make_target(addition_str .. "describe-json")
	local parser = ucl.parser()
	local parsed_json, err = parser:parse_string(output_table)

	ucl_obj = parser:get_object()
	rtn_table = {}

	-- Example for this one is glib 2.0 package which
	-- outputs JSON with object that has okeys 'default-glib20' and 'bootstrap-glib20'
	-- To simplify we choose first which should be 'default'.
	-- otherwise there is only one object so use that one
	if ucl_obj["pkgbase"] == nil then
		logger:debug("Multiple packages describe in JSON")
		for key, cur_obj in pairs(ucl_obj) do
			if cur_obj["pkgbase"] ~= nil then
				rtn_table["name"] = cur_obj["pkgbase"]
				rtn_table["version"] = cur_obj["distversion"]
				rtn_table["license"] = cur_obj["license"]
				break
			end
		end
	else
		rtn_table["name"] = ucl_obj["pkgbase"]
		rtn_table["version"] = ucl_obj["distversion"]
		rtn_table["license"] = ucl_obj["license"]
	end

	logger:debug("Described name: " .. rtn_table["name"])
	logger:debug("Described version: " .. rtn_table["version"])

	for _, license_str in ipairs(rtn_table["license"]) do
		logger:debug("Described license: " .. license_str)
	end

	return rtn_table
end

-------------------------------------------------------------------------------
-- Parses 'package-depends-list' one line and creates unified table
-- @param table_string One line of output which should be parsed
-- @return Parse output as table which contains name, version, full_location
--         and location
-------------------------------------------------------------------------------
local function spdx_traverse_split_output(table_string)
	local splitted_table = ports_make_split_string(table_string, " ")
	local version_table = ports_make_split_string(splitted_table[1], "-")

	version_table_len = #version_table
	local name_len = (string.len(splitted_table[1]) - string.len(version_table[version_table_len])) - 1

	local version_str = version_table[version_table_len]
	local name_str = string.sub(splitted_table[1], 0, name_len)

	rtn_table = {}
	rtn_table["name"] = name_str
	rtn_table["version"] = version_str
	rtn_table["full_location"] = splitted_table[2]
	rtn_table["location"] = splitted_table[3]

	logger:debug("Package name: " .. rtn_table["name"])
	logger:debug("Package version: " .. rtn_table["version"])
	logger:debug("Package full location: " .. rtn_table["full_location"])
	logger:debug("Package location: " .. rtn_table["location"])

	return rtn_table
end

-------------------------------------------------------------------------------
-- Add depends for some packge to Graph from 'package-depends-list' output
-- @param deps_table Output of package-depends-list as table
-- @param package Current package for relationship from-key
-- @param software_sbom Current softwareSbom
-- @param spdx_document Current spdxDocument
-- @param creation_info Current creationInfo
-- @return none
-------------------------------------------------------------------------------
local function spdx_traverse_add_depends_on(deps_table, package, software_sbom, spdx_document, creation_info)
	local depends_on_table = nil
	for _, output_str in ipairs(deps_table) do
		package_dep_table = spdx_traverse_split_output(output_str)
		to_spdx_id = spdx_lite_get_spdxId("software_Package", package_dep_table["name"])

		if depends_on_table == nil then
			depends_on_table = spdx_lite_add_relationship(
				root_graph,
				package.name,
				package.spdxId,
				to_spdx_id,
				"packages",
				"dependsOn",
				software_sbom,
				spdx_document,
				creation_info
			)
		else
			table.insert(depends_on_table.to, to_spdx_id)
		end
	end
end

root_graph = {}
-- Create Graph root objects
local agent, creation_info, spdx_document = spdx_lite_create_root(root_graph)

local output_table = ports_make_target_as_table("package-depends-list")
local package_data = spdx_traverse_describe_json()

-- Create SBOM object for package we are currently SBOMing
local software_sbom, package = spdx_lite_create_sbom(
	root_graph,
	package_data["name"],
	package_data["version"],
	package_data["license"],
	spdx_document,
	creation_info,
	agent,
	"build"
)

-- Add depends for current SBOM
spdx_traverse_add_depends_on(output_table, package, software_sbom, spdx_document, creation_info)

-- Add depends to current package
for _, output_str in ipairs(output_table) do
	local package_dep_table = spdx_traverse_split_output(output_str)
	local package_data = spdx_traverse_describe_json(package_dep_table["full_location"])
	local dep_software_sbom, dep_package = spdx_lite_create_sbom(
		root_graph,
		package_data["name"],
		package_data["version"],
		package_data["license"],
		spdx_document,
		creation_info,
		agent,
		"build"
	)

	local deps_table =
		ports_make_target_as_table("-C " .. package_dep_table["full_location"] .. " package-depends-list")
	spdx_traverse_add_depends_on(deps_table, dep_package, software_sbom, spdx_document, creation_info)
end

-- Add licenses to Graph
spdx_lite_add_liceses(root_graph, spdx_document, creation_info)

json_ld = spdx_lite_json_ld(root_graph)
print(ucl.to_format(json_ld, "json"))
