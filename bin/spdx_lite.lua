#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
-- under sponsorship from the FreeBSD Foundation.
--
-- Lua script for creating SPDX Lite profile version 3.0.1 files
--
-- !! Heavy WIP warning !!
--

local Logging = require("logging")
local ucl = require("ucl")

local logger = Logging.new(nil, "DEBUG")
local spdx_version = "3.0.1"
local use_uri = "http://freebsd.org/git"
local agent_id = ""
-- license_table contains all licenses in SPDX license format
-- license_spxd_id_table contains them in spdxId format
-- These are only have once every license nor many occurances
local license_table = {}
local license_spxd_id_table = {}

-------------------------------------------------------------------------------
-- get spdxId URI with part and id
-- It produces URI: start/part/id
-- @param part Prepresents part of SBOM like 'Package' or 'Relationship'
-- @param id Id is something unique id for this part like package name
-- @return URI: start/part/id or https://start/part/id
-------------------------------------------------------------------------------
local function get_spdxId(part, id)
	rtn_string = use_uri .. "/" .. part .. "/" .. id
	return rtn_string
end

-------------------------------------------------------------------------------
-- get /Core/SpdxDocument element
-- Note: There can be only one SpdxDocument in SPDX Lite 3.0.1 document
-- @param spdx_id spdxId for this SpdxDocument
-- @param creation_info_id Which creation info we are using
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_core_spdx_document(spdx_id, creation_info_id)
	rtn_table = {
		creation_info = creation_info_id,
		spdxId = spdx_id,
		rootElement = {},
		element = {},
	}

	rtn_table["@type"] = "SpdxDocument"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Classes/Sbom/ element which holds one package information
-- @param spdx_id spdxId for this SpdxDocument
-- @param creation_info_id Which creation info we are using
-- @param sbom_type_str mainly 'build' but see documenation for extra info
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_software_sbom(spdx_id, creation_info_id, sbom_type_str)
	rtn_table = {
		creation_info = creation_info_id,
		spdxId = spdx_id,
		sbom_type = { sbom_type_str },
		element = {},
		rootElement = {},
	}

	rtn_table["@type"] = "software_Sbom"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /SimpleLicensing/LicenseExpression element which holds SPDX license name
-- @param creation_info_id Which creation info we are using
-- @param license SPDX license expression
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_simplelicensing_license_expression(creation_info_id, license)
	spdx_id = ""

	-- If we don't have this kind of license then just create one
	-- otherwise bail out
	if license_spxd_id_table[license] == nil then
		spdx_id = get_spdxId("simplelicensing_LicenseExpression", string.lower(license))
		license_spxd_id_table[license] = spdx_id
	else
		return nil
	end

	rtn_table = {
		creation_info = creation_info_id,
		spdxId = spdx_id,
		license_expression = license,
	}

	rtn_table["@type"] = "simplelicensing_LicenseExpression"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Software/Package element which holds one package information
-- There can be lot of extra information but this holds only bare minimum
-- @param creation_info_id Which creation info we are using
-- @param agent_id Some agent information
-- @param package_name Name of package
-- @param package_version Package version number
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_software_package(creation_info_id, agent_id, package_name, package_version)
	spdx_id = get_spdxId("Package", package_name)

	rtn_table = {
		creation_info = creation_info_id,
		spdxId = spdx_id,
		originatedBy = { agent_id },
		name = package_name,
		software_copyrightText = "NOASSERTION",
		software_packageVersion = package_version,
	}

	rtn_table["@type"] = "Package"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/Relationship element which holds somekind of relationship.
-- @param spdx_id spdxId for relationship
-- @param creation_info_id Which creation info we are using
-- @param from_id From this spdxId
-- @param to_id To this spdxId
-- @param relationship_type which kind of relation ship. See documentation.
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_core_relationship(spdx_id, creation_info_id, from_id, to_id, relationship_type)
	rtn_table = {
		creation_info = creation_info_id,
		spdxId = spdx_id,
		from = from_id,
		to = { to_id },
		creationg_info = creation_info_id,
	}

	rtn_table["@type"] = "Relationship"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/Agent element which is actor in system.
-- @param creation_info_id Which creation info we are using
-- @param name Name of actor
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_core_agent(creation_info_id, name)
	-- assert(type(name) ~= "string", "Name must be string, got: %s.", type(name))
	spdxId_str = get_spdxId("Agent", string.lower(name):gsub(" ", "_"))

	rtn_table = {
		spdxId = spdxId_str,
		name = name,
		creation_info = creation_info_id,
	}

	rtn_table["@type"] = "Agent"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/CreationInfo element which is creation info for this document.
-- @param creation_id Which creation info we are using
-- @param agent_id Which agent have made this document
-- @return table which holds object
-------------------------------------------------------------------------------
local function get_core_creation_info(creation_id, agent_id)
	local now = os.time()
	local formatted_date = os.date("%FT%TZ", now)

	rtn_table = {
		created = formatted_date,
		created_by = { agent_id },
		created_using = "FreeBSD Port SPDX tool 1.0.0",
		spec_version = spdx_version,
	}

	rtn_table["@type"] = "CreationInfo"
	rtn_table["@id"] = creation_id

	return rtn_table
end

-------------------------------------------------------------------------------
-- get JSON-LD table for creating RDF
-- @param graph Holds table for @graph
-- @return JSON-LD table
-------------------------------------------------------------------------------
local function get_json_ld(graph)
	rtn_table = {}

	rtn_table["@context"] = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

	rtn_table["@graph"] = graph

	return rtn_table
end

package_name = "foo"
package_version = "1.0.0"
package_license = "MIT"


logger:debug("Package name: '" .. package_name .. "' Package version: '" .. package_version .. "' License: '" .. package_license .. "'")

root_graph = {}
default_agent = get_core_agent("_:creationinfo_1", "Default agent")
creation_info = get_core_creation_info("_:creationinfo_1", default_agent.spdxId)
spdx_document = get_core_spdx_document(get_spdxId("spdxDocument", "core"), creation_info["@id"])
software_sbom = get_software_sbom(get_spdxId("software_Sbom", package_name), creation_info["@id"], "build")
package = get_software_package(creation_info["@id"], default_agent.spdxId, package_name, package_version)
license = get_simplelicensing_license_expression(creation_info["@id"], package_license)

has_declared_license_spdx_id_str = package_name .. "/hasDeclaredLicense/" .. string.lower(package_license)
has_declared_license_spdx_id = get_spdxId("Relationship", has_declared_license_spdx_id_str)

has_concluded_license_spdx_id_str = package_name .. "/hasConcludedLicense/" .. string.lower(package_license)
has_concluded_license_spdx_id = get_spdxId("Relationship", has_declared_license_spdx_id_str)

has_declared_license = get_core_relationship(
	has_declared_license_spdx_id,
	creation_info["@id"],
	package.spdxId,
	license.spdxId,
	"hasDeclaredLicense"
)
has_concluded_license = get_core_relationship(
	has_concluded_license_spdx_id,
	creation_info["@id"],
	package.spdxId,
	license.spdxId,
	"hasDeclaredLicense"
)

table.insert(spdx_document.element, default_agent.spdxId)
table.insert(spdx_document.element, software_sbom.spdxId)
table.insert(spdx_document.element, package.spdxId)
table.insert(spdx_document.element, has_declared_license_spdx_id)
table.insert(spdx_document.element, has_concluded_license_spdx_id)
table.insert(spdx_document.element, license.spdxId)
table.insert(spdx_document.rootElement, software_sbom.spdxId)

table.insert(software_sbom.rootElement, package.spdxId)
table.insert(software_sbom.element, has_declared_license_spdx_id)
table.insert(software_sbom.element, has_concluded_license_spdx_id)

table.insert(root_graph, spdx_document)
table.insert(root_graph, creation_info)
table.insert(root_graph, default_agent)
table.insert(root_graph, software_sbom)
table.insert(root_graph, package)
table.insert(root_graph, license)
table.insert(root_graph, has_declared_license)
table.insert(root_graph, has_concluded_license)

json_ld = get_json_ld(root_graph)
print(ucl.to_format(json_ld, "json"))
