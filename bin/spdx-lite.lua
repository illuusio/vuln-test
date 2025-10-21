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

local logger = Logging.new(nil, "INFO")
local spdx_version = "3.0.1"
local use_uri = "https://cgit.freebsd.org/ports"
local agent_id = ""
-- license_table contains all licenses in SPDX license format
-- license_spxd_id_table contains them in spdxId format
-- These are only have once every license nor many occurances
local license_table = {}
local license_spxd_id_table = {}
local freebsd_document_license = "FreeBSD-DOC"
local freebsd_document_license_url = "https://spdx.org/licenses/FreeBSD-DOC.html"

-------------------------------------------------------------------------------
-- get spdxId URI with part and id
-- It produces URI: start/part/id
-- @param part Prepresents part of SBOM like 'Package' or 'Relationship'
-- @param id Id is something unique id for this part like package name
-- @return URI: start/part/id or https://start/part/id
-------------------------------------------------------------------------------
function spdx_lite_get_spdxId(part, id)
	rtn_string = use_uri .. "/" .. part .. "/" .. id
	return rtn_string
end

-------------------------------------------------------------------------------
-- Create basic table with correct structure to extend in
-- specific create functions
-- @param spdx_id spdxId for this SpdxDocument
-- @param obj_type Type of object
-- @param creation_info_id Which creation info we are using
-- @return table which holds object
-------------------------------------------------------------------------------
local function spdx_lite_create_table(spdx_id, obj_type, creation_info_id)
	rtn_table = {
		creationInfo = creation_info_id,
		spdxId = spdx_id,
	}

	rtn_table["@type"] = obj_type

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/SpdxDocument element
-- Note: There can be only one SpdxDocument in SPDX Lite 3.0.1 document
-- @param spdx_id spdxId for this SpdxDocument
-- @param creation_info_id Which creation info we are using
-- @return table which holds object
-------------------------------------------------------------------------------
function spdx_lite_core_spdx_document(spdx_id, creation_info_id)
	rtn_table = spdx_lite_create_table(spdx_id, "SpdxDocument", creation_info_id)

	rtn_table["rootElement"] = {}
	rtn_table["element"] = {}

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Classes/Sbom/ element which holds one package information
-- @param spdx_id spdxId for this SpdxDocument
-- @param creation_info_id Which creation info we are using
-- @param sbom_type_str mainly 'build' but see documenation for extra info
-- @return table which holds object
-------------------------------------------------------------------------------
function spdx_lite_software_sbom(spdx_id, creation_info_id, sbom_type_str)
	rtn_table = spdx_lite_create_table(spdx_id, "software_Sbom", creation_info_id)

	rtn_table["rootElement"] = {}
	rtn_table["element"] = {}
	rtn_table["sbom_type"] = { sbom_type_str }

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /SimpleLicensing/LicenseExpression element which holds SPDX license name
-- @param creation_info_id Which creation info we are using
-- @param license SPDX license expression
-- @return table which holds object
-------------------------------------------------------------------------------
function spdx_lite_simplelicensing_license_expression(creation_info_id, license)
	spdx_id = spdx_lite_get_spdxId("simplelicensing_LicenseExpression", string.lower(license))

	rtn_table = spdx_lite_create_table(spdx_id, "simplelicensing_LicenseExpression", creation_info_id)

	rtn_table["license_expression"] = license

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
function spdx_lite_software_package(creation_info_id, agent_id, package_name, package_version)
	spdx_id = spdx_lite_get_spdxId("software_Package", package_name)

	rtn_table = spdx_lite_create_table(spdx_id, "software_Package", creation_info_id)

	rtn_table["originatedBy"] = { agent_id }
	rtn_table["name"] = package_name
	rtn_table["software_copyrightText"] = "NOASSERTION"
	rtn_table["software_packageVersion"] = package_version

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
function spdx_lite_core_relationship(spdx_id, creation_info_id, from_id, to_id, relationship_type)
	rtn_table = spdx_lite_create_table(spdx_id, "Relationship", creation_info_id)

	rtn_table["from"] = from_id
	rtn_table["to"] = { to_id }
	rtn_table["relationshipType"] = relationship_type

	rtn_table["@type"] = "Relationship"

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/Agent element which is actor in system.
-- @param creation_info_id Which creation info we are using
-- @param name Name of actor
-- @return table which holds object
-------------------------------------------------------------------------------
function spdx_lite_core_agent(creation_info_id, name)
	-- assert(type(name) ~= "string", "Name must be string, got: %s.", type(name))
	spdxId = spdx_lite_get_spdxId("Agent", string.lower(name):gsub(" ", "_"))

	rtn_table = spdx_lite_create_table(spdx_id, "Agent", creation_info_id)

	rtn_table["name"] = name

	return rtn_table
end

-------------------------------------------------------------------------------
-- get /Core/CreationInfo element which is creation info for this document.
-- @param creation_id Which creation info we are using
-- @param agent_id Which agent have made this document
-- @return table which holds object
-------------------------------------------------------------------------------
function spdx_lite_core_creation_info(creation_id, agent_id)
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
function spdx_lite_json_ld(graph)
	rtn_table = {}

	rtn_table["@context"] = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

	rtn_table["@graph"] = graph

	return rtn_table
end

-------------------------------------------------------------------------------
-- Add to object 'element' or 'rootElement'
-- @param object_table Object table
-- @param spdx_id spdxId to add
-- @return is_root if false then add to 'element' and if true 'rootElement'
-------------------------------------------------------------------------------
local function spdx_lite_add_to_element(object_table, spdx_id, is_root)
	if is_root then
		table.insert(object_table.rootElement, spdx_id)
	else
		table.insert(object_table.element, spdx_id)
	end
end

local function spdx_lite_add_to_graph(root_graph, object_table)
	table.insert(root_graph, object_table)
end

function spdx_lite_add_liceses(root_graph, spdx_document, creation_info)
	for key, license_str in pairs(license_spxd_id_table) do
		if license_str ~= "" then
			license_table = spdx_lite_simplelicensing_license_expression(creation_info["@id"], license_str)
			spdx_lite_add_to_element(spdx_document, license_table.spdxId, false)
			spdx_lite_add_to_graph(root_graph, license_table)
		end
	end
end

-------------------------------------------------------------------------------
-- Add relationship to Graph. It makes all necesery adds to SBOM and
-- spdxDocument
-- @param root_graph Graph object
-- @param package_name Package name from we want to make relationship
-- @param from From spdxId
-- @param to to spdxId
-- @param to_string This is what comes at last in spdxId
-- @param relationship_type What kind of relationship is this
-- @param software_sbom Current software SBOM
-- @param spdx_document Current SPDX document
-- @param creation_info Current creation info
-- @return Relationship table
-------------------------------------------------------------------------------
function spdx_lite_add_relationship(
	root_graph,
	package_name,
	from,
	to,
	to_string,
	relationship_type,
	software_sbom,
	spdx_document,
	creation_info
)
	relation_spdx_id_str = package_name .. "/" .. relationship_type .. "/" .. string.lower(to_string)
	relation_spdx_id = spdx_lite_get_spdxId("Relationship", relation_spdx_id_str)

	relation_table = spdx_lite_core_relationship(relation_spdx_id, creation_info["@id"], from, to, relationship_type)

	spdx_lite_add_to_element(spdx_document, relation_table.spdxId, false)
	spdx_lite_add_to_element(software_sbom, relation_table.spdxId, false)
	spdx_lite_add_to_graph(root_graph, relation_table)

	return relation_table
end

-------------------------------------------------------------------------------
-- Add SBOM to Graph. It makes all necesery adds to SBOM and
-- spdxDocument
-- @param root_graph Graph object
-- @param package_name Package name
-- @param package_version Package version
-- @param package_license Package license array (Comes from JSON)
-- @param spdx_document Current SPDX document
-- @param creation_info Current creation info
-- @param agent Current agent
-- @param type Type of SBOM
-- @return SBOM table and package table
-------------------------------------------------------------------------------
function spdx_lite_create_sbom(
	root_graph,
	package_name,
	package_version,
	package_license,
	spdx_document,
	creation_info,
	agent,
	type
)
	logger:debug("Create SBOM with package name: '" .. package_name .. "' and version: '" .. package_version)

	software_sbom =
		spdx_lite_software_sbom(spdx_lite_get_spdxId("software_Sbom", package_name), creation_info["@id"], type)

	package = spdx_lite_software_package(creation_info["@id"], default_agent.spdxId, package_name, package_version)

	spdx_lite_add_to_element(spdx_document, software_sbom.spdxId, false)
	spdx_lite_add_to_element(spdx_document, package.spdxId, false)
	spdx_lite_add_to_element(spdx_document, software_sbom.spdxId, true)
	spdx_lite_add_to_element(software_sbom, package.spdxId, true)

	spdx_lite_add_to_graph(root_graph, software_sbom)
	spdx_lite_add_to_graph(root_graph, package)

	for _, license_str in ipairs(package_license) do
		license_spdx_id = spdx_lite_get_spdxId("simplelicensing_LicenseExpression", string.lower(license_str))

		-- If we don't have this kind of license then just create one
		-- otherwise bail out
		if license_spxd_id_table[license_str] == nil then
			logger:debug("SBOM package license: " .. license_str)
			license_spxd_id_table[license_str] = license_str
		end

		license = spdx_lite_simplelicensing_license_expression(creation_info["@id"], license_str)

		spdx_lite_add_relationship(
			root_graph,
			package_name,
			package.spdxId,
			license_spdx_id,
			license_str,
			"hasDeclaredLicense",
			software_sbom,
			spdx_document,
			creation_info
		)
		spdx_lite_add_relationship(
			root_graph,
			package_name,
			package.spdxId,
			license_spdx_id,
			license_str,
			"hasConcludedLicense",
			software_sbom,
			spdx_document,
			creation_info
		)
	end

	return software_sbom, package
end

-------------------------------------------------------------------------------
-- Add SpdxDocument, Agent and creationInfo to Graph. It makes all necesery
-- adds to SBOM and spdxDocument
-- @param root_graph Graph object
-- @return Agent table, creationInfo Table, spdxDocument table
-------------------------------------------------------------------------------
function spdx_lite_create_root(root_graph)
	default_agent = spdx_lite_core_agent("_:creationinfo_1", "Default agent")
	creation_info = spdx_lite_core_creation_info("_:creationinfo_1", default_agent.spdxId)
	spdx_document = spdx_lite_core_spdx_document(spdx_lite_get_spdxId("SpdxDocument", "core"), creation_info["@id"])

	spdx_lite_add_to_element(spdx_document, default_agent.spdxId, false)
	spdx_lite_add_to_graph(root_graph, spdx_document)
	spdx_lite_add_to_graph(root_graph, creation_info)
	spdx_lite_add_to_graph(root_graph, default_agent)

	return default_agent, creation_info, spdx_document
end
