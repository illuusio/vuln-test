#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
-- under sponsorship from the FreeBSD Foundation.
--
-- Tool can be used for validating OSVf files against schema and
-- merging JSON files in one big array of OSVf files (and validate
-- them all)
--
-- !! Heavy WIP warning !!
--

local Logging = require("logging")
local ucl = require("ucl")

require("ports-make")

-- This one is official but does not yet contain FreeBSD namespace
-- Use non-official until PR is included
-- local osvf_schema_url = "https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json"
local osvf_schema_url =
	"https://raw.githubusercontent.com/illuusio/osv-schema/refs/heads/FreeBSD-ecosystem/validation/schema.json"
local logger = Logging.new(nil, "INFO")
local schema_file_location = ""
local schema_remoce = false
local osvf_files_location = "../vuln"

-------------------------------------------------------------------------------
-- Validate OSVf JSON against OSVf schema. This is done using libUCL
-- validation.
-- @param schema_location Schema to use for validation
-- @param package_name JSON file to validate
-- @return False is not valid and true is it's correct OSVf 1.7.0 file
-------------------------------------------------------------------------------
local function osvf_tool_validate(schema_location, json_location)
	local parser = ucl.parser()
	local is_error, err = parser:parse_file(json_location)

	if is_error == false then
		logger:error("osvf_tool_validate: Can't parse OSVf JSON file: " .. err)
		return false
	end

	is_error, err = parser:validate(schema_location)

	if is_error == false then
		logger:error("osvf_tool_validate: Can't validate OSVf JSON file with '" .. schema_location "': " .. err)
		logger:error("osvf_tool_validate: Please see schema at: " .. osvf_schema_url)
		return false
	end

	return true
end

-------------------------------------------------------------------------------
-- Does file exist and can it be opened and read
-- @param filename Filename to be checked
-- @return False if file does not exist and true is it does
-------------------------------------------------------------------------------
local function osvf_tool_file_exist(filename)
	local is_present = true
	-- Opens a file
	hanle = io.open(filename)

	-- if file is not present, f will be nil
	if not handle then
		isPresent = false
	else
		-- close the file
		hanle:close()
	end

	-- return status
	return is_present
end

-------------------------------------------------------------------------------
-- Run command and return output
-- @param command Command to be run
-- @return Output of command
-- @return True if success and false if not
-------------------------------------------------------------------------------
local function osvf_tool_run_cmd(command)
	logger:debug("Run make command: '" .. command .. "'")
	local handle = io.popen(command)
	local output = handle:read("*a")
	rtn_value = handle:close()
	return output, rtn_value
end

-------------------------------------------------------------------------------
-- Download OSVf schema to temp location with curl or fetch command
-- @return True if schema was downloaded and false if not
-- @return Location of downloaded schema or nil if it couldn't
-------------------------------------------------------------------------------
local function osvf_tool_get_schema()
	tmp_file_location = os.tmpname()
	logger:debug("Output file to: " .. tmp_file_location)
	local output = ""
	local rc = false

	if osvf_tool_file_exist("/usr/bin/curl") then
		output, rc =
			osvf_tool_run_cmd("/usr/bin/curl -o " .. tmp_file_location .. " " .. osvf_schema_url .. " 2> /dev/null")
	elseif osvf_tool_file_exist("/usr/bin/fetch") then
		logging:error("Fetch is not working yet!")
		return false, nil
	else
		logging:error("Can't locate '/usr/bin/curl' or '/usr/bin/fetch' from '/usr/bin'")
		return false, nil
	end

	if rc == false then
		logger:error("Can't download: " .. osvf_schema_url)
		return false, nil
	end

	return true, tmp_file_location
end

-------------------------------------------------------------------------------
-- Merge OSVf files together in one big JSON array and validate files when
-- merging them
-- Function does not make any other loading for JSON after validation. JSON
-- files are just pasted as if as they are valid.
-- @return True if succesfully merged files and false if not
-- @return Merged OSVf array as a string
-------------------------------------------------------------------------------
local function osvf_tool_merge_osvf_files(schema_location, osv_location)
	local output, rc = osvf_tool_run_cmd("find " .. osv_location .. " -type f -name '*.json' | sort")

	if rc == false then
		logger:error("Something went wrong with find in '" .. osv_location .. "'. Exiting")
		return false, nil
	end

	local find_table = ports_make_split_string(output, "\n")
	local output_table = { "[\n" }
	local output_table_pos = 1

	-- Go thru every file that find have finded
	for find_table_pos, output_str in ipairs(find_table) do
		local pos = 1
		-- Validate file and make sure it can be loaded as JSON and
		-- it's valid OSVf 1.7.0 file. If not then don't go further
		if osvf_tool_validate(schema_location, output_str) == false then
			logger:error("Can't validate: " .. output_str)
			return false, nil
		end
		local file_hanle = assert(io.open(output_str, "rb"))
		local content = file_hanle:read("*all")
		file_hanle:close()

		local content_table = ports_make_split_string(content, "\n")

		-- Add files content to be part of merged JSON array variable
		-- which is returned
		for pos, content_str in ipairs(content_table) do
			local comma_str = ""
			output_table_pos = output_table_pos + 1
			if pos == #content_table and find_table_pos < #find_table then
				comma_str = ","
			end

			output_table[output_table_pos] = "    " .. content_str .. comma_str .. "\n"
		end
	end

	output_table[output_table_pos + 1] = "]\n"

	return true, table.concat(output_table)
end

if #arg == 0 then
	print("Usage: osvf-tool.lua [OSVf dir location] [OSVf schema location]")
end

osvf_files_location = arg[1]

if #arg == 1 then
	is_success, schema_file_location = osvf_tool_get_schema()
	schema_remove = true
else
	if osvf_tool_file_exist(arg[2]) == false then
		logger:error("Can't find schema file: '" .. arg[2] .. "'. Exiting")
		os.exit(1)
	end

	is_success = true
	schema_file_location = arg[2]
	schema_remove = false
end

if is_success then
	is_error, output = osvf_tool_merge_osvf_files(schema_file_location, osvf_files_location)

	if is_error then
		print(output)
	end

	if schema_remove then
		local success, err = os.remove(schema_file_location)

		if success == false then
			logger:error("Can't delete tmp file: '" .. schema_file_location .. "' (" .. err .. ")")
		end
	end
end
