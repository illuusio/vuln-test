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
		logger:error("osvf_tool_validate: Can't validate OSVf JSON file with '" .. schema_location .. "': " .. err)
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

local function oscf_tool_find_file(osv_location)
	local output, rc = osvf_tool_run_cmd("find " .. osv_location .. " -type f -name '*.json' | sort -r")

	if rc == false then
		logger:error("Something went wrong with find in '" .. osv_location .. "'. Exiting")
		return nil
	end

	return ports_make_split_string(output, "\n")
end

-------------------------------------------------------------------------------
-- Download schema from git or use existing one if provided
-- @param schema_location Schema location or nil wanted to download it
-- @return True if succesfully merged files and false if not
-------------------------------------------------------------------------------
local function osvf_tool_download_schema(schema_location)
	local schema_remove = false
	local file_location = schema_location

	if schema_location == nil then
		is_success, file_location = osvf_tool_get_schema()
		schema_remove = true

		if is_success == false then
			logger:error("Can't donwload schema file: '" .. osvf_schema_url .. "'. Exiting")
			return false
		end
	else
		if osvf_tool_file_exist(schema_location) == false then
			logger:error("Can't find schema file: '" .. schema_location .. "'. Exiting")
			return false
		end

		is_success = true
		schema_remove = false
	end

	return schema_remove, file_location
end

-------------------------------------------------------------------------------
-- Remove schema if wanted or bail out
-- @param schema_location Schema location or nil wanted to download it
-- @param schema_remove Remove schmea if true. Do nothing if false
-- @return True if succesfully merged files and false if not
-------------------------------------------------------------------------------
local function osvf_tool_remove_schema(schema_location, schema_remove)
	if not schema_remove then
		return true
	end

	if osvf_tool_file_exist(schema_location) then
		logging:error("Can't find schema to remove: " .. schema_location)
		return false
	end

	if schema_remove then
		local success, err = os.remove(schema_location)

		if success == false then
			logger:error("Can't delete tmp schema file: '" .. file_location .. "' (" .. err .. ")")
			return false
		end
	end

	return true
end

-------------------------------------------------------------------------------
-- Validate all files all together from directory
-- @param schema_location Schema location or nil wanted to download it
-- @param osv_location Directory location of OSVf JSON files
-- @return True if succesfully merged files and false if not
-------------------------------------------------------------------------------
local function osvf_tool_validate_osvf_files(schema_location, osv_location)
	local find_table = oscf_tool_find_file(osv_location)

	if find_table == nil then
		logger:error("Something went wrong with find in '" .. osv_location .. "'. Exiting")
		return false
	end

	local schema_remove, file_location = osvf_tool_download_schema(schema_location)
	local is_valid = false

	for find_table_pos, json_file in ipairs(find_table) do
		is_valid = osvf_tool_validate(file_location, json_file)

		if is_valid == false then
			logger:error("Can't validate file: '" .. json_file .. "'. Exiting")
			break
		end
	end

	osvf_tool_remove_schema(file_location, schema_remove)

	return is_valid
end

-------------------------------------------------------------------------------
-- Merge OSVf files together in one big JSON array and validate files when
-- merging them
-- Function does not make any other loading for JSON after validation. JSON
-- files are just pasted as if as they are valid.
-- @param schema_location Schema location or nil wanted to download it
-- @param osv_location Directory location of OSVf JSON files
-- @return True if succesfully merged files and false if not
-- @return Merged OSVf array as a string
-------------------------------------------------------------------------------
local function osvf_tool_merge_osvf_files(schema_location, osv_location)
	local find_table = oscf_tool_find_file(osv_location)

	if find_table == nil then
		logger:error("Something went wrong with find in '" .. osv_location .. "'. Exiting")
		return false, nil
	end

	local schema_remove, file_location = osvf_tool_download_schema(schema_location)

	local output_table = { "[\n" }
	local output_table_pos = 1

	-- Go thru every file that find have finded
	for find_table_pos, output_str in ipairs(find_table) do
		local pos = 1
		-- Validate file and make sure it can be loaded as JSON and
		-- it's valid OSVf 1.7.0 file. If not then don't go further
		if osvf_tool_validate(file_location, output_str) == false then
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

	osvf_tool_remove_schema(file_location, schema_remove)

	output_table[output_table_pos + 1] = "]\n"

	return true, table.concat(output_table)
end

if #arg == 0 then
	print("Usage:\tosvf-tool.lua validate|newentry|merge|commonmark|html\n")
	print("\tvalidate\tValidate lastes entry or if last option is JSON file use that one\n")
	print("\t\t\tExample: osvf-tool.lua validate")
	print("\t\t\tWill validate all files in vuln directory\n")
	print("\t\t\tExample: osvf-tool.lua validate vuln/2025/FreeBSD-2025-0001.json")
	print("\t\t\tWill validate only file: 'vuln/2025/FreeBSD-2025-0001.json'\n")

	print(
		"\tnewentry\tCreate new entry and set ID for it. Create it from template tmpl/FreeBSD-tmpl.json and fill with defaults\n"
	)
	print("\t\t\tExample: osvf-tool.lua newentry")
	print("\t\t\tCreate new entry with next ID which is available\n")
	print("\t\t\tExample: osvf-tool.lua newentry ID")
	print("\t\t\tCreate new entry with ID\n")
	os.exit(1)
end

local commands = {
	validate = 1,
	newentry = 2,
	merge = 3,
	commonmark = 4,
	html = 5,
}

local which_command = commands[arg[1]]

if which_command == 1 then
	is_valid = osvf_tool_validate_osvf_files("schema/osvf_schema-1.7.4.json", "vuln")

	if is_valid == true then
		print("All OSVf JSON files are valid inside vuln-directory")
	else
		print("Validation of OSVf JSON files didn't succeeded please see error(s)")
	end
elseif which_command == 2 then
	print("New entry needs to be implemented")
elseif which_command == 3 then
	is_error, output = osvf_tool_merge_osvf_files("schema/osvf_schema-1.7.4.json", "vuln")

	if is_error == true then
		print(output)
	end
end

os.exit(0)
