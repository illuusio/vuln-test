-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
-- under sponsorship from the FreeBSD Foundation.
--
-- Functions handling ports make command output
--
-- !! Heavy WIP warning !!
--

local Logging = require("logging")

local logger = Logging.new(nil, "INFO")

-------------------------------------------------------------------------------
-- Splits string with separator
-- @param inputstr String to be splitter
-- @param sep Separator
-- @return Table with splitted values
-------------------------------------------------------------------------------
function ports_make_split_string(inputstr, sep)
	if sep == nil then
		sep = "%s"
	end
	local rtn_table = {}
	for part in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
		table.insert(rtn_table, part)
	end
	return rtn_table
end

-------------------------------------------------------------------------------
-- Call make with target
-- @param target String to be splitter
-- @return Stdout outpout of make-command
-------------------------------------------------------------------------------
function ports_make_target(target)
	logger:debug("Run make target: '" .. target .. "'")
	local handle = io.popen("make " .. target)
	local output = handle:read("*a")
	handle:close()
	return output
end

-------------------------------------------------------------------------------
-- Call make with target and add it line by line to table
-- @param target String to be splitter
-- @return Table line by line output of make-command
-------------------------------------------------------------------------------
function ports_make_target_as_table(target)
	local output = ports_make_target(target)
	return ports_make_split_string(output, "\n")
end
