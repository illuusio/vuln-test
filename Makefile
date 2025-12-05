# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright(c) 2025 The FreeBSD Foundation.
#
# This software was developed by Tuukka Pasanen <tuukka.pasanen@ilmi.fi>
# under sponsorship from the FreeBSD Foundation
#
# 1. run 'make newentry' to add a template to the top of the document
# 2. fill in the template
# 3. use 'make validate' to verify syntax correctness.
# 4. fix any errors
# 5. use 'make OSV_ID=xxx-yyy-zzz markdown' to emit the entry's html file for formatting review
# 6. profit!
#
# Additional tests can be done this way:
# $ make vuln-flat.xml

TOP := $(shell pwd)
ifeq ($(LUA_CMD),)
LUA_CMD := "/usr/libexec/flua"
endif
ifeq ($(PYTHON_CMD),)
PYTHON_CMD := $(shell which python3)
endif
LUA_PATH := "$(TOP)/bin/?.lua;;"
VUXML_URL := "https://vuxml.freebsd.org/freebsd/vuln.xml.xz"

.PHONY: download-vuxml unpack-vuxml convert-vuxml check-lua check-python

check-lua:
	@[ -x $(LUA_CMD) ] || { echo "Lua not found. Please install FreeBSD Lua or use LUA_CMD global variable on commandline to locate lua intepreter (5.4 recommended)"; exit 1; }

check-python:
	@[ -x $(PYTHON_CMD) ] || { echo "Python not found. Please install at least version 3.11 or use PYTHON_CMD global variable on commandline to locate lua intepreter"; exit 1; }
	@$(PYTHON_CMD) -c "import lxml" || { echo "Python module 'lxml' is needed in conversion please install it"; exit 1; }
	@$(PYTHON_CMD) -c "import pypandoc" || { echo "Python module 'pypandoc' is needed in conversion please install it"; exit 1; }

download-vuxml:
	@which curl >/dev/null 2>&1 || { echo "curl not found"; exit 1; }
	@curl --output vuln.xml.xz https://vuxml.freebsd.org/freebsd/vuln.xml.xz >/dev/null 2>&1 || { echo "Can't download '$(VUXML_URL)'"; exit 1; }

unpack-vuxml: download-vuxml
	@which xz >/dev/null 2>&1 || { echo "xz not found"; exit 1; }
	@xz -d vuln.xml.xz || { echo "Can't unpack vuln.xml.xz"; exit 1; }

convert-vuxml: check-python unpack-vuxml
	@$(PYTHON_CMD) bin/convert_vuxml.py -o vuln vuln.xml

