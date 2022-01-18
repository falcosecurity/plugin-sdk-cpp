#
# Copyright (C) 2022 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
CURL = curl

FALCOSECURITY_LIBS_REVISION ?= a9964b82b450d6f9758e12210dd12ecc80d83815
FALCOSECURITY_LIBS_REPO ?= falcosecurity/libs

PLUGIN_INFO_DIR=include
PLUGIN_INFO_URL=https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/libscap/plugin_info.h

.PHONY: all
all: plugin_info

.PHONY: clean
clean:
	@rm -f $(PLUGIN_INFO_DIR)/plugin_info.h

.PHONY: plugin_info
plugin_info:
	@$(CURL) -Lso $(PLUGIN_INFO_DIR)/plugin_info.h $(PLUGIN_INFO_URL)
