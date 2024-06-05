# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CURL ?= curl
PATCH ?= patch

FALCOSECURITY_LIBS_REVISION ?= 0.17.2
FALCOSECURITY_LIBS_REPO     ?= falcosecurity/libs
DEPS_INCLUDEDIR             := include/falcosecurity/internal/deps
DEPS_PLUGIN_LIB_URL         := https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/plugin
INCLUDE_DIR                 := include/falcosecurity
INSTALL_DIR                 ?= /usr/$(INCLUDE_DIR)

examples_dir = $(shell ls -d examples/*/ | cut -f2 -d'/' | xargs)
examples_build = $(addprefix example-,$(examples_dir))
examples_clean = $(addprefix clean-example-,$(examples_dir))

.PHONY: all
all: examples

.PHONY: clean
clean: $(examples_clean)
	+rm -fr $(DEPS_INCLUDEDIR)/plugin_api.h $(DEPS_INCLUDEDIR)/plugin_types.h $(DEPS_INCLUDEDIR)/nlohmann/json.hpp
	+rm -fr $(LIBDIR) $(OBJFILES)

.PHONY: format
format:
	+find ./include -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i
	+find ./examples -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i

.PHONY: deps
deps: $(DEPS_INCLUDEDIR)/plugin_types.h $(DEPS_INCLUDEDIR)/plugin_api.h $(DEPS_INCLUDEDIR)/nlohmann/json.hpp

.PHONY: examples
examples: $(examples_build)

example-%: deps
	+@cd examples/$* && make

clean-example-%:
	+@cd examples/$* && make clean

$(DEPS_INCLUDEDIR):
	+mkdir -p $@
	+mkdir -p $@/nlohmann

$(DEPS_INCLUDEDIR)/plugin_types.h: $(DEPS_INCLUDEDIR)
	+$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_types.h $(DEPS_PLUGIN_LIB_URL)/plugin_types.h

$(DEPS_INCLUDEDIR)/plugin_api.h: $(DEPS_INCLUDEDIR)
	+$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_api.h $(DEPS_PLUGIN_LIB_URL)/plugin_api.h
	+$(PATCH) -p1 < $(DEPS_INCLUDEDIR)/plugin_api.patch

$(DEPS_INCLUDEDIR)/nlohmann/json.hpp: $(DEPS_INCLUDEDIR)
	+$(CURL) -sLo $(DEPS_INCLUDEDIR)/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.10.2/json.hpp

.PHONY: install
install: 
	cp -r $(INCLUDE_DIR) $(INSTALL_DIR)

.PHONY: uninstall
uninstall:
	rm -rf $(INSTALL_DIR)