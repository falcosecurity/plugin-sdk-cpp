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


GH_CONTENT_PREFIX           := https://raw.githubusercontent.com/
DEPS_INCLUDEDIR             := include/falcosecurity/internal/deps
INCLUDE_DIR                 := include/falcosecurity

CURL                        ?= curl
INSTALL_DIR                 ?= /usr/$(INCLUDE_DIR)
FALCOSECURITY_LIBS_REPO     ?= falcosecurity/libs
FALCOSECURITY_LIBS_VER      ?= 0.11.3
NLOHMANN_VER                ?= 3.10.2
TL_EXPECTED_VER             ?= 1.1.0

examples_dir = $(shell ls -d examples/*/ | cut -f2 -d'/' | xargs)
examples_build = $(addprefix example-,$(examples_dir))
examples_clean = $(addprefix clean-example-,$(examples_dir))

.PHONY: all
all: examples

.PHONY: clean
clean: $(examples_clean)
	rm -fr $(DEPS_INCLUDEDIR) $(LIBDIR) $(OBJFILES)

.PHONY: format
format:
	find ./include -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i
	find ./examples -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i

.PHONY: examples
examples: $(examples_build)

example-%: deps
	+@make -C examples/$*

clean-example-%:
	+@make -C examples/$* clean

.PHONY: install
install: 
	cp -r $(INCLUDE_DIR) $(INSTALL_DIR)

.PHONY: uninstall
uninstall:
	rm -rf $(INSTALL_DIR)

.PHONY: deps
deps: $(DEPS_INCLUDEDIR)/plugin_types.h \
      $(DEPS_INCLUDEDIR)/plugin_api.h \
      $(DEPS_INCLUDEDIR)/nlohmann/json.hpp \
      $(DEPS_INCLUDEDIR)/tl/expected.hpp

$(DEPS_INCLUDEDIR):
	+mkdir -p $@

$(DEPS_INCLUDEDIR)/plugin_types.h: $(DEPS_INCLUDEDIR)
	+$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_types.h ${GH_CONTENT_PREFIX}/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_VER}/userspace/plugin/plugin_types.h

$(DEPS_INCLUDEDIR)/plugin_api.h: $(DEPS_INCLUDEDIR)
	+$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_api.h ${GH_CONTENT_PREFIX}/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_VER}/userspace/plugin/plugin_api.h

$(DEPS_INCLUDEDIR)/nlohmann/json.hpp: $(DEPS_INCLUDEDIR)
	+mkdir -p $(DEPS_INCLUDEDIR)/nlohmann
	+$(CURL) -sLo $(DEPS_INCLUDEDIR)/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v${NLOHMANN_VER}/json.hpp

$(DEPS_INCLUDEDIR)/tl/expected.hpp: $(DEPS_INCLUDEDIR)
	+mkdir -p $(DEPS_INCLUDEDIR)/tl
	+$(CURL) -sLo $(DEPS_INCLUDEDIR)/tl/expected.hpp ${GH_CONTENT_PREFIX}/TartanLlama/expected/v${TL_EXPECTED_VER}/include/tl/expected.hpp
