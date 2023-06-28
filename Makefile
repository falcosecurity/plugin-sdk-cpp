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

FALCOSECURITY_LIBS_REVISION ?= 0.11.3
FALCOSECURITY_LIBS_REPO     ?= falcosecurity/libs
DEPS_INCLUDEDIR             := include/falcosecurity/internal/deps
DEPS_PLUGIN_LIB_URL         := https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/plugin

.PHONY: all
all: deps

$(DEPS_INCLUDEDIR)/plugin_types.h: $(DEPS_INCLUDEDIR)
	$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_types.h $(DEPS_PLUGIN_LIB_URL)/plugin_types.h

$(DEPS_INCLUDEDIR)/plugin_api.h: $(DEPS_INCLUDEDIR)
	$(CURL) -Lso $(DEPS_INCLUDEDIR)/plugin_api.h $(DEPS_PLUGIN_LIB_URL)/plugin_api.h

$(DEPS_INCLUDEDIR)/nlohmann/json.hpp: $(DEPS_INCLUDEDIR)
	mkdir -p $(DEPS_INCLUDEDIR)/nlohmann && \
		$(CURL) -sLo $(DEPS_INCLUDEDIR)/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.10.2/json.hpp

$(DEPS_INCLUDEDIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -fr $(DEPS_INCLUDEDIR) $(LIBDIR) $(OBJFILES)

.PHONY: format
format:
	find ./include -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i
	find ./examples -iname *.h -o -iname *.cpp | grep -v "/deps/" | xargs clang-format -i

.PHONY: deps
deps: $(DEPS_INCLUDEDIR)/plugin_types.h $(DEPS_INCLUDEDIR)/plugin_api.h $(DEPS_INCLUDEDIR)/nlohmann/json.hpp
