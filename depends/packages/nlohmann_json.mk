nlohmann_json_version := 3.11.3
nlohmann_json_file    := nlohmann-json-$(nlohmann_json_version).tar.gz
nlohmann_json_url     := https://github.com/nlohmann/json/archive/refs/tags/v$(nlohmann_json_version).tar.gz
nlohmann_json_sha256  := 0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406

nlohmann_json: | $(WORK) $(PREFIX)
	$(call fetch,$(nlohmann_json_url),$(nlohmann_json_file),$(nlohmann_json_sha256))
	@if [ ! -f $(PREFIX)/.stamp_nlohmann_json ]; then \
	  echo "Installing nlohmann_json $(nlohmann_json_version)"; \
	  rm -rf $(WORK)/json-$(nlohmann_json_version); \
	  tar xzf $(SOURCES)/$(nlohmann_json_file) -C $(WORK); \
	  cd $(WORK)/json-$(nlohmann_json_version) && \
	  cmake -S . -B build \
	      -DCMAKE_INSTALL_PREFIX=$(PREFIX) \
	      -DJSON_BuildTests=OFF && \
	  cmake --install build && \
	  touch $(PREFIX)/.stamp_nlohmann_json; \
	else \
	  echo "nlohmann_json already installed"; \
	fi
