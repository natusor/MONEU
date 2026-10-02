boost_version := 1.83.0
boost_file    := boost-$(boost_version).tar.gz
boost_url     := https://github.com/boostorg/boost/releases/download/boost-$(boost_version)/$(boost_file)
boost_sha256  := 0c6049764e80aa32754acd7d4f179fd5551d8172a83b71532ae093e7384e98da

boost: | $(WORK) $(PREFIX)
	$(call fetch,$(boost_url),$(boost_file),$(boost_sha256))
	@if [ ! -f $(PREFIX)/.stamp_boost ]; then \
	  echo "Building Boost $(boost_version) for $(HOST), this takes a while"; \
	  rm -rf $(WORK)/boost-$(boost_version); \
	  tar xzf $(SOURCES)/$(boost_file) -C $(WORK); \
	  cd $(WORK)/boost-$(boost_version) && \
	  echo "using gcc : mingw : $(CXX) ;" > user-config.jam && \
	  ./bootstrap.sh --without-icu \
	      --with-libraries=filesystem,system,thread,program_options && \
	  ./b2 -j$(JOBS) -d1 --user-config=user-config.jam \
	      toolset=gcc-mingw target-os=windows threadapi=win32 \
	      address-model=64 binary-format=pe abi=ms \
	      variant=release link=static runtime-link=static threading=multi \
	      --layout=system --prefix=$(PREFIX) install && \
	  touch $(PREFIX)/.stamp_boost; \
	else \
	  echo "Boost already built"; \
	fi
